# app.py
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
)
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from ipaddress import ip_address, ip_network

import threading
import os



import time
#import time as time_mod
import subprocess
import re

from scapy.all import sniff, IP, IPv6, TCP, UDP

from models import db, Device, Admin, Flow, TrafficSample, IPSConfig, FirewallRule, IPSRule, IPSAlert
from list_devices import scan_devices



# Flask / DB / Login setup


app = Flask(__name__)


from datetime import datetime, timedelta, timezone

# timezone configuration

try:
    from zoneinfo import ZoneInfo 
    LOCAL_TZ = ZoneInfo("America/Toronto")  # Eastern time (Quebec)
except ImportError:
    ZoneInfo = None
    LOCAL_TZ = None

def to_local(dt):
  
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if LOCAL_TZ:
            return dt.astimezone(LOCAL_TZ)
        return dt
    except Exception:
        return dt

@app.template_filter("localdt")
def localdt_filter(value, fmt="%Y-%m-%d %H:%M:%S"):
    if value is None:
        return "N/A"
    return to_local(value).strftime(fmt)



#DB CONFIG robust absolute path
basedir = os.path.abspath(os.path.dirname(__file__))

db_dir = os.path.join(basedir, "instance")

db_path = os.path.join(db_dir, "smart_home_ips.db")
app.config["SECRET_KEY"] = "change-me-strong-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# hotspot interface used for sniffing
app.config["HOTSPOT_IFACE"] = "wlo1"
NETWORK_CIDR = "10.42.0.0/24"       
AUTO_SCAN = True                    
SCAN_INTERVAL = 2
MAX_TRAFFIC_POINTS = 2000           
DEFAULT_CHART_WINDOW = 200          


# IPS configuration
IPS_DEFAULT_RATE_THRESHOLD_KBPS = 12000.0   # default anomaly threshold
IPS_DEFAULT_THROTTLE_MINUTES = 2          # default throttle duration

IPS_RATE_THRESHOLD_KBPS = IPS_DEFAULT_RATE_THRESHOLD_KBPS
IPS_THROTTLE_DURATION_MINUTES = IPS_DEFAULT_THROTTLE_MINUTES

THROTTLED_DEVICES = {}


db.init_app(app)
with app.app_context():
    db.create_all()

    cfg = IPSConfig.query.get(1)
    if cfg is None:
        cfg = IPSConfig(
            id=1,
            rate_threshold_kbps=IPS_DEFAULT_RATE_THRESHOLD_KBPS,
            throttle_minutes=IPS_DEFAULT_THROTTLE_MINUTES,
        )
        db.session.add(cfg)
        db.session.commit()

    IPS_RATE_THRESHOLD_KBPS = float(cfg.rate_threshold_kbps or IPS_DEFAULT_RATE_THRESHOLD_KBPS)
    IPS_THROTTLE_DURATION_MINUTES = int(cfg.throttle_minutes or IPS_DEFAULT_THROTTLE_MINUTES)

login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))


# vendor + device-type guessing
APPLE_OUIS = {
    "A4:5E:60",
    "28:F0:76",
    "3C:15:C2",
    "8C:85:90",
    "DC:A9:04",
}

SAMSUNG_OUIS = {
    "F0:18:98",
    "5C:F8:A1",
    "64:77:91",
    "30:07:4D",
}


def guess_vendor(mac: str, hostname: str | None = None) -> str | None:
    mac_norm = mac.upper()
    prefix = ":".join(mac_norm.split(":")[:3])

    if hostname:
        h = hostname.lower()
        if "iphone" in h or "ipad" in h or "mac" in h or "apple" in h:
            return "Apple"
        if "samsung" in h or "galaxy" in h:
            return "Samsung"

    if prefix in APPLE_OUIS:
        return "Apple"
    if prefix in SAMSUNG_OUIS:
        return "Samsung"

    return None


def guess_device_type(hostname: str | None = None) -> str | None:
    if not hostname:
        return None
    h = hostname.lower()
    if "iphone" in h or "ipad" in h or "phone" in h:
        return "Phone / Tablet"
    if "mac" in h or "pc" in h or "desktop" in h or "laptop" in h:
        return "Desktop / Laptop"
    if "tv" in h:
        return "Smart TV"
    return None

def has_unseen_alerts():
    from models import IPSAlert
    return IPSAlert.query.count() > 0


# firewall + iptables integration


def _run_iptables(args):
    
    try:
        subprocess.run(
            ["iptables"] + args,
            check=False,
            text=True,
            capture_output=True,
        )
    except Exception as e:
        print("iptables error:", e)


def init_firewall_chain():
    
    _run_iptables(["-N", "SMART_FW"])

    try:
        res = subprocess.run(
            ["iptables", "-C", "FORWARD", "-j", "SMART_FW"],
            check=False,
            text=True,
            capture_output=True,
        )
        if res.returncode != 0:
            _run_iptables(["-I", "FORWARD", "1", "-j", "SMART_FW"])
    except Exception as e:
        print("iptables FORWARD hook error:", e)


def apply_firewall_rules():
   
    init_firewall_chain()

    _run_iptables(["-F", "SMART_FW"])

    rules = FirewallRule.query.filter_by(enabled=True).all()

    for r in rules:
        device_ip = (r.device_ip or "").strip()
        remote_ip = (r.remote_ip or "").strip()
        dev_port = r.device_port
        rem_port = r.remote_port
        protocol = (r.protocol or "any").lower()
        direction = (r.direction or "any").lower()

        has_dev_ip = bool(device_ip)
        has_rem_ip = bool(remote_ip)
        has_dev_port = dev_port is not None
        has_rem_port = rem_port is not None

        # checks if any port is specified
        if has_dev_port or has_rem_port:
            if protocol in ("tcp", "udp"):
                protos = [protocol]
            else:
                protos = ["tcp", "udp"]
        else:
            protos = [None]
        
        _run_iptables(args + ["-j", "DROP"])

        # Outgoing device -remote
        if direction in ("out", "any"):
            for proto in protos:
                args = ["-A", "SMART_FW"]
                if has_dev_ip:
                    args += ["-s", device_ip]
                if has_rem_ip:
                    args += ["-d", remote_ip]
                if proto:
                    args += ["-p", proto]
                if has_dev_port:
                    args += ["--sport", str(dev_port)]
                if has_rem_port:
                    args += ["--dport", str(rem_port)]
                _run_iptables(args + ["-j", "DROP"])

        # incoming: remote - device 
        if direction in ("in", "any"):
            for proto in protos:
                args = ["-A", "SMART_FW"]
                if has_dev_ip:
                    args += ["-d", device_ip]
                if has_rem_ip:
                    args += ["-s", remote_ip]
                if proto:
                    args += ["-p", proto]
                if has_dev_port:
                    args += ["--dport", str(dev_port)]
                if has_rem_port:
                    args += ["--sport", str(rem_port)]
                _run_iptables(args + ["-j", "DROP"])


def _cleanup_expired_throttles():
    from datetime import datetime

    now = datetime.utcnow()
    expired_ips = [ip for ip, exp in THROTTLED_DEVICES.items() if exp <= now]

    for ip in expired_ips:
        print(f"[IPS] Removing throttle for {ip}")
        _run_iptables(["-D", "SMART_FW", "-s", ip, "-j", "DROP"])
        _run_iptables(["-D", "SMART_FW", "-d", ip, "-j", "DROP"])
        del THROTTLED_DEVICES[ip]

from ipaddress import ip_address, ip_network
#from datetime import datetime, timedelta


def _load_ips_rules_for_device_ip(device_ip: str):
    
    try:
        rules = IPSRule.query.filter_by(enabled=True).all()
        print(f"[IPS DEBUG] _load_ips_rules_for_device_ip({device_ip}) -> {len(rules)} raw rules")
    except Exception as e:
        print(f"[IPS ERROR] Failed to load IPS rules for {device_ip}: {e}")
        return []

    def parse_net(text: str | None):
        text = (text or "").strip()
        if not text:
            return None
        try:
            if "/" in text:
                # CIDR given, use as-is
                return ip_network(text, strict=False)
            # Single IP -> /32 (IPv4) or /128 (IPv6)
            suffix = "/32" if ":" not in text else "/128"
            return ip_network(text + suffix, strict=False)
        except ValueError:
            return None

    parsed = []
    for r in rules:
        # device-specific rule
        if r.device_ip and r.device_ip.strip() != device_ip:
            continue

        parsed.append(
            {
                "rule": r,
                "remote_net": parse_net(r.remote_ip),
                "protocol": (r.protocol or "any").lower(),
                "remote_port": r.remote_port,
                "action": (r.action or "alert_block").lower(),
            }
        )

    return parsed


def _check_ips_packet(device, device_ip, proto, src_ip, sport, dst_ip, dport, ips_rules):

    proto_l = proto.lower()

    # decide which side is remote
    if src_ip == device_ip:
        remote_ip = dst_ip
        remote_port = dport
    elif dst_ip == device_ip:
        remote_ip = src_ip
        remote_port = sport
    else:
        return False

    try:
        remote_addr = ip_address(remote_ip)
    except ValueError:
        remote_addr = None

    for pr in ips_rules:
        r = pr["rule"]
        remote_net = pr["remote_net"]
        rule_port = pr["remote_port"]
        rule_proto = pr["protocol"]
        action = pr["action"]

        # protocol match
        if rule_proto not in ("any", proto_l):
            continue

        # remote IP/CIDR match
        if remote_net is not None:
            if (
                not remote_addr
                or remote_addr.version != remote_net.version
                or remote_addr not in remote_net
            ):
                continue

        # remote port match
        if rule_port is not None and remote_port != rule_port:
            continue

        #  Signature matched
        msg = f"Signature alert: {device_ip} -> {remote_ip}:{remote_port}"

        alert = IPSAlert(
            device_id=device.id if device else None,
            rule_id=r.id,
            alert_type="signature",
            message=msg,
            protocol=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
        )
        db.session.add(alert)
        db.session.commit()
        print(f"[IPS] {msg}")

        if action == "alert_block":
            existing = FirewallRule.query.filter_by(
                device_ip=device_ip,
                remote_ip=r.remote_ip,
                device_port=None,
                remote_port=r.remote_port,
                protocol=r.protocol or "any",
                direction="any",
            ).first()

            if not existing:
                fw = FirewallRule(
                    description=f"IPS BLOCK {device_ip} -> {r.remote_ip}",
                    device_ip=device_ip,
                    remote_ip=r.remote_ip,
                    device_port=None,
                    remote_port=r.remote_port,
                    protocol=r.protocol or "any",
                    direction="any",
                    enabled=True,
                )
                db.session.add(fw)
                db.session.commit()
                apply_firewall_rules()

        return True

    return False

def evaluate_ips_signatures_for_ip(device):
    
    device_ip = device.ip
    if not device_ip:
        return

    ips_rules = _load_ips_rules_for_device_ip(device_ip)
    if not ips_rules:
        return

    flows = parse_conntrack_for_ip(device_ip)

    for f in flows:
        proto = f.get("protocol", "ip")
        src_ip = f.get("src_ip")
        dst_ip = f.get("dst_ip")
        sport = int(f.get("src_port", 0) or 0)
        dport = int(f.get("dst_port", 0) or 0)

        if not src_ip or not dst_ip:
            continue

        try:
            _check_ips_packet(
                device=device,
                device_ip=device_ip,
                proto=proto,
                src_ip=src_ip,
                sport=sport,
                dst_ip=dst_ip,
                dport=dport,
                ips_rules=ips_rules,
            )
        except Exception as e:
            print(f"[IPS] Signature eval error for {device_ip}: {e}")


def do_scan():
    
    found = scan_devices()

    now = datetime.utcnow()
    current_macs = {d["mac"].lower() for d in found}

    for d in found:
        mac = d["mac"].lower()
        ip = d["ip"]
        hostname = d.get("name")

        device = Device.query.filter_by(mac=mac).first()
        if not device:
            device = Device(ip=ip, mac=mac)
            db.session.add(device)

        device.ip = ip
        device.is_online = True
        device.last_seen = now

        if hostname and (not device.name or device.name in ("", "Unknown", "None")):
            device.name = hostname

        # auto-vendor if possible
        v = guess_vendor(mac, hostname)
        if v and (not device.vendor or device.vendor in ("", "Unknown", "None")):
            device.vendor = v

        # auto device type/model
        m = guess_device_type(hostname)
        if m and (not device.model or device.model in ("", "Unknown", "None")):
            device.model = m

    # mark everything else offline
    all_devices = Device.query.all()
    for dev in all_devices:
        if dev.mac.lower() not in current_macs:
            dev.is_online = False

    db.session.commit()


# background auto-scan every 60 seconds
def auto_scan_loop():
 
    SCAN_INTERVAL = 2      # seconds between each full cycle
    SNIFF_DURATION = 3       # seconds of sniffing per device

    with app.app_context():
        while True:
            try:
                now = datetime.utcnow()
                _cleanup_expired_throttles()
                try:
                    found = scan_devices() or []
                except Exception as e:
                    print("Auto-scan: device scan failed:", e)
                    found = []

                seen_macs = set()

                for dev_info in found:
                    mac = dev_info.get("mac", "").lower()
                    ip_addr = dev_info.get("ip")
                    name = dev_info.get("name") or "Unknown"

                    if not mac:
                        continue

                    seen_macs.add(mac)

                    device = Device.query.filter_by(mac=mac).first()
                    if not device:
                        device = Device(
                            mac=mac,
                            ip=ip_addr,
                            name=name,
                            is_online=True,
                            last_seen=now,
                        )
                    else:
                        device.ip = ip_addr
                        device.name = name
                        device.is_online = True
                        device.last_seen = now

                    db.session.add(device)

                # mark devices that didn’t show up as offline
                for dev in Device.query.all():
                    if dev.mac and dev.mac.lower() not in seen_macs:
                        dev.is_online = False
                        db.session.add(dev)

                db.session.commit()

                online_devices = Device.query.filter_by(is_online=True).all()

                for dev in online_devices:
                    if not dev.ip:
                        continue
                    
                        
                    try:
                        hotspot_iface = app.config.get("HOTSPOT_IFACE", "wlo1")
                        total_bytes, flow_list = sniff_device_traffic_with_flows(
                            device_ip=dev.ip,
                            iface=hotspot_iface,
                            duration=SNIFF_DURATION,
                        )
                    except Exception as e:
                        print(f"Auto-scan: sniff failed for {dev.ip}: {e}")
                        continue
                    try:
                        evaluate_ips_for_device(
                            device=dev,
                            total_bytes=total_bytes,
                            flow_list=flow_list,
                            duration_seconds=SNIFF_DURATION,
                        )
                    except Exception as e:
                        print(f"[IPS] Error evaluating IPS for {dev.ip}: {e}")



                    # storing TrafficSample for graph
                    if total_bytes > 0:
                        rate_kbps = (total_bytes * 8.0 / SNIFF_DURATION) / 1000.0
                        sample = TrafficSample(
                            device_id=dev.id,
                            timestamp=datetime.utcnow(),
                            total_bytes=total_bytes,
                            rate_kbps=rate_kbps,
                        )
                        db.session.add(sample)

                    # Upsert Flow rows for this device
                    for f in flow_list:
                        proto = f.get("proto") or f.get("protocol")
                        src_ip = f.get("src") or f.get("src_ip")
                        src_port = f.get("sport") or f.get("src_port")
                        dst_ip = f.get("dst") or f.get("dst_ip")
                        dst_port = f.get("dport") or f.get("dst_port")
                        direction = f.get("direction")
                        packets = f.get("packets", 0)
                        last_seen = f.get("last_seen", datetime.utcnow())

                        if not (proto and src_ip and dst_ip):
                            continue

                        flow = Flow.query.filter_by(
                            device_id=dev.id,
                            protocol=proto,
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            direction=direction,
                        ).first()

                        if not flow:
                            flow = Flow(
                                device_id=dev.id,
                                protocol=proto,
                                src_ip=src_ip,
                                src_port=src_port,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                direction=direction,
                                packets=packets,
                                last_seen=last_seen,
                            )
                        else:
                            flow.packets += packets
                            flow.last_seen = last_seen

                        db.session.add(flow)

                db.session.commit()

            except Exception as e:
                print("Auto-scan error:", e)
                db.session.rollback()

            time.sleep(SCAN_INTERVAL)




def parse_conntrack_for_ip(ip: str):
    try:
        output = subprocess.check_output(["conntrack", "-L"], text=True)
    except subprocess.CalledProcessError as e:
        print("conntrack error:", e)
        return []

    flows = []
    now = datetime.utcnow()

    for line in output.splitlines():
        if ip not in line:
            continue

        m = re.search(
            r"^(?P<proto>\S+).+src=(?P<src_ip>\S+)\s+dst=(?P<dst_ip>\S+).*?"
            r"sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)",
            line,
        )
        if not m:
            continue

        proto = m.group("proto").upper()
        src_ip = m.group("src_ip")
        dst_ip = m.group("dst_ip")
        sport = int(m.group("sport"))
        dport = int(m.group("dport"))

        pm = re.search(r"packets=(\d+)", line)
        packets = int(pm.group(1)) if pm else 0

        flows.append(
            {
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "packets": packets,
                "last_seen": now,
            }
        )

    return flows





def _load_active_firewall_rules():
    
    try:
        rules = FirewallRule.query.filter_by(enabled=True).all()
    except Exception:
        return []

    def parse_net(text):
        text = (text or "").strip()
        if not text:
            return None
        try:
            if "/" in text:
                return ip_network(text, strict=False)
            # Single IP - /32 (IPv4) or /128 (IPv6)
            suffix = "/32" if ":" not in text else "/128"
            return ip_network(text + suffix, strict=False)
        except ValueError:
            return None

    simplified = []
    for r in rules:
        simplified.append(
            {
                "device_ip_raw": (r.device_ip or "").strip(),
                "remote_ip_raw": (r.remote_ip or "").strip(),
                "device_net": parse_net(r.device_ip),
                "remote_net": parse_net(r.remote_ip),
                "device_port": r.device_port,
                "remote_port": r.remote_port,
                "protocol": (r.protocol or "any").lower(),
                "direction": (r.direction or "any").lower(),
            }
        )
    return simplified

def _packet_blocked(proto, src_ip, sport, dst_ip, dport, rules):
    
    proto_l = proto.lower()

    try:
        src_addr = ip_address(src_ip)
        dst_addr = ip_address(dst_ip)
    except ValueError:
        src_addr = None
        dst_addr = None

    for r in rules:
        r_proto = r["protocol"]
        if r_proto not in ("any", proto_l):
            continue

        dev_net = r["device_net"]
        rem_net = r["remote_net"]
        dev_port = r["device_port"]
        rem_port = r["remote_port"]
        direction = r["direction"]

        #  Outgoing device - remote
        if direction in ("out", "any"):
            cond = True

            if dev_net is not None:
                if (
                    not src_addr
                    or src_addr.version != dev_net.version
                    or src_addr not in dev_net
                ):
                    cond = False

            if rem_net is not None:
                if (
                    not dst_addr
                    or dst_addr.version != rem_net.version
                    or dst_addr not in rem_net
                ):
                    cond = False

            if dev_port is not None and sport != dev_port:
                cond = False
            if rem_port is not None and dport != rem_port:
                cond = False

            if cond:
                return True

        # Incoming: remote - device 
        if direction in ("in", "any"):
            cond = True

            if dev_net is not None:
                if (
                    not dst_addr
                    or dst_addr.version != dev_net.version
                    or dst_addr not in dev_net
                ):
                    cond = False

            if rem_net is not None:
                if (
                    not src_addr
                    or src_addr.version != rem_net.version
                    or src_addr not in rem_net
                ):
                    cond = False

            if dev_port is not None and dport != dev_port:
                cond = False
            if rem_port is not None and sport != rem_port:
                cond = False

            if cond:
                return True

    return False

def sniff_device_traffic_with_flows(device_ip: str, iface: str, duration: int = 3):
    
    flows = {}
    total_bytes = 0

    # load firewall rules
    fw_rules = _load_active_firewall_rules()

    # load device record + IPS rules once
    device = Device.query.filter_by(ip=device_ip).first()
    ips_rules = _load_ips_rules_for_device_ip(device_ip)

    print(f"[IPS DEBUG] sniff for {device_ip}: loaded {len(ips_rules)} IPS rules")

    def _handle(pkt):
        nonlocal total_bytes

        try:
            # Identify IP layer
            ip_layer = None
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
            else:
                return  # not IP

            src = ip_layer.src
            dst = ip_layer.dst

            # Only handle packets involving this device
            if src != device_ip and dst != device_ip:
                return

            # Protocol + ports
            proto = "IP"
            sport = 0
            dport = 0

            if TCP in pkt:
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)

            if _packet_blocked(proto, src, sport, dst, dport, fw_rules):
                # print(f"[FW] DROP {proto} {src}:{sport} -> {dst}:{dport}")
                return

            # IPS SIGNATURE CHECK 
            blocked_by_ips = _check_ips_packet(
                device=device,
                device_ip=device_ip,
                proto=proto,
                src_ip=src,
                sport=sport,
                dst_ip=dst,
                dport=dport,
                ips_rules=ips_rules,
            )

            # allowed packet - update flow stats
            size = len(pkt)
            total_bytes += size

            key = (proto, src, sport, dst, dport)
            if key not in flows:
                flows[key] = {
                    "proto": proto,
                    "src": src,
                    "sport": sport,
                    "dst": dst,
                    "dport": dport,
                    "packets": 1,
                    "bytes": size,
                }
            else:
                flows[key]["packets"] += 1
                flows[key]["bytes"] += size

        except Exception as e:
            print(f"[SNIF DEBUG] handler error: {e}")

    # sniffing
    sniff(
        iface=iface,
        prn=_handle,
        timeout=duration,
        store=False
    )

    return total_bytes, list(flows.values())

 

#from ipaddress import ip_address, ip_network  # you already import these above

def evaluate_ips_for_device(device, total_bytes, flow_list, duration_seconds):
    """
    IPS for one device:
      1) Signature-based detection using IPSRule (CIDR, device_ip, port, proto)
      2) Anomaly detection based on data rate (kbps)
    """
    now = datetime.utcnow()
    device_ip = device.ip

    # ----------signature detection ----------
    try:
        all_rules = IPSRule.query.filter_by(enabled=True).all()
    except Exception as e:
        print(f"[IPS] Failed to load IPS rules: {e}")
        all_rules = []

    prepared_rules = []
    for r in all_rules:
        if r.device_ip and r.device_ip.strip() != device_ip:
            continue

        remote_ip = (r.remote_ip or "").strip()
        if not remote_ip:
            continue

        # parse IP / CIDR
        try:
            if "/" in remote_ip:
                net = ip_network(remote_ip, strict=False)
            else:
                suffix = "/32" if ":" not in remote_ip else "/128"
                net = ip_network(remote_ip + suffix, strict=False)
        except ValueError:
            continue

        prepared_rules.append(
            {
                "rule": r,
                "net": net,
                "proto": (r.protocol or "any").lower(),      # 'any', 'tcp', 'udp'
                "port": r.remote_port,                       # None or int
                "action": (r.action or "alert_block").lower()  # 'alert_only' / 'alert_block'
            }
        )

    if prepared_rules and flow_list:
        print(
            f"[IPS] eval for {device_ip}: "
            f"{len(flow_list)} flows, {len(prepared_rules)} IPS rules"
        )

        for f in flow_list:
            
            proto = (f.get("proto") or f.get("protocol") or "ip").lower()
            src_ip = f.get("src") or f.get("src_ip")
            dst_ip = f.get("dst") or f.get("dst_ip")
            sport = int(f.get("sport", 0) or 0)
            dport = int(f.get("dport", 0) or 0)

            if not src_ip or not dst_ip:
                continue

            # decide remote side relative to this device
            if src_ip == device_ip:
                remote_ip = dst_ip
                remote_port = dport
            elif dst_ip == device_ip:
                remote_ip = src_ip
                remote_port = sport
            else:
                continue

            try:
                remote_addr = ip_address(remote_ip)
            except ValueError:
                # non-ip? Skip.
                continue

            #checking against each IPS rule
            for pr in prepared_rules:
                r = pr["rule"]
                net = pr["net"]
                rule_proto = pr["proto"]
                rule_port = pr["port"]
                action = pr["action"]

                # protocol match
                if rule_proto not in ("any", proto):
                    continue

                # ip match
                if remote_addr.version != net.version or remote_addr not in net:
                    continue

                # port match if specified
                if rule_port is not None and remote_port != rule_port:
                    continue

                #log alert
                msg = (
                    f"Signature alert: Device {device_ip} "
                    f"connected to {remote_ip}:{remote_port}"
                )
                now = datetime.utcnow()

                # to avoid dublication
                last_alert = (
                    IPSAlert.query.filter_by(
                        device_id=device.id,
                        rule_id=r.id,
                        alert_type="signature",
                        dst_ip=dst_ip,
                        dst_port=dport,
                        protocol=proto.upper(),
                    )
                    .order_by(IPSAlert.created_at.desc())
                    .first()
                )
 
# If we already logged the same thing in the last 30 seconds, skip
                if last_alert and (now - last_alert.created_at).total_seconds() < 30:
    # We still rely on the firewall rule that was already created earlier.
                    return  # or "break" if you're inside a loop over rules

                print(f"[IPS] {msg}")
                
                alert = IPSAlert(
                    device_id=device.id,
                    rule_id=r.id,
                    alert_type="signature",
                    message=msg,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto.upper(),
                )
                db.session.add(alert)
                db.session.commit()
                # alert_block, create a firewall rule if needed
                if action == "alert_block":
                    existing = FirewallRule.query.filter_by(
                        device_ip=device_ip,
                        remote_ip=r.remote_ip,
                        device_port=None,
                        remote_port=r.remote_port,
                        protocol=r.protocol or "any",
                        direction="any",
                    ).first()

                    if not existing:
                        fw = FirewallRule(
                            description=f"IPS BLOCK {device_ip} -> {r.remote_ip}",
                            device_ip=device_ip,
                            remote_ip=r.remote_ip,
                            device_port=None,
                            remote_port=r.remote_port,
                            protocol=r.protocol or "any",
                            direction="any",
                            enabled=True,
                        )
                        db.session.add(fw)
                        db.session.commit()
                        apply_firewall_rules()

                break

    # anomaly detection
    if duration_seconds <= 0:
        return

    current_rate_kbps = (total_bytes * 8.0 / duration_seconds) / 1000.0
    threshold = IPS_RATE_THRESHOLD_KBPS

    if current_rate_kbps > threshold and device_ip not in THROTTLED_DEVICES:
        expires_at = now + timedelta(minutes=IPS_THROTTLE_DURATION_MINUTES)
        THROTTLED_DEVICES[device_ip] = expires_at

        print(
            f"[IPS] Anomaly alert for {device_ip}: "
            f"{current_rate_kbps:.1f} kbps > {threshold:.1f} kbps; throttling until {expires_at}"
        )

        # applying throttle via firewall chain
        _run_iptables(["-A", "SMART_FW", "-s", device_ip, "-j", "DROP"])
        _run_iptables(["-A", "SMART_FW", "-d", device_ip, "-j", "DROP"])

        anomaly_alert = IPSAlert(
            device_id=device.id,
            rule_id=None,
            alert_type="anomaly",
            message=(
                f"Anomaly: data rate {current_rate_kbps:.1f} kbps exceeds "
                f"threshold {threshold:.1f} kbps; device throttled"
            ),
            observed_rate_kbps=current_rate_kbps,
            throttle_applied=True,
            throttle_expires_at=expires_at,
        )
        db.session.add(anomaly_alert)
        db.session.commit()



# routes: auth

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            return redirect(url_for("index"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
    

# Routes: Firewall configuration (Function 3)

@app.route("/firewall")
@login_required
def firewall_page():
    rules = FirewallRule.query.order_by(FirewallRule.created_at.desc()).all()
    return render_template("firewall.html", has_unseen_alerts=has_unseen_alerts(),rules=rules, active_page="firewall")


@app.route("/firewall/add", methods=["POST"])
@login_required
def add_firewall_rule():
    description = request.form.get("description", "").strip()

    device_ip_value = request.form.get("device_ip", "").strip()
    remote_ip_value = request.form.get("remote_ip", "").strip()

    device_port_value = request.form.get("device_port", "").strip()
    remote_port_value = request.form.get("remote_port", "").strip()

    protocol = request.form.get("protocol", "any").lower()
    direction = request.form.get("direction", "any").lower()

    device_port = int(device_port_value) if device_port_value else None
    remote_port = int(remote_port_value) if remote_port_value else None

    # validate input
    if (
        not device_ip_value
        and not remote_ip_value
        and device_port is None
        and remote_port is None
    ):
        return redirect(url_for("firewall_page"))

    new_rule = FirewallRule(
        description=description or None,
        device_ip=device_ip_value or None,
        remote_ip=remote_ip_value or None,
        device_port=device_port,
        remote_port=remote_port,
        protocol=protocol,
        direction=direction,
        enabled=True,
    )

    db.session.add(new_rule)
    db.session.commit()

    apply_firewall_rules()

    return redirect(url_for("firewall_page"))



@app.route("/firewall/<int:rule_id>/toggle")
@login_required
def toggle_firewall_rule(rule_id):
    rule = FirewallRule.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    apply_firewall_rules()
    return redirect(url_for("firewall_page"))


@app.route("/firewall/<int:rule_id>/delete")
@login_required
def delete_firewall_rule(rule_id):
    rule = FirewallRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    apply_firewall_rules()
    return redirect(url_for("firewall_page"))

# routes: IPS dashboard (Function 4)



@app.route("/ips")
@login_required
def ips_dashboard():
    """
    Main IPS page:
      - Show form to add signature-based IPS rules
      - List existing rules
      - List recent alerts (signature + anomaly)
    """
    devices = Device.query.order_by(Device.ip).all()
    rules = IPSRule.query.order_by(IPSRule.created_at.desc()).all()
    alerts = (
        IPSAlert.query
        .order_by(IPSAlert.created_at.desc())
        .limit(100)
        .all()
    )

    return render_template(
        "ips.html",
        devices=devices,
        rules=rules,
        alerts=alerts,
        rate_threshold=IPS_RATE_THRESHOLD_KBPS,
        throttle_minutes=IPS_THROTTLE_DURATION_MINUTES,
        throttled_devices=THROTTLED_DEVICES,
        has_unseen_alerts=has_unseen_alerts(),
        active_page="ips"
    )


@app.route("/ips/rule/add", methods=["POST"])
@login_required
def add_ips_rule():

    description = (request.form.get("description") or "").strip()

    device_id_value = request.form.get("device_id") or ""
    device_ip_value = (request.form.get("device_ip") or "").strip()

    remote_ip_value = (request.form.get("remote_ip") or "").strip()
    remote_port_value = (request.form.get("remote_port") or "").strip()

    protocol = (request.form.get("protocol") or "any").lower()
    action = (request.form.get("action") or "alert_block").lower()
    enabled_value = request.form.get("enabled")

    remote_port = int(remote_port_value) if remote_port_value else None

    # determine which device
    device = None
    device_id = None
    device_ip = None

    if device_id_value:
        try:
            device_id = int(device_id_value)
        except ValueError:
            device_id = None

    if device_id:
        device = Device.query.get(device_id)
        if device:
            device_ip = device.ip

    # if user manually typed device_ip, prefer that
    if device_ip_value:
        device_ip = device_ip_value

    # If a rule has no remote_ip and no device_ip
    if (not remote_ip_value) or (not device_ip and not device):
        return redirect(url_for("ips_dashboard"))

    # Enabled checkbox
    enabled = bool(enabled_value == "on")

    rule = IPSRule(
        description=description or f"IPS rule for {device_ip or 'device'}",
        device_id=device.id if device else None,
        device_ip=device_ip,
        remote_ip=remote_ip_value or None,
        remote_port=remote_port,
        protocol=protocol,
        action=action,
        enabled=enabled,
    )

    db.session.add(rule)
    db.session.commit()

    return redirect(url_for("ips_dashboard"))


@app.route("/ips/rule/<int:rule_id>/toggle")
@login_required
def toggle_ips_rule(rule_id):
    
    rule = IPSRule.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    return redirect(url_for("ips_dashboard"))


@app.route("/ips/rule/<int:rule_id>/delete")
@login_required
def delete_ips_rule(rule_id):
    
    rule = IPSRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return redirect(url_for("ips_dashboard"))


@app.route("/ips/alerts/clear")
@login_required
def clear_ips_alerts():
    
    IPSAlert.query.delete()
    db.session.commit()
    return redirect(url_for("ips_dashboard"))





# Routes: main pages

@app.route("/")
@login_required
def index():
    online_devices = Device.query.filter_by(is_online=True).order_by(Device.ip).all()
    offline_devices = (
        Device.query.filter_by(is_online=False)
        .order_by(Device.last_seen.desc())
        .all()
    )
    return render_template(
        "devices.html",
        online_devices=online_devices,
        offline_devices=offline_devices,
        active_page="devices",
        has_unseen_alerts=has_unseen_alerts(),
    )


@app.route("/scan")
@login_required
def scan():
    do_scan()
    return redirect(url_for("index"))


@app.route("/edit/<int:device_id>", methods=["POST"])
@login_required
def edit_device(device_id):
    device = Device.query.get_or_404(device_id)

    device.name = request.form.get("name") or device.name
    device.vendor = request.form.get("vendor") or device.vendor
    device.model = request.form.get("model") or device.model

    db.session.commit()
    return redirect(url_for("index"))



# Routes: device detail, traffic and flows

@app.route("/device/<int:device_id>")
@login_required
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)

    # Y days history (default 7)
    days = request.args.get("days", 7, type=int)
    since = datetime.utcnow() - timedelta(days=days)

    
    # Fetch up to MAX_TRAFFIC_POINTS newest samples 
    recent_samples = (
        TrafficSample.query
        .filter(
            TrafficSample.device_id == device.id,
            TrafficSample.timestamp >= since,
        )
        .order_by(TrafficSample.timestamp.desc())
        .limit(MAX_TRAFFIC_POINTS)
        .all()
    )
    recent_samples = list(reversed(recent_samples))

    labels = [
        to_local(s.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        for s in recent_samples
    ]
    rates = [s.rate_kbps for s in recent_samples]
    current_rate_kbps = rates[-1] if rates else 0.0

    flows = (
        Flow.query
        .filter(
            Flow.device_id == device.id,
            Flow.last_seen >= since,
        )
        .order_by(Flow.last_seen.desc())
        .all()
    )

    return render_template(
        "device_detail.html",
        device=device,
        days=days,
        labels=labels,
        rates=rates,
        current_rate_kbps=current_rate_kbps,
        flows=flows,
        default_chart_window=DEFAULT_CHART_WINDOW,
        has_unseen_alerts=has_unseen_alerts(),
    )



@app.route("/device/<int:device_id>/traffic_json")
@login_required
def device_traffic_json(device_id):
   
    #from datetime import datetime, timedelta

    device = Device.query.get_or_404(device_id)

    # How many days of history to allow<
    days = request.args.get("days", 7, type=int)
    since = datetime.utcnow() - timedelta(days=days)

    # -------live Scapy sniff --
    current_rate_kbps = 0.0
    try:
        hotspot_iface = app.config.get("HOTSPOT_IFACE", "wlo1")

        total_bytes, _flows = sniff_device_traffic_with_flows(
            device_ip=device.ip,
            iface=hotspot_iface,
            duration=2,
        )

        if total_bytes and total_bytes > 0:
            current_rate_kbps = (total_bytes * 8.0 / 2.0) / 1000.0

    # mark device as online
            device.is_online = True
            device.last_seen = datetime.utcnow()
            db.session.add(device)

    # store this as a TrafficSample
            sample = TrafficSample(
                device_id=device.id,
                timestamp=datetime.utcnow(),
                total_bytes=total_bytes,
                rate_kbps=current_rate_kbps,
            )
            db.session.add(sample)
            db.session.commit()

    except Exception as e:
        print(f"device_traffic_json sniff error: {e}")

    # Get the most recent samples within the selected time range.
    recent_samples = (
        TrafficSample.query
        .filter(
            TrafficSample.device_id == device.id,
            TrafficSample.timestamp >= since,
        )
        .order_by(TrafficSample.timestamp.desc())
        .limit(MAX_TRAFFIC_POINTS)
        .all()
    )

    # Reverse them so they are oldest to newest for plotting
    recent_samples = list(reversed(recent_samples))

    labels = [
    to_local(s.timestamp).strftime("%Y-%m-%d %H:%M:%S")
    for s in recent_samples
    ]   

    rates = [s.rate_kbps for s in recent_samples]

    # If DB has data, use the latest as fallback current rate
    if rates:
        db_latest_rate = rates[-1]
    else:
        db_latest_rate = 0.0

    # Prefer the live sniff value if we got one
    current = current_rate_kbps or db_latest_rate

    return jsonify({
        "labels": labels,
        "rates": rates,
        "current_rate": current,
    })



@app.route("/device/<int:device_id>/flows_json")
@login_required
def device_flows_json(device_id):
    device = Device.query.get_or_404(device_id)

    days = request.args.get("days", 7, type=int)
    since = datetime.utcnow() - timedelta(days=days)

    flows = (
        Flow.query
        .filter(
            Flow.device_id == device.id,
            Flow.last_seen >= since,
        )
        .order_by(Flow.last_seen.desc())
        .all()
    )

    data = []
    for f in flows:
        data.append({
            "protocol": f.protocol,
            "src_ip": f.src_ip,
            "src_port": f.src_port,
            "dst_ip": f.dst_ip,
            "dst_port": f.dst_port,
            "packets": f.packets,
            "last_seen": to_local(f.last_seen).strftime("%Y-%m-%d %H:%M:%S"),
        })

    return jsonify(data)


@app.route("/device/<int:device_id>/sample_traffic")
@login_required
def sample_traffic(device_id):
    device = Device.query.get_or_404(device_id)

    # Interface used for sniffing
    iface = app.config.get("HOTSPOT_IFACE", "wlo1")
    duration = 5  # seconds

    try:
        # scapy flow aggregation
        total_bytes, flow_stats = sniff_device_traffic_with_flows(
            device.ip,
            iface,
            duration=duration,
        )
    except Exception as e:
        print("sample_traffic sniff error:", e)
        return redirect(url_for("device_detail", device_id=device.id))

    # convert bytes - kbps for the graph
    if duration > 0:
        rate_kbps = (total_bytes * 8.0 / duration) / 1000.0
    else:
        rate_kbps = 0.0

    # Store one traffic sample
    sample = TrafficSample(
        device_id=device.id,
        timestamp=datetime.utcnow(),
        total_bytes=total_bytes,   
        rate_kbps=rate_kbps,
    )
    db.session.add(sample)
    db.session.commit()

    return redirect(url_for("device_detail", device_id=device.id))

#  UPDATE FLOW
@app.route("/device/<int:device_id>/update_flows")
@login_required
def update_flows(device_id):
    device = Device.query.get_or_404(device_id)

    # Same iface as hotspot
    iface = app.config.get("HOTSPOT_IFACE", "wlo1")

    try:
        # Scapy capture with per-direction flows
        total_bytes, captured_flows = sniff_device_traffic_with_flows(
            device.ip,
            iface,
            duration=3,   #
        )
        print(f"update_flows: captured {len(captured_flows)} flows, {total_bytes} bytes")
    except Exception as e:
        print("update_flows sniff error:", e)
        return redirect(url_for("device_detail", device_id=device.id))

    now = datetime.utcnow() 

    for f in captured_flows:
        proto = f.get("proto", "IP")
        src_ip = f.get("src")
        dst_ip = f.get("dst")
        src_port = int(f.get("sport", 0) or 0)
        dst_port = int(f.get("dport", 0) or 0)
        packets = int(f.get("packets", 0) or 0)

        if not src_ip or not dst_ip:
            continue

        existing = (
            Flow.query.filter_by(
                device_id=device.id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
            )
            .first()
        )

        if existing:
            # gather packet counts & refresh timestamp
            existing.packets += packets
            existing.last_seen = now
        else:
            flow = Flow(
                device_id=device.id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                packets=packets,
                last_seen=now,
            )
            db.session.add(flow)

    db.session.commit()
    return redirect(url_for("device_detail", device_id=device.id))

@app.route("/ips/alerts/live")
@login_required
def ips_alerts_live():
    alerts = IPSAlert.query.order_by(IPSAlert.created_at.desc()).limit(100).all()
    return render_template("ips_alerts_live.html", alerts=alerts, has_unseen_alerts=has_unseen_alerts(), active_page="alerts")


@app.route("/device/<int:device_id>/delete_traffic")
@login_required
def delete_traffic(device_id):
    TrafficSample.query.filter_by(device_id=device_id).delete()
    db.session.commit()
    return redirect(url_for("device_detail", device_id=device_id))




@app.route("/device/<int:device_id>/delete_flows", methods=["POST", "GET"])
@login_required
def delete_flows(device_id):
    device = Device.query.get_or_404(device_id)

    if request.method == "POST":
        days = request.form.get("days_to_delete", type=int)
    else:
        days = request.args.get("days", type=int)

    query = Flow.query.filter_by(device_id=device.id)

    if days and days > 0:
        # Delete flows whose last_seen is older than N days
        cutoff = datetime.utcnow() - timedelta(days=days)
        query = query.filter(Flow.last_seen <= cutoff)

    query.delete()
    db.session.commit()

    return redirect(url_for("device_detail", device_id=device.id))

    
@app.route("/ips/settings", methods=["POST"])
@login_required
def update_ips_settings():
    
    global IPS_THROTTLE_DURATION_MINUTES, IPS_RATE_THRESHOLD_KBPS

    # --- Parse inputs ---
    minutes_raw = (request.form.get("throttle_minutes") or "").strip()
    threshold_raw = (request.form.get("rate_threshold_kbps") or "").strip()

    minutes = None
    threshold = None

    if minutes_raw:
        try:
            minutes = int(minutes_raw)
        except ValueError:
            print(f"[IPS] Invalid throttle_minutes value: {minutes_raw!r}")
            minutes = None
        else:
            minutes = max(1, min(60, minutes))

    if threshold_raw:
        try:
            threshold = float(threshold_raw)
        except ValueError:
            print(f"[IPS] Invalid rate_threshold_kbps value: {threshold_raw!r}")
            threshold = None
        else:
            threshold = max(100.0, min(1_000_000.0, threshold))

    if minutes is None and threshold is None:
        return redirect(url_for("ips_dashboard"))

    # Persist to DB singleton + update runtime globals
    cfg = IPSConfig.query.get(1)
    if cfg is None:
        cfg = IPSConfig(id=1)

    if minutes is not None:
        cfg.throttle_minutes = minutes
        IPS_THROTTLE_DURATION_MINUTES = minutes

    if threshold is not None:
        cfg.rate_threshold_kbps = threshold
        IPS_RATE_THRESHOLD_KBPS = threshold

    cfg.updated_at = datetime.utcnow()

    db.session.add(cfg)
    db.session.commit()

    print(
        f"[IPS] Updated settings via UI: "
        f"threshold={IPS_RATE_THRESHOLD_KBPS:.1f} kbps, throttle={IPS_THROTTLE_DURATION_MINUTES} min"
    )

    return redirect(url_for("ips_dashboard"))

    if minutes < 1:
        minutes = 1
    if minutes > 60:
        minutes = 60

    IPS_THROTTLE_DURATION_MINUTES = minutes
    print(f"[IPS] Updated throttle duration to {minutes} minutes via UI")

    return redirect(url_for("ips_dashboard"))

    
#---------------------------Firewall----------------

def setup_firewall():
    try:
        init_firewall_chain()
        apply_firewall_rules()
    except Exception as e:
        print("Firewall setup error:", e)
        
@app.route("/ips/reset_throttle/<int:device_id>")
@login_required
def reset_throttle(device_id):
    device = Device.query.get_or_404(device_id)

    if not device.ip:
        return redirect(url_for("ips_dashboard"))

    ip = device.ip

    #  Remove from in-memory throttle map
    if ip in THROTTLED_DEVICES:
        del THROTTLED_DEVICES[ip]

    # remove DROP rules for this IP in SMART_FW 
    _run_iptables(["-D", "SMART_FW", "-s", ip, "-j", "DROP"])
    _run_iptables(["-D", "SMART_FW", "-d", ip, "-j", "DROP"])

    # log an IPSAlert about the manual reset 
    alert = IPSAlert(
        device_id=device.id,
        rule_id=None,
        alert_type="throttle_reset",
        message=f"Throttle reset manually for device {ip}",
    )
    db.session.add(alert)
    db.session.commit()

    return redirect(url_for("ips_dashboard"))

# Entry point


def _start_auto_scan_thread():
    """Start the background auto-scan loop in a daemon thread."""
    t = threading.Thread(
        target=lambda *args, **kwargs: auto_scan_loop(),  # accept & ignore any args
        daemon=True,
    )
    t.start()


if __name__ == "__main__":

    
    with app.app_context():
        db.create_all()
        try:
            init_firewall_chain()
            apply_firewall_rules()
        except Exception as e:
            print("Firewall initialization error:", e)

    
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        _start_auto_scan_thread()

 
    app.run(host="0.0.0.0", port=5000, debug=True)

