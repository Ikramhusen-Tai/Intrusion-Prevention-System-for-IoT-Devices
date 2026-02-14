# list_devices.py
import subprocess
import ipaddress
import time
import re

HOTSPOT_IFACE = "wlo1"
NETWORK_CIDR = "10.42.0.0/24"
LEASES_FILE = "/var/lib/misc/dnsmasq.leases"


# runs a shell command and returns the command output (stdout) as a string.
# used to fetch system-level networking info - RP/neighbor table via `ip neigh`) from Python.

def run_cmd(cmd: str) -> str:
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout

# send one ping to every IP in the subnet to force Linux to see active devices in its neighbor table
def ping_sweep():
    net = ipaddress.ip_network(NETWORK_CIDR, strict=False)
    print(f"[+] Scanning network {NETWORK_CIDR} ...")
    for ip in net.hosts():
        subprocess.Popen(
            f"ping -c 1 -W 1 {ip} >/dev/null 2>&1",
            shell=True,
        )

#parse dnsmasq lease records to map each device MAC address to its DHCP hostname 
def load_dhcp_names():
    names_by_mac = {}

    try:
        with open(LEASES_FILE, "r") as f:
            for line in f:
                parts = line.strip().split()
                # <expiry> <mac> <ip> <hostname> <client_id>
                if len(parts) >= 4:
                    _expiry, mac, ip, hostname = parts[:4]
                    mac = mac.lower()

                    if hostname and hostname != "*":
                        names_by_mac[mac] = hostname
    except FileNotFoundError:
        pass

    return names_by_mac

# building a clean device list (IP, MAC, hostname) by combining ARP/neighbor data with dnsmasq lease hostnames.
def get_devices():
    output = run_cmd("ip neigh")
    devices = []

    names_by_mac = load_dhcp_names()

    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            ip_addr = parts[0]
            iface = parts[2]
            mac = parts[4].lower()

            if iface == HOTSPOT_IFACE and re.match(
                r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac
            ):
                hostname = names_by_mac.get(mac)
                devices.append(
                    {
                        "ip": ip_addr,
                        "mac": mac,
                        "name": hostname if hostname else "Unknown",
                    }
                )

    return devices

#  this function called by the Flask app to performs a ping sweep then collects discovered devices.
def scan_devices():
    ping_sweep()
    time.sleep(2)
    return get_devices()


def main():
    devices = scan_devices()
    print("\nDiscovered Devices:")
    print("------------------------------")
    for dev in devices:
        print(
            f"IP: {dev['ip']}, MAC: {dev['mac']}, Name: {dev['name']}"
        )
    print("------------------------------")


if __name__ == "__main__":
    main()
