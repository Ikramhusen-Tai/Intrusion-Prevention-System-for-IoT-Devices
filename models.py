from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    mac = db.Column(db.String(50))
    name = db.Column(db.String(100))
    vendor = db.Column(db.String(100))
    model = db.Column(db.String(100))
    description = db.Column(db.String(200))
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return str(self.id)


class Flow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"))

    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))

    direction = db.Column(db.String(10), default="unknown")
    packets = db.Column(db.Integer)
    bytes = db.Column(db.Integer, default=0)

    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


class TrafficSample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # NEW fields used by sample_traffic()
    total_bytes = db.Column(db.Integer)
    rate_kbps = db.Column(db.Float)
    
class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    description = db.Column(db.String(200))

    device_ip = db.Column(db.String(50))       # e.g. 192.168.1.42/32
    device_port = db.Column(db.Integer)        # local port

    remote_ip = db.Column(db.String(50))       # e.g. 142.250.0.0/15
    remote_port = db.Column(db.Integer)        # e.g. 443

    # "tcp", "udp", or "any"
    protocol = db.Column(db.String(10), default="any")

    # "in", "out", or "any"
    direction = db.Column(db.String(10), default="any")

    # Enable/disable without deleting
    enabled = db.Column(db.Boolean, default=True)


class IPSRule(db.Model):
    __tablename__ = "ips_rule"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    description = db.Column(db.String(200))

    # Which device this rule is for
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=True)
    device_ip = db.Column(db.String(50))   

    # Signature / pattern to match
    remote_ip = db.Column(db.String(50))   # e.g. "203.0.113.5" or "203.0.113.0/24"
    remote_port = db.Column(db.Integer)   
    protocol = db.Column(db.String(10), default="any")  # tcp/udp/any


    action = db.Column(db.String(20), default="alert_block")

    enabled = db.Column(db.Boolean, default=True)


class IPSAlert(db.Model):
    __tablename__ = "ips_alert"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    device_id = db.Column(db.Integer, db.ForeignKey("device.id"))
    rule_id = db.Column(db.Integer, db.ForeignKey("ips_rule.id"), nullable=True)

    alert_type = db.Column(db.String(20))

    message = db.Column(db.String(300))

    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))

    observed_rate_kbps = db.Column(db.Float, nullable=True)
    throttle_applied = db.Column(db.Boolean, default=False)
    throttle_expires_at = db.Column(db.DateTime, nullable=True)



class IPSConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rate_threshold_kbps = db.Column(db.Float, default=12000.0)
    throttle_minutes = db.Column(db.Integer, default=2)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

