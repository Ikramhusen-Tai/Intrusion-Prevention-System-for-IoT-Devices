#!/usr/bin/env bash
set -e


WAN_IF="enx5632c775fef2"   # internet side(my iPhone)
AP_IF="wlo1"               # Wi-Fi hotspot interface
AP_IP="10.42.0.1/24"       # hotspot IP /24

# bringing up hotspot interface $AP_IF on $AP_IP"
ip link set "$AP_IF" up || true
ip addr flush dev "$AP_IF" || true
ip addr add "$AP_IP" dev "$AP_IF"

# enabling IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# restarting hostapd and dnsmasq
systemctl restart hostapd
systemctl restart dnsmasq

# resetting iptables NAT / FORWARD rules 
iptables -t nat -D POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i "$WAN_IF" -o "$AP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$AP_IF" -o "$WAN_IF" -j ACCEPT 2>/dev/null || true

# adding iptables NAT / FORWARD rules
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
iptables -A FORWARD -i "$WAN_IF" -o "$AP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "$AP_IF" -o "$WAN_IF" -j ACCEPT

echo
echo "Hotspot script finished."
echo "Hotspot SSID is configured in /etc/hostapd/hostapd.conf"
echo "ip addr show $AP_IF"
echo "systemctl status hostapd dnsmasq"
