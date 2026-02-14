# Smart Home Intrusion Prevention System (IPS)

A lightweight network-based intrusion prevention system designed to monitor, detect, and block suspicious activity in a smart home environment. The system runs as a gateway that inspects traffic from connected devices and applies automated firewall rules to mitigate threats in real time.

This project demonstrates practical implementation of Linux networking, firewall automation, and security monitoring using open-source tools and a custom dashboard.

---

## Overview

Smart home and IoT devices often lack strong built-in security. This project addresses that gap by creating a gateway-level IPS that:

- Discovers connected devices  
- Monitors traffic behavior  
- Detects anomalies or suspicious activity  
- Blocks malicious IPs automatically  
- Provides a web dashboard for monitoring and control  

---

## Tech Stack

- OS: Ubuntu Linux  
- Networking: hostapd, dnsmasq  
- Firewall: iptables  
- Backend: Python (Flask)  
- Database: SQLite  
- Frontend: HTML, Jinja templates, Bootstrap  

---

## Features

- Real-time device discovery  
- Traffic monitoring and logging  
- Automated firewall rule enforcement  
- Intrusion detection and prevention logic  
- Web-based monitoring dashboard  

---


---

## Installation

### Prerequisites
- Ubuntu Linux machine
- Python 3
- Root/admin privileges

Install required packages:

```bash
sudo apt update
sudo apt install hostapd dnsmasq iptables python3-pip
pip install flask


