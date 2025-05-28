# IPThreatIntelTool 🔍

A Python-based IP threat intelligence toolkit that helps cybersecurity analysts investigate IP addresses using open-source APIs. Designed for blue team workflows, SOC environments, and automation.

## 💠 Features

* 🌐 IP Geolocation Lookup (`ipapi`)
* 🕵️ VPN / Proxy / TOR / Relay Detection (`vpnapi.io`)
* 🚨 IP Reputation / Abuse Score (`AbuseIPDB`)
* 🔓 Port Scan with **optional Shodan integration**
* ⚠️ Includes a FREE alternative using `socket` for scanning well-known ports
* 📂 NEW: Bulk IP scanning via file input (`IPThreatIntel_Bulk.py`)

---

## 📁 Included Scripts

### ✅ `IPThreatIntelTool.py`

Main tool using external APIs including Shodan. Recommended for deep, individual IP analysis.

> **Note**: Shodan’s free tier often has strict limits. You may encounter 403 errors or unreliable access without upgrading.

### ✅ `IPThreatInspector_Socket.py`

Socket-based port scanner — an alternative to Shodan when you want a free, local scan for common ports.

> Useful when you're testing on a budget or Shodan access fails.

### ✅ `IPThreatIntel_Bulk.py`

Upgraded version of the tool that allows users to scan a **list of IP addresses** from a file. Performs geolocation, VPN/proxy/TOR checks, abuse score lookup, and optionally attempts port analysis on each IP.

> Ideal for batch investigations in SOC environments or automated pipelines.

---

## 🚀 Usage

1. Clone the repo:

   ```bash
   git clone https://github.com/your-username/IPThreatIntelTool.git
   cd IPThreatIntelTool
   ```

2. Install requirements:

   ```bash
   pip install requests
   ```

3. Run individual IP scan:

   ```bash
   python IPThreatIntelTool.py
   ```

4. Run socket-based version:

   ```bash
   python IPThreatInspector_Socket.py
   ```

5. Run bulk scan from file:

   ```bash
   python IPThreatIntel_Bulk.py
   ```

   > You will be prompted to enter the file name. Each line in the file should contain one IP address.

---

## 🔐 Requirements

* Python 3.7+
* API keys from:

  * [ipapi.co](https://ipapi.co/)
  * [vpnapi.io](https://vpnapi.io/)
  * [abuseipdb.com](https://abuseipdb.com/)
  * [shodan.io](https://shodan.io) *(optional)*

---

## 🧠 Why This Exists

Most open-source IP scanners require paid API tiers for full functionality. This tool was built to bridge that gap — using socket-based scanning as a fallback when Shodan isn’t available, and giving students, researchers, and SOC analysts a practical tool.

With the added bulk scanner, it's now suitable for both **one-off investigations** and **large-scale threat analysis workflows.**

---


