
import requests
import socket

# === CONFIGURATION === #
VPNAPI_KEY = "YOUR_API_KEY_HERE"
ABUSEIPDB_KEY = "YOUR_API_KEY_HERE"

# === GEOLOCATION LOOKUP === #
def get_ip_location(ip_address):  
    response = requests.get(f"https://ipinfo.io/{ip_address}/json?token=YOUR_API_TOKEN_HERE")  
    if response.status_code == 200:  
        result = response.json()
        print(f"The IP Address entered was: {result.get('ip')}")
        print(f"Country: {result.get('country')}")  # Country code (e.g., US)
        print(f"Region: {result.get('region')}")
        print(f"City: {result.get('city')}")
        print(f"ISP: {result.get('org')}")
    else:
        print("Failed to retrieve data.")

# === VPN / PROXY / TOR CHECK === #
def get_anonymity_status(ip):
    url = f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            sec = response.json().get("security", {})
            print(f"🕵️ Anonymity Check:")
            print(f"  VPN: {sec.get('vpn')}")
            print(f"  Proxy: {sec.get('proxy')}")
            print(f"  TOR: {sec.get('tor')}")
            print(f"  Relay: {sec.get('relay')}")
        else:
            print("  Failed to get VPN/proxy info.")
    except Exception as e:
        print(f"  Error: {e}")

# === ABUSE / REPUTATION CHECK === #
def get_abuse_score(ip):
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()["data"]
            print(f"🚨 Reputation Info:")
            print(f"  Abuse Score: {data.get('abuseConfidenceScore')}")
            print(f"  Total Reports: {data.get('totalReports')}")
            print(f"  Last Reported: {data.get('lastReportedAt')}")
        else:
            print("  Failed to get abuse info.")
    except Exception as e:
        print(f"  Error: {e}")

# === BASIC PORT SCANNER === #
def basic_port_scan(ip):
    print(f"🔓 Basic Port Scan (Top 10 common ports):")
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        443: "HTTPS",
        445: "SMB"
    }
    for port, name in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"  Port {port} ({name}) is OPEN")
            sock.close()
        except socket.error:
            print(f"  Could not connect to port {port}")

# === MAIN EXECUTION === #
def main():
    ip = input("🔍 Enter the IP address to analyze: ").strip()
    print("="*50)
    get_ip_location(ip)
    print("-"*50)
    get_anonymity_status(ip)
    print("-"*50)
    get_abuse_score(ip)
    print("-"*50)
    basic_port_scan(ip)
    print("="*50)

if __name__ == "__main__":
    main()
