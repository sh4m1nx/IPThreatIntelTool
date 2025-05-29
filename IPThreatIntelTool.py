
import requests
import shodan

# === CONFIGURATION === #
VPNAPI_KEY = "YOUR_API_KEY_HERE"
ABUSEIPDB_KEY = "YOUR_API_KEY_HERE"
SHODAN_KEY = "YOUR_API_KEY_HERE"

# === GEOLOCATION LOOKUP === #
def get_ip_location(ip_address):  
    response = requests.get(f"https://ipinfo.io/{ip_address}/json?token=YOUR_REAL_API_TOKEN_HERE") 
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

# === SHODAN OPEN PORTS === #
def get_open_ports(ip):
    try:
        api = shodan.Shodan(SHODAN_KEY)
        result = api.host(ip)
        print(f"🔓 Open Ports & Services:")
        for item in result.get("data", []):
            port = item.get("port")
            product = item.get("product")
            transport = item.get("transport")
            print(f"  Port {port}/{transport} - {product}")
    except shodan.APIError as e:
        print(f"  Shodan Error: {e}")
    except Exception as e:
        print(f"  Error: {e}")

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
    get_open_ports(ip)
    print("="*50)

if __name__ == "__main__":
    main()
