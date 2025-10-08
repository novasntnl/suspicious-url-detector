import re
from urllib.parse import urlparse

suspicious_keywords = [
    "login", "verify", "update", "secure", "account", "paypal", "bank", "signin"
]

def is_ip_address(domain):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None

def check_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path.lower()

    alerts = []

    if is_ip_address(domain):
        alerts.append("⚠️ Suspicious: URL uses an IP address instead of a domain.")

    for word in suspicious_keywords:
        if word in url.lower():
            alerts.append(f"⚠️ Suspicious keyword found: '{word}'")

    if len(url) > 75:
        alerts.append("⚠️ Suspicious: URL is very long.")

    return alerts

if __name__ == "__main__":
    print("🛡️ Simple URL Checker")
    url = input("Enter a URL to check: ").strip()
    results = check_url(url)

    if results:
        for res in results:
            print(res)
    else:
        print("✅ Looks safe (based on simple checks).")
