import argparse
import dns.resolver
import requests
import socket
import warnings

# Suppress all warnings from urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)


def check_port(ip, port):
    """Checks if a specific port is open on a given IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5) # Reduced timeout for faster scanning
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    finally:
        sock.close()

def get_web_technologies(url):
    """Identifies web technologies by inspecting HTTP headers and page content."""
    technologies = {}
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=3, headers=headers, verify=False)

        resp_headers = response.headers

        if 'Server' in resp_headers:
            technologies['Server'] = resp_headers['Server']
        if 'X-Powered-By' in resp_headers:
            technologies['X-Powered-By'] = resp_headers['X-Powered-By']

        body = response.text.lower()
        if 'wp-content' in body or 'wordpress' in body:
            technologies['CMS'] = 'WordPress'
        elif 'joomla' in body:
            technologies['CMS'] = 'Joomla'
        elif 'drupal' in body or 'sites/all' in body:
            technologies['CMS'] = 'Drupal'

    except requests.RequestException:
        return None
    return technologies

def attack_surface_mapper(domain):
    """
    Maps the attack surface of a given domain.
    """
    print(f"[+] بدء عملية مسح سطح الهجوم لـ: {domain}\n")

    common_subdomains = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "cpanel", "whm", "autodiscover", "dev", "api", "test", "vpn", "moodle", "portal", "owa"
    ]

    found_subdomains = []

    print("[*] البحث عن النطاقات الفرعية...")

    # Check the root domain first
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for ip in answers:
            found_subdomains.append((domain, str(ip)))
            print(f"  [>] تم العثور على: {domain} -> {ip}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        print(f"[-] لا يمكن العثور على سجلات للنطاق الجذر: {domain}. تأكد من صحة النطاق.")
        return

    # Check common subdomains
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            for ip in answers:
                if (full_domain, str(ip)) not in found_subdomains:
                    found_subdomains.append((full_domain, str(ip)))
                    print(f"  [>] تم العثور على: {full_domain} -> {ip}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            continue

    print("\n[*] فحص المنافذ المفتوحة والتقنيات المستخدمة...")

    unique_subdomains = sorted(list(set(found_subdomains)))

    if not unique_subdomains:
        print("[-] لم يتم العثور على أي نطاقات فرعية.")
        return

    for sub_domain, ip in unique_subdomains:
        print(f"\n--- نتائج {sub_domain} ({ip}) ---")

        found_open_port = False
        for port in [80, 443]:
            if check_port(ip, port):
                found_open_port = True
                print(f"  [+] المنفذ {port} مفتوح")
                protocol = "https" if port == 443 else "http"
                url = f"{protocol}://{sub_domain}"

                print(f"    [*] تحديد التقنيات على {url}...")
                techs = get_web_technologies(url)
                if techs:
                    for tech, value in techs.items():
                        print(f"      - {tech}: {value}")
                else:
                    print("      - تعذر تحديد التقنيات.")

        if not found_open_port:
            print("  [-] لم يتم العثور على منافذ ويب مفتوحة (80, 443).")


def main():
    parser = argparse.ArgumentParser(description="أداة لمسح سطح الهجوم لنطاق معين.", epilog="مثال: python attack_surface_mapper.py example.com")
    parser.add_argument("domain", help="النطاق الهدف للمسح.")
    args = parser.parse_args()

    attack_surface_mapper(args.domain)

if __name__ == "__main__":
    main()
