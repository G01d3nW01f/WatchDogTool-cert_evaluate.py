#!/usr/bin/python3

import ssl
import socket
from urllib.parse import urlparse
import sys
from datetime import datetime
import json  # add for change the dic to json

def init():
    if len(sys.argv) != 2:
        print(f"[+] Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)
    return sys.argv[1]

def get_cert(url):
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # output the cert to text file
                filename = f"{hostname}.cert.txt"
                with open(filename, "w") as f:
                    f.write(json.dumps(cert, indent=4))  
                print(f"[+] Certificate saved to {filename}")
                return cert
    except Exception as e:
        print(f"[-] Error fetching cert: {e}")
        sys.exit(1)

def score_cert(cert, url):
    score = 0
    reasons = []

    # CA check
    issuer = dict(x[0] for x in cert['issuer']).get('organizationName', '')
    if 'Let’s Encrypt' in issuer:
        score += 10
        reasons.append("CA is Let’s Encrypt (+10)")
    elif issuer not in ['DigiCert', 'GlobalSign', 'Sectigo']:
        score += 20
        reasons.append(f"Unrecognized CA: {issuer} (+20)")

    # check for varidity period
    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
    issued = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y GMT')
    days = (expiry - issued).days
    if days < 90:
        score += 15
        reasons.append(f"Short validity period: {days} days (+15)")

    # domain
    cn = dict(x[0] for x in cert['subject']).get('commonName', '')
    hostname = urlparse(url).hostname
    if cn != hostname:
        score += 20
        reasons.append(f"Domain mismatch: {cn} != {hostname} (+20)")

    return score, reasons

def main():
    target_url = init()
    cert = get_cert(target_url)
    score, reasons = score_cert(cert, target_url)

    print(f"[+] Target: {target_url}")
    print(f"[+] Score: {score}/100")
    if reasons:
        print("[+] Reasons:")
        for reason in reasons:
            print(f"  - {reason}")
    if score > 50:
        print("[!] WARNING: This site might be little suspicious or misconfiguration")
    elif score > 65:
        print("[!] WARNING: this site might be suspicious")
    else:
        print("[+] Looks relatively safe.")

if __name__ == "__main__":
    main()
