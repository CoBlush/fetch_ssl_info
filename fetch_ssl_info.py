import ssl
import socket
import json
import csv
import logging
from datetime import datetime

# Constants
INPUT_FILE = 'domains.txt'
JSON_OUTPUT = 'ssl_results.json'
CSV_OUTPUT = 'ssl_results.csv'

# Setup logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_ssl_info(domain, port=443):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issued_to = subject.get('commonName')
                expires = cert['notAfter']
                expires_dt = datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')
                logging.info(f"[✔] {domain} - Issued to: {issued_to} - Expires: {expires_dt.strftime('%Y-%m-%d')}")
                return {
                    'domain': domain,
                    'issued_to': issued_to,
                    'expires_on': expires_dt.strftime('%Y-%m-%d'),
                    'valid': True,
                    'error': None
                }
    except Exception as e:
        logging.error(f"[✖] {domain} - Error: {e}")
        return {
            'domain': domain,
            'issued_to': None,
            'expires_on': None,
            'valid': False,
            'error': str(e)
        }

def load_domains(filename):
    try:
        with open(filename, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
            logging.info(f"Loaded {len(domains)} domains from {filename}")
            return domains
    except FileNotFoundError:
        logging.critical(f"Input file '{filename}' not found.")
        return []

def save_results(results):
    with open(JSON_OUTPUT, 'w') as jf:
        json.dump(results, jf, indent=4)
    logging.info(f"Saved JSON output to {JSON_OUTPUT}")

    with open(CSV_OUTPUT, 'w', newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=['domain', 'issued_to', 'expires_on', 'valid', 'error'])
        writer.writeheader()
        writer.writerows(results)
    logging.info(f"Saved CSV output to {CSV_OUTPUT}")

def main():
    domains = load_domains(INPUT_FILE)
    if not domains:
        return

    results = [get_ssl_info(domain) for domain in domains]
    save_results(results)

if __name__ == '__main__':
    main()
