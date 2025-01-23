import socket
import requests
import subprocess
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama for colorful console output
init(autoreset=True)

# Tool Header
def print_header():
    print(Fore.CYAN + "=" * 50)
    print(Fore.CYAN + " " * 10 + "PY-HAWK: A Recon & Scan Tool" + " " * 10)
    print(Fore.CYAN + "=" * 50)

# Basic Recon: Whois Lookup
def whois_lookup(domain):
    print(Fore.GREEN + f"\nPerforming WHOIS lookup for {domain}...")
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        print(Fore.YELLOW + result.stdout)
    except Exception as e:
        print(Fore.RED + f"Error performing WHOIS lookup: {e}")

# HTTP Headers Scan
def headers_scan(domain):
    print(Fore.GREEN + f"\nFetching HTTP headers for {domain}...")
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        for header, value in response.headers.items():
            print(Fore.YELLOW + f"{header}: {value}")
    except Exception as e:
        print(Fore.RED + f"Error fetching HTTP headers: {e}")

# DNS Lookup
def dns_lookup(domain):
    print(Fore.GREEN + f"\nPerforming DNS lookup for {domain}...")
    try:
        ip_address = socket.gethostbyname(domain)
        print(Fore.YELLOW + f"IP Address: {ip_address}")
    except Exception as e:
        print(Fore.RED + f"Error resolving DNS: {e}")

# Web Crawler
def crawl_website(domain):
    print(Fore.GREEN + f"\nCrawling website {domain} for links and forms...")
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        # Find all links
        links = [a['href'] for a in soup.find_all('a', href=True)]
        print(Fore.YELLOW + "\nLinks found:")
        for link in links:
            print(link)
        # Find forms
        print(Fore.YELLOW + "\nForms found:")
        forms = soup.find_all('form')
        for form in forms:
            print(form)
    except Exception as e:
        print(Fore.RED + f"Error crawling website: {e}")

# SQL Injection Vulnerability Scan
def sql_injection_scan(domain):
    print(Fore.GREEN + f"\nScanning {domain} for SQL Injection vulnerabilities...")
    payloads = ["' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT 1,2,3--"]
    test_url = input(Fore.YELLOW + "Enter a test URL (e.g., /login): ").strip()
    full_url = urljoin(f"http://{domain}", test_url)
    try:
        for payload in payloads:
            response = requests.get(full_url, params={'id': payload}, timeout=5)
            if "error" in response.text.lower():
                print(Fore.RED + f"[!] Vulnerability found with payload: {payload}")
            else:
                print(Fore.GREEN + f"[+] No vulnerability detected with payload: {payload}")
    except Exception as e:
        print(Fore.RED + f"Error during SQL injection scan: {e}")

# Main Menu
def menu():
    while True:
        print_header()
        print(Fore.MAGENTA + """
        [1] WHOIS Lookup
        [2] HTTP Headers Scan
        [3] DNS Lookup
        [4] Web Crawler
        [5] SQL Injection Scan
        [Q] Quit
        """)
        choice = input(Fore.YELLOW + "Enter your choice: ").strip().upper()
        if choice == '1':
            domain = input(Fore.YELLOW + "Enter the domain: ").strip()
            whois_lookup(domain)
        elif choice == '2':
            domain = input(Fore.YELLOW + "Enter the domain: ").strip()
            headers_scan(domain)
        elif choice == '3':
            domain = input(Fore.YELLOW + "Enter the domain: ").strip()
            dns_lookup(domain)
        elif choice == '4':
            domain = input(Fore.YELLOW + "Enter the domain: ").strip()
            crawl_website(domain)
        elif choice == '5':
            domain = input(Fore.YELLOW + "Enter the domain: ").strip()
            sql_injection_scan(domain)
        elif choice == 'Q':
            print(Fore.CYAN + "Exiting PY-HAWK...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

# Main Execution
if __name__ == "__main__":
    menu()
