#!/usr/bin/env python3

import platform
import pyfiglet
import argparse
import socket
import sys
import itertools
import threading
import time
import nmap
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored


ascii_banner = pyfiglet.figlet_format("SigmaScan!!")
print(ascii_banner)

result = pyfiglet.figlet_format("Created By ", font="digital")
print(result)

# Ask the user for the target IP address
ip = input("Enter IP address to scan: ")

print(" " * 60)
print(f"Please wait, scanning remote host {ip}")

# Ask the user to select a scan option
print('Select a scan option:')
print('1. Basic (Ports: 20, 21, 22, 23, 25, 53, 69, 80, 110, 135, 139, 143, 443, 465, 587, 636, 993, 995,1337, 3306)')
print('2. Medium (Ports: 1-1024)')
print('3. High (Ports: 1-65535)')
scan_option = input('Enter the number of the scan option to use (default: 2): ')
if scan_option == '1':
    ports = [20, 21, 22, 23, 25, 53, 69, 80, 110, 135, 139, 143, 443, 465, 587, 636, 993, 995,1337, 3306]
elif scan_option == '2':
    ports = range(1, 1025)
else:
    ports = range(1, 65536)

# Initialize nmap scanner
scanner = nmap.PortScanner()

# Define function to scan a single port on a target host
# Define function to scan a single port on a target host
def scan_port(target_host, port):
    try:
        result = scanner.scan(target_host, str(port), arguments='-sV -sC')
        port_status = result['scan'][target_host]['tcp'][port]['state']
        if port_status == 'open':
            print(colored(f"[+] Port {port} is open", 'green'))
            print(f"\tService: {result['scan'][target_host]['tcp'][port]['name']}")
            print(f"\tVersion: {result['scan'][target_host]['tcp'][port]['version']}")
    except:
        print(colored(f"[!] Error scanning port {port}", 'yellow'))


# Define function to scan a target host for open ports
def scan_host(target_host):
    try:
        start_time = datetime.now()
        print(f"Scanning host {target_host}...")
        for port in ports:
            with ThreadPoolExecutor(max_workers=10) as executor:
                executor.submit(scan_port, target_host, port)
        end_time = datetime.now()
        scan_duration = end_time - start_time
        print(f"Scanning completed in {scan_duration}")
    except KeyboardInterrupt:
        print(colored("[!] Keyboard Interrupt - Exiting...", 'yellow'))
        sys.exit()
    except:
        print(colored(f"[!] Error scanning host {target_host}", 'yellow'))

# Start the scan
try:
    scan_host(ip)
except KeyboardInterrupt:
    print(colored("[!] Keyboard Interrupt - Exiting...", 'yellow'))
    sys.exit()
except socket.gaierror:
    print(colored("[!] Hostname could not be resolved", 'yellow'))
    sys.exit()
except socket.error:
    print(colored("[!] Could not connect to server", 'yellow'))
    sys.exit()
except:
    print(colored("[!] Unexpected error:", 'yellow'))
    raise
