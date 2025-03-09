import subprocess
import time
import sys
import os

# PRINT NASTY
def print_ascii_art():
    art = """
             ▄████▄   ██▀███   ▄▄▄       ▄████▄   ██ ▄█▀
            ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ 
            ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ 
            ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ 
            ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄
            ░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒
              ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░
               ░          ░░   ░   ░   ▒   ░        ░ ░░ ░ 
               ░ ░         ░           ░  ░░ ░      ░  ░   
               ░                           ░               
                 "CRACK" - A WPA Pentesting Project
                ----------------------------------------
                 A project focused on improving WIFI WP
                         License: MIT License
                            Version: 1.2.0
                           Dev: Tim "TANK" Burns
    """
    print(art)

def run_command(command):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(e)
        sys.exit(1)

def main():
    print_ascii_art()

    # ROOT - check only 
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run it as root.")
        sys.exit(1)

    # ASK - for ssid to test 
    ssid = input("Enter the SSID of the network you have permission to test: ").strip()

    # CHECK - Check for root *only*
    permission = input("You must have explicit permission to test the network security of this SSID. Proceed? (y/n): ").strip().lower()
    if permission != "y":
        print("Permission denied. Exiting.")
        sys.exit(1)

    # TOOLS
    required_tools = ["airmon-ng", "airodump-ng"]
    for tool in required_tools:
        if not run_command(f"command -v {tool}"):
            print(f"Error: {tool} is not installed. Please install Aircrack-ng and try again.")
            sys.exit(1)

    # IDENTIFY 
    print("Available Wi-Fi interfaces:")
    interfaces = run_command("iw dev | grep Interface | awk '{print $2}'")
    if not interfaces:
        print("No Wi-Fi interfaces found. Exiting.")
        sys.exit(1)
    
    print(interfaces)
    interface = input("Enter the Wi-Fi interface to use: ").strip()

    # START
    print(f"Starting monitor mode on {interface}...")
    run_command(f"airmon-ng start {interface}")
    monitor_interface = f"{interface}mon"

    # SCAN
    print("Scanning for networks. Press CTRL+C when you find the target.")
    time.sleep(2)
    try:
        subprocess.run(f"airodump-ng {monitor_interface}", shell=True, check=True)
    except KeyboardInterrupt:
        print("\nScanning stopped by user.")

    # AUTOMATE
    target_ssid = input("Enter the SSID of the target network: ").strip()
    scan_output = run_command(f"airodump-ng {monitor_interface} | grep '{target_ssid}'")
    
    if not scan_output:
        print("Unable to find the network. Exiting.")
        run_command(f"airmon-ng stop {monitor_interface}")
        sys.exit(1)

    scan_lines = scan_output.split("\n")
    if not scan_lines:
        print("Error: No matching network found.")
        sys.exit(1)

    try:
        # EXTRACT
        bssid = scan_lines[0].split()[0]
        channel = scan_lines[0].split()[5]
    except IndexError:
        print("Error parsing network details. Exiting.")
        sys.exit(1)

    print(f"Target BSSID: {bssid}, Channel: {channel}")

    # CAPTURE
    print(f"Capturing handshakes for BSSID: {bssid} on Channel: {channel}...")
    run_command(f"airodump-ng --bssid {bssid} -c {channel} --write capture {monitor_interface}")

    # HOLD - Monitor mode 
    print("Stopping monitor mode...")
    run_command(f"airmon-ng stop {monitor_interface}")

    print("Operation completed. Check 'capture-01.cap' for captured handshakes.")

    # PRINT - Discovery and only
    file_path = input("Enter the path of the file to print: ").strip()
    try:
        with open(file_path, 'r') as file:
            print(file.read())
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")

if __name__ == "__main__":
    main()