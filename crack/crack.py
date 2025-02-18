import subprocess
import time
import sys
import os

# PRINT BANNER
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
                 A project focused on improving WIFI WPA
                security by automating, containerizing
                            Hardening and
                     System protection measures.
                         License: MIT License
                            Version: 1.2.0
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
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

    # Ask for SSID
    ssid = input("Enter the SSID of the network you have permission to test: ").strip()

    # Check permissions
    permission = input("You must have explicit permission to test the network security of this SSID. Proceed? (y/n): ").strip().lower()
    if permission != "y":
        print("Permission denied. Exiting.")
        sys.exit(1)

    # Check for necessary tools
    required_tools = ["airmon-ng", "airodump-ng"]
    for tool in required_tools:
        if not run_command(f"command -v {tool}"):
            print(f"Error: {tool} is not installed. Please install Aircrack-ng and try again.")
            sys.exit(1)

    # Identify available interfaces
    print("Available Wi-Fi interfaces:")
    interfaces = run_command("iw dev | grep Interface | awk '{print $2}'")
    if not interfaces:
        print("No Wi-Fi interfaces found. Exiting.")
        sys.exit(1)
    
    print(interfaces)
    interface = input("Enter the Wi-Fi interface to use: ").strip()

    # Start monitor mode
    print(f"Starting monitor mode on {interface}...")
    run_command(f"airmon-ng start {interface}")
    monitor_interface = f"{interface}mon"

    # Scan for networks
    print("Scanning for networks. Press CTRL+C when you find the target.")
    time.sleep(2)
    try:
        subprocess.run(f"airodump-ng {monitor_interface}", shell=True, check=True)
    except KeyboardInterrupt:
        print("\nScanning stopped by user.")

    # Automate BSSID and channel discovery
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
        # Extract BSSID and Channel from the scan output
        bssid = scan_lines[0].split()[0]
        channel = scan_lines[0].split()[5]
    except IndexError:
        print("Error parsing network details. Exiting.")
        sys.exit(1)

    print(f"Target BSSID: {bssid}, Channel: {channel}")

    # Capture handshakes
    print(f"Capturing handshakes for BSSID: {bssid} on Channel: {channel}...")
    run_command(f"airodump-ng --bssid {bssid} -c {channel} --write capture {monitor_interface}")

    # Stop monitor mode
    print("Stopping monitor mode...")
    run_command(f"airmon-ng stop {monitor_interface}")

    print("Operation completed. Check 'capture-01.cap' for captured handshakes.")

if __name__ == "__main__":
    main()
