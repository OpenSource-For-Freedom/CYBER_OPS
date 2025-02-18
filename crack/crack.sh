#!/bin/bash

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
                "CRACK" - The Linux Security Project
                ----------------------------------------
                 A project focused on improving Linux
                security by automating, containerizing
                            Hardening and
                     System protection measures.
                         License: MIT License
                            Version: 1.2.0
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)
# Ask for the SSID
read -p "Enter the SSID of the network you have permission to test: " SSID

# Check permissions
echo "You must have explicit permission to test the network security of this SSID. Proceed? (y/n)"
read permission

if [ "$permission" != "y" ]; then
  echo "Permission denied. Exiting."
  exit 1
fi

# Check for tools
if ! command -v airmon-ng &> /dev/null; then
    echo "airmon-ng could not be found. Please install Aircrack-ng and run again."
    exit
fi

if ! command -v airodump-ng &> /dev/null; then
    echo "airodump-ng could not be found. Please install Aircrack-ng and run this script again."
    exit
fi

# Identify available interfaces
echo "Available Wi-Fi interfaces:"
iw dev | grep Interface | awk '{print $2}'
read -p "Enter the Wi-Fi interface to use: " INTERFACE

# Start monitor mode
echo "Starting monitor mode on $INTERFACE..."
airmon-ng start $INTERFACE
MONITOR_INTERFACE="${INTERFACE}mon"

# Scan for networks
echo "Scanning for networks. Press CTRL+C when you find the target."
airodump-ng $MONITOR_INTERFACE

# Automate BSSID and channel discovery
read -p "Enter the SSID of the target network: " TARGET_SSID
BSSID=$(airodump-ng $MONITOR_INTERFACE | grep "$TARGET_SSID" | awk '{print $1}')
CHANNEL=$(airodump-ng $MONITOR_INTERFACE | grep "$TARGET_SSID" | awk '{print $6}')

if [ -z "$BSSID" ] || [ -z "$CHANNEL" ]; then
  echo "Unable to find the network. Exiting."
  airmon-ng stop $MONITOR_INTERFACE
  exit 1
fi

# Capture handshakes
echo "Capturing handshakes for BSSID: $BSSID on Channel: $CHANNEL."
airodump-ng --bssid $BSSID -c $CHANNEL --write capture $MONITOR_INTERFACE

# Stop monitor mode
echo "Stopping monitor mode..."
airmon-ng stop $MONITOR_INTERFACE

echo "Operation completed. Check 'capture-01.cap' for captured handshakes."
