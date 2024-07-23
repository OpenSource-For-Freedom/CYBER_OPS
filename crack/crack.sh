#!/bin/bash

# Ask for the SSID
read -p "Enter the SSID of the network you have permission to test: " SSID

# check permissions
echo "You must have explicit permission to test the network security of this SSID. Proceed? (y/n)"
read permission

if [ "$permission" != "y" ]; then
  echo "Permission denied. Exiting."
  exit 1
fi

# Check for tools
# if no tools, need to load tools
if ! command -v airmon-ng &> /dev/null; then
    echo "airmon-ng could not be found. Please install Aircrack-ng and run again."
    exit
fi

if ! command -v airodump-ng &> /dev/null; then
    echo "airodump-ng could not be found. Please install Aircrack-ng and run this script again."
    exit
fi

# identify the interface but add ind interface if different.
INTERFACE="wlan0"

# add interface selection script 
# thought... tinkenter could be a good app to use to show the logs?

# Start monitor mode 
echo "Starting monitor mode on $INTERFACE..."
airmon-ng start $INTERFACE

MONITOR_INTERFACE="${INTERFACE}mon"

# ask for bssid
read -p "Enter the BSSID of the network: " BSSID
read -p "Enter the channel of the network: " CHANNEL

# automate this with grep/awk based on the SSID input.
# dont forget to identify ssid


# need sleep function if they want to toss multple attacks... another thought

read -p "Enter the BSSID of the network: " BSSID
read -p "Enter the channel of the network: " CHANNEL

# This will create files with the prefix "capture"
echo "Capturing handshakes. Press CTRL+C to stop."
airodump-ng --bssid $BSSID -c $CHANNEL --write capture $MONITOR_INTERFACE

# Stop monitor mode
echo "Stopping monitor mode..."
airmon-ng stop $MONITOR_INTERFACE

echo "Operation completed. Check 'capture-01.cap' for captured handshakes."
