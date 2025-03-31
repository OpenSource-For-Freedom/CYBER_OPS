#!/bin/bash

u
banner=(
"██████╗██████╗  █████╗  ██████╗██╗  ██╗"
"██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝"
"██║     ██████╔╝███████║██║     █████╔╝ "
"██║     ██╔══██╗██╔══██║██║     ██╔═██╗ "
"╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗"
" ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝"
)


term_width=$(tput cols)


for line in "${banner[@]}"; do
  line_length=${#line}
  padding=$(( (term_width - line_length) / 2 ))
  printf "%*s%s\n" "$padding" "" "$line"
done

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root."
  exit 1
fi


read -p "Enter the SSID of the network you have permission to test: " SSID


echo "You must have explicit permission to test the network security of this SSID. Proceed? (y/n)"
read permission

if [ "$permission" != "y" ]; then
  echo "Permission denied. Exiting."
  exit 1
fi


echo "Checking for required tools..."
sudo apt update -y
sudo apt install -y aircrack-ng iw
if ! command -v airmon-ng &> /dev/null; then
  echo "airmon-ng could not be found. Please install Aircrack-ng and run again."
  exit 1
fi

if ! command -v airodump-ng &> /dev/null; then
  echo "airodump-ng could not be found. Please install Aircrack-ng and run this script again."
  exit 1
fi


echo "Available Wi-Fi interfaces:"
iw dev | grep Interface | awk '{print $2}'
read -p "Enter the Wi-Fi interface to use: " INTERFACE


echo "Starting monitor mode on $INTERFACE..."
airmon-ng start $INTERFACE
MONITOR_INTERFACE="${INTERFACE}mon"


cleanup() {
  echo "Stopping monitor mode..."
  airmon-ng stop $MONITOR_INTERFACE
}
trap cleanup EXIT


echo "Scanning for networks. Press CTRL+C when you find the target."
airodump-ng --write scan_results --output-format csv $MONITOR_INTERFACE


read -p "Enter the SSID of the target network: " TARGET_SSID
BSSID=$(grep "$TARGET_SSID" scan_results-01.csv | awk -F',' '{print $1}')
CHANNEL=$(grep "$TARGET_SSID" scan_results-01.csv | awk -F',' '{print $4}')

if [ -z "$BSSID" ] || [ -z "$CHANNEL" ]; then
  echo "Unable to find the network. Exiting."
  exit 1
fi

echo "Capturing handshakes for BSSID: $BSSID on Channel: $CHANNEL."
airodump-ng --bssid $BSSID -c $CHANNEL --write capture $MONITOR_INTERFACE

echo "Operation completed. Check 'capture-01.cap' for captured handshakes."
