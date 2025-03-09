# Network Security Testing Script

This Bash script is designed to assist in testing the security of wireless networks. It is crucial that this tool is used ethically and legally, with explicit permission from the network owner.

Prerequisites

## Before running this script, ensure you have installed:

	•	Aircrack-ng: This tool is essential for the network testing functions used in the script.

# Getting Started

To use this script, clone this repository or copy the script to your local machine. Make sure the script has executable permissions:

> chmod +x network_test.sh

# Usage

## Run the script from terminal:

> ./network_test.sh

## Follow the interactive prompts to enter the necessary information such as the SSID, BSSID, and channel of the network you are testing.

## Steps Executed by the Script

	1.	Prompt for Network SSID: You will be asked to enter the SSID of the network to test.
	2.	Verify Permission: Confirms that you have permission to test the network, exiting if permission is not granted.
	3.	Check for Necessary Tools: Ensures that airmon-ng and airodump-ng are installed.
	4.	Setup Network Interface: Sets wlan0 as the default interface, with an option to select a different one.
	5.	Start Monitor Mode: Enables monitor mode on the network interface.
	6.	Capture Handshakes: Prompts for BSSID and channel, then uses airodump-ng to capture handshakes, saving them to a file.
	7.	Stop Monitor Mode: Disables monitor mode and concludes the operation.

## Important Notes

	•	Always ensure you have explicit permission to test the network.
	•	The script defaults to using wlan0 as the network interface. If your interface name is different, you will need to modify the script accordingly.

## Contributing
Contact directly or Fork 