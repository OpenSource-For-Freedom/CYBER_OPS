import os
import nmap
import csv
import time
import dpkt
from pythonping import ping
import sys

# Constants
TARGET_IP = "192.168.1.254"
OUTPUT_DIRECTORY = os.path.expanduser("~/Desktop/nmap_scans")
NMAP_PATH = "/usr/bin/nmap"

# Function to check if the script is run as root/admin
def check_admin():
    if os.geteuid() != 0:
        print("This script must be run as root or with admin privileges.")
        sys.exit(1)

# Function to ping the target IP address
def ping_target(ip_address):
    try:
        response = ping(ip_address, count=4)  # Send 4 ping packets
        if response.success():
            return True
        else:
            raise Exception(f"Target IP {ip_address} is not reachable.")
    except Exception as e:
        print(f"Error: {e}")
        return False

# Function to ask the user for confirmation to proceed
def ask_user_confirmation():
    while True:
        try:
            user_input = int(input("Target acquired. Do you want to proceed? (1 = Yes, 2 = No): "))
            if user_input == 1:
                return True
            elif user_input == 2:
                return False
            else:
                print("Invalid input. Please enter 1 to proceed or 2 to abort.")
        except ValueError:
            print("Invalid input. Please enter 1 to proceed or 2 to abort.")

# Function to run an Nmap scan
def run_nmap_scan(output_filename, scan_args):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=TARGET_IP, arguments=scan_args)
        full_output_path = os.path.join(OUTPUT_DIRECTORY, output_filename)
        with open(full_output_path, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Host", "Port/Protocol", "State", "Service"])
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        service = nm[host][proto][port]['name']
                        state = nm[host][proto][port]['state']
                        row = [host, f"{port}/{proto}", state, service]
                        csv_writer.writerow(row)
        print(f"Nmap scan results saved to {output_filename}.")
    except Exception as e:
        print(f"An error occurred during the Nmap scan: {e}")

# Function to analyze network packets from a pcap file
def analyze_packets(pcap_file):
    packets_data = []
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}"
                    dst_ip = f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}"
                    packets_data.append([src_ip, dst_ip])
        print("Packet analysis completed.")
    except Exception as e:
        print(f"An error occurred during packet analysis: {e}")
    return packets_data

# Function to save analysis results to a CSV file
def save_analysis_to_csv(data, filename):
    try:
        full_output_path = os.path.join(OUTPUT_DIRECTORY, filename)
        with open(full_output_path, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Source IP", "Destination IP"])  # Writing header
            for row in data:
                csv_writer.writerow(row)
        print(f"Analysis results saved to {filename}.")
    except Exception as e:
        print(f"An error occurred while saving analysis results to {filename}: {e}")

# Function to run weekly scans
def run_weekly_scan():
    if not os.path.exists(OUTPUT_DIRECTORY):
        os.makedirs(OUTPUT_DIRECTORY)
    
    if not ping_target(TARGET_IP):
        print(f"Terminating script because target IP {TARGET_IP} is not reachable.")
    else:
        # Run Nmap scan
        run_nmap_scan("nmap_scan_results.csv", "-sS -Pn -T4")
        time.sleep(5)

        # Capture and analyze network packets (example pcap file: 'capture.pcap')
        packet_analysis_data = analyze_packets("capture.pcap")
        save_analysis_to_csv(packet_analysis_data, 'packet_analysis.csv')

        print("Scans completed. Results saved to the 'nmap_scans' directory on the desktop.")

# Entry point of the script
if __name__ == "__main__":
    check_admin()
    if ask_user_confirmation():
        run_weekly_scan()
    else:
        print("Script aborted by the user.")