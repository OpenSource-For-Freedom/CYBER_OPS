import os
import nmap
import csv
import time
import dpkt
from pythonping import ping
import tkinter as tk #added for gui
from tkinter import messagebox, filedialog
import sys

# statics 
TARGET_IP = "192.168.1.254"
OUTPUT_DIRECTORY = os.path.expanduser("~/Desktop/nmap_scans")
NMAP_PATH = "/usr/bin/nmap"

# check if the script is run as root
def check_admin():
    if os.geteuid() != 0:
        tk.messagebox.showerror("Error", "This script must be run as root or with admin privileges.")
        sys.exit(1)

# ping the target IP address
def ping_target(ip_address):
    try:
        response = ping(ip_address, count=4)  # Send 4 ping packets
        if response.success():
            return True
        else:
            raise Exception(f"Target IP {ip_address} is not reachable.")
    except Exception as e:
        messagebox.showerror("Ping Error", str(e))
        return False

# run an Nmap scan
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
        tk.messagebox.showinfo("Nmap Scan", f"Nmap scan results saved to {output_filename}.")
    except Exception as e:
        tk.messagebox.showerror("Nmap Scan Error", str(e))

# analyze network packets from pcap file
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
        tk.messagebox.showinfo("Packet Analysis", "Packet analysis completed.")
    except Exception as e:
        tk.messagebox.showerror("Packet Analysis Error", str(e))
    return packets_data

#  save analysis results to a CSV file (local Dir) 
def save_analysis_to_csv(data, filename):
    try:
        full_output_path = os.path.join(OUTPUT_DIRECTORY, filename)
        with open(full_output_path, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Source IP", "Destination IP"])  # Writing header
            for row in data:
                csv_writer.writerow(row)
        tk.messagebox.showinfo("Save Results", f"Analysis results saved to {filename}.")
    except Exception as e:
        tk.messagebox.showerror("Save Error", str(e))

# start the weekly scan process
def start_scan():
    if not os.path.exists(OUTPUT_DIRECTORY):
        os.makedirs(OUTPUT_DIRECTORY)

    if not ping_target(TARGET_IP):
        tk.messagebox.showerror("Ping Failed", f"Target IP {TARGET_IP} is not reachable.")
    else:
        # Run Nmap 
        run_nmap_scan("nmap_scan_results.csv", "-sS -Pn -T4")
        time.sleep(5)

        # Ask the user to select a .pcap file for analysis
        pcap_file = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP files", "*.pcap")])
        if pcap_file:
            packet_analysis_data = analyze_packets(pcap_file)
            save_analysis_to_csv(packet_analysis_data, 'packet_analysis.csv')
        else:
            tk.messagebox.showinfo("Packet Analysis", "No PCAP file selected. Skipping packet analysis.")

# Tkinter GUI
def create_gui():
    root = tk.Tk()
    root.title("Network Scan Tool")
    root.geometry("400x200")

    # Welcome Label
    tk.Label(root, text="Welcome to the Network Scan Tool", font=("Arial", 14)).pack(pady=10)

    # Scan Button
    tk.Button(root, text="Start Scan", command=start_scan, font=("Arial", 12), bg="blue", fg="white").pack(pady=20)

    # Exit Button
    tk.Button(root, text="Exit", command=root.quit, font=("Arial", 12), bg="red", fg="white").pack(pady=10)

    root.mainloop()

# Entry point
if __name__ == "__main__":
    check_admin()
    create_gui()