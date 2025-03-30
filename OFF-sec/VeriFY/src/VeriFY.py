import os
import nmap
import csv
import time
import dpkt
from pythonping import ping
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import sys
import re

# Display ASCII art in the GUI
def display_ascii_art():
    ascii_art = """
 ▄█    █▄     ▄████████    ▄████████  ▄█     ▄████████ ▄██   ▄   
███    ███   ███    ███   ███    ███ ███    ███    ███ ███   ██▄ 
███    ███   ███    █▀    ███    ███ ███▌   ███    █▀  ███▄▄▄███ 
███    ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ ███▌  ▄███▄▄▄     ▀▀▀▀▀▀███ 
███    ███ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   ███▌ ▀▀███▀▀▀     ▄██   ███ 
███    ███   ███    █▄  ▀███████████ ███    ███        ███   ███ 
███    ███   ███    ███   ███    ███ ███    ███        ███   ███ 
 ▀██████▀    ██████████   ███    ███ █▀     ███         ▀█████▀  
                          ███    ███        
"""
    art_window = tk.Toplevel()
    art_window.title("ASCII Art")
    art_label = tk.Label(art_window, text=ascii_art, font=("Courier", 10), justify="left")
    art_label.pack(padx=10, pady=10)
# Check Admin Privileges
def check_admin():
    if os.geteuid() != 0:
        tk.messagebox.showerror("Error", "Must run as Higher.")
        sys.exit(1)

        # build python venv
def build_venv():
    os.system('python3 -m venv venv')
    os.system('source venv/bin/activate')
    os.system('pip install -r requirements.txt')
    os.system('pip install pythonping')
    os.system('pip install python-nmap')
    os.system('pip install dpkt')        


# Validate 
def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None

# Ping Target
def ping_target(ip_address):
    try:
        response = ping(ip_address, count=4)
        if response.success():
            return True
        else:
            raise Exception(f"Target IP {ip_address} is not reachable.")
    except Exception as e:
        tk.messagebox.showerror("Ping Error", str(e))
        return False

# Run 
def run_nmap_scan(ip_address, output_dir, status_label=None):
    if status_label is None:
        status_label = tk.Label() 
    try:
        nm = nmap.PortScanner()
        status_label.config(text="Running Nmap scan...")
        nm.scan(hosts=ip_address, arguments=scan_args)
        status_label.config(text="Running Nmap scan...")
        nm.scan(hosts=ip_address, arguments=scan_args)
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_file = os.path.join(output_dir, f"nmap_scan_{timestamp}.csv")
        
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Host", "Port/Protocol", "State", "Service"])
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service = nm[host][proto][port]['name']
                        state = nm[host][proto][port]['state']
                        csv_writer.writerow([host, f"{port}/{proto}", state, service])
        
        status_label.config(text=f"Nmap scan completed. Results saved to {output_file}.")
        tk.messagebox.showinfo("Nmap Scan", f"Scan results saved to: {output_file}")
    except Exception as e:
        tk.messagebox.showerror("Nmap Scan Error", str(e))

# Analyze
def analyze_packets(pcap_file, output_dir, status_label):
    packets_data = []
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = ".".join(map(str, ip.src))
                    dst_ip = ".".join(map(str, ip.dst))
                    packets_data.append([src_ip, dst_ip])
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_file = os.path.join(output_dir, f"packet_analysis_{timestamp}.csv")
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Source IP", "Destination IP"])
            csv_writer.writerows(packets_data)
        
        status_label.config(text=f"Packet analysis completed. Results saved to {output_file}.")
        tk.messagebox.showinfo("Packet Analysis", f"Analysis results saved to: {output_file}")
    except Exception as e:
        tk.messagebox.showerror("Packet Analysis Error", str(e))

# Start 
def start_scan(target_ip, output_dir, status_label):
    if not target_ip or not is_valid_ip(target_ip):
        tk.messagebox.showerror("Input Error", "Please provide a valid target IP address.")
        return
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    status_label.config(text="Pinging target...")
    if not ping_target(target_ip):
        status_label.config(text=f"Target IP {target_ip} is not reachable.")
        return
    
    run_nmap_scan(target_ip, output_dir, status_label)
    
    pcap_file = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP files", "*.pcap")])
    if pcap_file:
        analyze_packets(pcap_file, output_dir, status_label)
    else:
        tk.messagebox.showinfo("Packet Analysis", "No PCAP file selected. Skipping packet analysis.")

# GUI Setup
def create_gui():
    root = tk.Tk()
    root.title("VeriFY Port Scanning Tool")
    root.geometry("500x300")

    # Input Frame
    input_frame = tk.Frame(root)
    input_frame.pack(pady=10)

    tk.Label(input_frame, text="Target IP:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=5)
    target_ip_entry = tk.Entry(input_frame, font=("Arial", 12), width=20)
    target_ip_entry.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(input_frame, text="Output Directory:", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=5)
    output_dir_entry = tk.Entry(input_frame, font=("Arial", 12), width=20)
    output_dir_entry.grid(row=1, column=1, padx=10, pady=5)
    output_dir_button = tk.Button(input_frame, text="Browse", font=("Arial", 10), command=lambda: output_dir_entry.insert(0, filedialog.askdirectory()))
    output_dir_button.grid(row=1, column=2, padx=5)

    # Status Label
    status_label = tk.Label(root, text="", font=("Arial", 10), fg="green")
    status_label.pack(pady=10)

    # Buttons
    tk.Button(root, text="Start Scan", font=("Arial", 12), bg="blue", fg="white",
              command=lambda: start_scan(target_ip_entry.get(), output_dir_entry.get(), status_label)).pack(pady=10)

    tk.Button(root, text="Exit", font=("Arial", 12), bg="red", fg="white", command=root.quit).pack(pady=10)

    root.mainloop()

# Entry Point
if __name__ == "__main__":
    check_admin()
    create_gui()
