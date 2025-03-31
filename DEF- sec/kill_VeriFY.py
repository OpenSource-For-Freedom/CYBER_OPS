import os
import psutil
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, ARP, ICMP, IP, conf
import subprocess
import daemon
import signal

def show_alert(message):
    root = tk.Tk()
    root.withdraw()  
    messagebox.showwarning("Alert", message)
    root.destroy()

def kill_process(process_name):
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if process_name in proc.info['name']:
                proc.terminate()
                show_alert(f"Process {process_name} has been terminated.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def packet_handler(packet):
    if packet.haslayer(ARP) or packet.haslayer(ICMP) or packet.haslayer(IP):
        if packet.haslayer(ICMP):
            show_alert("ICMP Echo Request Detected (Ping)")
        elif packet.haslayer(ARP):
            show_alert("ARP Packet Detected (Potential Sniffing)")
        elif packet.sprintf("%IP.proto%") in ["TCP", "UDP"]:
            show_alert("Network Scan Detected (Nmap or similar tool)")
# kill ;)
        kill_process("kill_VeriFY.py")


def check_root():
    if os.geteuid() != 0:
        show_alert("This script must be run as root!")
        exit(1)

# set the interface 
def set_monitor_mode(interface):
    try:
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        print(f"Interface {interface} is set to monitor mode")
    except subprocess.CalledProcessError as e:
        show_alert(f"Failed to set interface {interface} to monitor mode: {e}")
        exit(1)


def get_available_interface():
    interfaces = conf.ifaces.data.keys()
    return next(iter(interfaces), None)


def start_sniffing(interface):
    sniff(iface=interface, prn=packet_handler, store=0)

# daemon runtime
def run_as_daemon():
    with daemon.DaemonContext():
        check_root()
        interface = get_available_interface()
        if interface:
            set_monitor_mode(interface)
            start_sniffing(interface)
        else:
            show_alert("No available network interface found!")

if __name__ == "__main__":
    run_as_daemon()