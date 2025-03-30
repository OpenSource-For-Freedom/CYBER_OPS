from scapy.all import *
import argparse
import tkinter as tk
from tkinter import messagebox


# install must have python3 and venv already running 
pip install scapy

# handle packets
def packet_handler(packet):
    if packet.haslayer(Dot11Deauth):
        print(f"Deauthentication frame detected: {packet.summary()}")
        # Show GUI alert
        show_alert(packet.summary())

# show GUI alert
def show_alert(message):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    messagebox.showwarning("Deauthentication Attack Detected", message)
    root.destroy()

if __name__ == "__main__":
    # Parsing
    parser = argparse.ArgumentParser(description="Simple WIDS to detect deauthentication attacks")
    parser.add_argument("interface", help="The network interface to monitor")
    args = parser.parse_args()

    # Start sniffing
    print(f"Monitoring on interface {args.interface}")
    sniff(iface=args.interface, prn=packet_handler, store=0)