from scapy.all import *
import argparse
import tkinter as tk
from tkinter import messagebox
import threading


def packet_handler(packet):
    if packet.haslayer(Dot11Deauth):
        
        print(f"Deauthentication frame detected: {packet.summary()}")
        show_alert(packet.summary())


def show_alert(message):
    def alert():
        root = tk.Tk()
        root.withdraw()  # Hide the root window
        messagebox.showwarning("Deauthentication Attack Detected", message)
        root.destroy()


    threading.Thread(target=alert).start()

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Simple WIDS to detect deauthentication attacks")
    parser.add_argument("interface", help="The network interface to monitor")
    args = parser.parse_args()

    try:

        print(f"Monitoring on interface {args.interface}")
        sniff(iface=args.interface, prn=packet_handler, store=0)
    except Exception as e:
        print(f"Error: {e}")
        print("Ensure you have the necessary permissions and the interface is valid.")