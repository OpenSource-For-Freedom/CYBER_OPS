#!/usr/bin/env python3

# to run: sudo python3 kill_crack.py wlan0


import os
import time
import argparse
import threading
import subprocess
import sys



#### 



def install_dependencies():
    try:
        import scapy.all
        import tkinter
    except ImportError:
        print("[+] Installing required dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
        print("[+] Dependencies installed. Please re-run the script.")
        sys.exit(0)

install_dependencies()
from scapy.all import *
import tkinter as tk
from tkinter import messagebox





last_alert_time = 0
cooldown_seconds = 10
log_file = "deauth_log.txt"







if os.geteuid() != 0:
    print("[-] This script must be run as root.")
    sys.exit(1)






def is_monitor_mode(interface):
    try:
        result = subprocess.check_output(f"iwconfig {interface}", shell=True).decode()
        return "Mode:Monitor" in result
    except subprocess.CalledProcessError:
        return False







def show_alert(message):
    def alert():
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning("Deauthentication Attack Detected", message)
        root.destroy()
    threading.Thread(target=alert).start()







def packet_handler(packet):
    global last_alert_time
    if packet.haslayer(Dot11Deauth):
        now = time.time()
        if now - last_alert_time >= cooldown_seconds:
            last_alert_time = now
            msg = f"{time.ctime()}: Deauth frame: {packet.summary()}"
            print(msg)
            with open(log_file, "a") as f:
                f.write(msg + "\n")
            show_alert(packet.summary())

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple WIDS to detect deauthentication attacks")
    parser.add_argument("interface", help="The wireless interface to monitor (must be in monitor mode)")
    args = parser.parse_args()

    if not is_monitor_mode(args.interface):
        print(f"[-] Interface {args.interface} is not in monitor mode.")
        print("[*] Example command: sudo ip link set wlan0 down && sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up")
        sys.exit(1)

    try:
        print(f"[+] Monitoring on interface {args.interface}")
        sniff(iface=args.interface, prn=packet_handler, store=0)
    except Exception as e:
        print(f"[-] Error: {e}")
        print("Ensure you have the necessary permissions and the interface exists.")