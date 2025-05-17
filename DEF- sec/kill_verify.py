#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil
import signal
import argparse

def install_dependencies():
    print("[*] Checking and installing dependencies...")

    def apt_install(pkg):
        try:
            subprocess.run(['apt', 'install', '-y', pkg], check=True)
        except subprocess.CalledProcessError:
            print(f"[!] Failed to install {pkg}")
            sys.exit(1)

    # Python packages
    try:
        import scapy.all
    except ImportError:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'scapy'], check=True)

    try:
        import psutil
    except ImportError:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'psutil'], check=True)

    try:
        import daemon
    except ImportError:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'python-daemon'], check=True)

    # System binaries
    if shutil.which("iwconfig") is None:
        apt_install("wireless-tools")

    if shutil.which("ip") is None:
        apt_install("iproute2")

    # GUI
    try:
        import tkinter
    except ImportError:
        apt_install("python3-tk")

    print("[+] All dependencies are installed.")

# Post-dependency imports
import psutil
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, ARP, ICMP, IP, conf
import daemon

SCRIPT_NAME = os.path.realpath(__file__)

def print_banner():
    banner = r"""

 __  ___  __   __       __         ____    ____  _______ .______       __   ___________    ____ 
|  |/  / |  | |  |     |  |        \   \  /   / |   ____||   _  \     |  | |   ____\   \  /   / 
|  '  /  |  | |  |     |  |         \   \/   /  |  |__   |  |_)  |    |  | |  |__   \   \/   /  
|    <   |  | |  |     |  |          \      /   |   __|  |      /     |  | |   __|   \_    _/   
|  .  \  |  | |  `----.|  `----.      \    /    |  |____ |  |\  \----.|  | |  |        |  |     
|__|\__\ |__| |_______||_______|       \__/     |_______|| _| `._____||__| |__|        |__|     
                                                                                                
 
-----------------------------------------------------
       KILL VERIFY - REVERSE SHELL & SCAN DEFENSE
-----------------------------------------------------
"""
    print(banner)

def show_alert(message):
    try:
        if os.environ.get("DISPLAY"):
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning("Security Alert", message)
            root.destroy()
        else:
            raise RuntimeError("No GUI available")
    except:
        print(f"[ALERT] {message}")

def kill_other_instances():
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            if proc.pid == current_pid:
                continue
            cmdline = proc.info['cmdline']
            if cmdline and any(os.path.realpath(arg) == SCRIPT_NAME for arg in cmdline):
                proc.terminate()
                show_alert(f"Other instance of kill_verify.py (PID {proc.pid}) terminated.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def packet_handler(packet):
    if packet.haslayer(ARP):
        show_alert("ARP Packet Detected – Potential MITM")
    elif packet.haslayer(ICMP):
        show_alert("ICMP Echo Request Detected – Possible Ping Sweep")
    elif packet.haslayer(IP) and packet.sprintf("%IP.proto%") in ["TCP", "UDP"]:
        show_alert("Network Scan Detected – Suspicious Packet Activity")

    kill_other_instances()

def check_root():
    if os.geteuid() != 0:
        show_alert("This script must be run as root.")
        sys.exit(1)

def set_monitor_mode(interface):
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        print(f"[+] Interface {interface} is now in monitor mode.")
    except subprocess.CalledProcessError as e:
        show_alert(f"Failed to set monitor mode on {interface}: {e}")
        sys.exit(1)

def get_available_interface():
    candidates = [iface for iface in conf.ifaces.data.keys() if not str(iface).startswith(("lo", "docker"))]
    return next(iter(candidates), None)

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_handler, store=0)

def handle_signal(signum, frame):
    print(f"[!] Caught signal {signum}. Exiting cleanly.")
    sys.exit(0)

def run_daemon(interface=None):
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    with daemon.DaemonContext():
        check_root()
        iface = interface or get_available_interface()
        if iface:
            set_monitor_mode(iface)
            start_sniffing(iface)
        else:
            show_alert("No usable network interface found.")

def parse_args():
    parser = argparse.ArgumentParser(description="Reverse Shell / Scan Detection Daemon")
    parser.add_argument("-i", "--interface", help="Network interface to monitor (e.g. wlan0)")
    parser.add_argument("--no-daemon", action="store_true", help="Run in foreground with banner and debug output")
    return parser.parse_args()

if __name__ == "__main__":
    install_dependencies()
    args = parse_args()

    if args.no_daemon:
        print_banner()
        check_root()
        iface = args.interface or get_available_interface()
        if iface:
            set_monitor_mode(iface)
            start_sniffing(iface)
        else:
            show_alert("No usable network interface found.")
    else:
        run_daemon(interface=args.interface)