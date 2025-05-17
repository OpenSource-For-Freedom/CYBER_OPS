#!/usr/bin/env python3

# sudo python3 kill_verify.py

# runs the bckgrnd as a service. 

#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil

INSTALL_PATH = "/usr/local/bin/kill_verify.py"
SERVICE_PATH = "/etc/systemd/system/kill_verify.service"
QUARANTINE_DIR = "/var/quarantine_kv"

def install_dependencies():
    print("[*] Installing dependencies...")
    def apt_install(pkg):
        subprocess.run(['apt', 'install', '-y', pkg], check=True)

    subprocess.run([sys.executable, '-m', 'pip', 'install', 'scapy', 'psutil', 'python-daemon'])

    if shutil.which("iwconfig") is None:
        apt_install("wireless-tools")
    if shutil.which("ip") is None:
        apt_install("iproute2")
    try:
        import tkinter
    except ImportError:
        apt_install("python3-tk")

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    print("[+] Dependencies installed and quarantine directory ready.")

def write_kill_verify_script():
    with open(INSTALL_PATH, "w") as f:
        f.write(KILL_VERIFY_SCRIPT)
    os.chmod(INSTALL_PATH, 0o755)
    print(f"[+] kill_verify.py installed at {INSTALL_PATH}")

def write_systemd_service(interface="wlan0"):
    service = f"""[Unit]
Description=Kill Verify - Reverse Shell & Network Scan Defense
After=network.target

[Service]
ExecStart=/usr/bin/python3 {INSTALL_PATH} --interface {interface}
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE_PATH, "w") as f:
        f.write(service)
    print(f"[+] systemd service written to {SERVICE_PATH}")

def enable_and_start_service():
    subprocess.run(["systemctl", "daemon-reexec"])
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "kill_verify.service"])
    subprocess.run(["systemctl", "start", "kill_verify.service"])
    print("[✓] kill_verify service enabled and running.")

KILL_VERIFY_SCRIPT = f'''#!/usr/bin/env python3
import os
import sys
import subprocess
import psutil
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, ARP, ICMP, IP, conf
import daemon
import shutil
import signal

SCRIPT_NAME = os.path.realpath(__file__)
QUARANTINE_DIR = "{QUARANTINE_DIR}"

def print_banner():
    banner = r"""
 ___  __    ___  ___       ___               ___      ___ _______   ________  ___  ________ ___    ___ 
|\  \|\  \ |\  \|\  \     |\  \             |\  \    /  /|\  ___ \ |\   __  \|\  \|\  _____\\  \  /  /|
\ \  \/  /|\ \  \ \  \    \ \  \            \ \  \  /  / | \   __/|\ \  \|\  \ \  \ \  \__/\ \  \/  / /
 \ \   ___  \ \  \ \  \    \ \  \            \ \  \/  / / \ \  \_|/_\ \   _  _\ \  \ \   __\\ \    / / 
  \ \  \\ \  \ \  \ \  \____\ \  \____        \ \    / /   \ \  \_|\ \ \  \\  \\ \  \ \  \_| \/  /  /  
   \ \__\\ \__\ \__\ \_______\ \_______\       \ \__/ /     \ \_______\ \__\\ _\\ \__\ \__\__/  / /    
    \|__| \|__|\|__|\|_______|\|_______|        \|__|/       \|_______|\|__|\|__|\|__|\|__|\___/ /     
                                                                                          \|___|/      
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
            raise Exception("No GUI")
    except:
        print(f"[ALERT] {{message}}")

def kill_other_instances():
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            if proc.pid == current_pid:
                continue
            if proc.info['cmdline'] and any(os.path.realpath(arg) == SCRIPT_NAME for arg in proc.info['cmdline']):
                proc.terminate()
                show_alert(f"Other kill_verify.py (PID {{proc.pid}}) terminated.")
        except:
            pass

def quarantine_shells():
    home_dirs = ["/tmp", "/home", "/var/tmp", "/root"]
    suspicious = []
    for dir in home_dirs:
        try:
            for root, dirs, files in os.walk(dir):
                for name in files:
                    if name in ["reverse_shell.sh", "rev.sh", "rshell.py"]:
                        full = os.path.join(root, name)
                        new_name = os.path.join(QUARANTINE_DIR, f"quarantine_{{os.path.basename(full)}}")
                        shutil.move(full, new_name)
                        suspicious.append(full)
        except:
            continue
    if suspicious:
        show_alert(f"Quarantined: {{', '.join(suspicious)}}")

def packet_handler(packet):
    if packet.haslayer(ARP):
        show_alert("ARP Packet Detected – Possible MITM")
    elif packet.haslayer(ICMP):
        show_alert("ICMP Echo Request – Ping Sweep?")
    elif packet.haslayer(IP) and packet.sprintf("%IP.proto%") in ["TCP", "UDP"]:
        show_alert("TCP/UDP Activity – Possible Reverse Shell or Scan")

    kill_other_instances()
    quarantine_shells()

def check_root():
    if os.geteuid() != 0:
        show_alert("Run as root.")
        sys.exit(1)

def set_monitor_mode(interface):
    subprocess.run(["ip", "link", "set", interface, "down"], check=True)
    subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
    subprocess.run(["ip", "link", "set", interface, "up"], check=True)

def get_available_interface():
    return next((iface for iface in conf.ifaces.data.keys() if not str(iface).startswith(("lo", "docker"))), None)

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_handler, store=0)

def handle_signal(signum, frame):
    print(f"[!] Signal {{signum}} caught. Exiting.")
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
            show_alert("No usable interface.")

def parse_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Interface to monitor")
    parser.add_argument("--no-daemon", action="store_true")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.no_daemon:
        print_banner()
        check_root()
        iface = args.interface or get_available_interface()
        if iface:
            set_monitor_mode(iface)
            start_sniffing(iface)
        else:
            show_alert("No interface.")
    else:
        run_daemon(args.interface)
'''

def main():
    print("[*] Initializing Kill Verify install and defense engine...")
    install_dependencies()
    write_kill_verify_script()
    write_systemd_service()
    enable_and_start_service()
    print("[✓] Setup complete. Kill Verify daemon is now active.")

if __name__ == "__main__":
    main()