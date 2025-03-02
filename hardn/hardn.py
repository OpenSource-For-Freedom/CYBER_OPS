import os
import subprocess
import sys
import shlex
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox  
from datetime import datetime

# Tie in wazuh SIEM
# Tie in VM support and containerization 
# Tie in API response and SSH again
# ROOT 
# Added VM compatibility 
def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

# NASTY
def print_ascii_art():
    art = """
             ██░ ██  ▄▄▄       ██▀███  ▓█████▄  ███▄    █ 
            ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌ ██ ▀█   █ 
            ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌▓██  ▀█ ██▒
            ░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌▓██▒  ▐▌██▒
            ░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▓ ▒██░   ▓██░
             ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░ ▒░   ▒ ▒ 
             ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒ ░ ░░   ░ ▒░
             ░  ░░ ░  ░   ▒     ░░   ░  ░ ░  ░    ░   ░ ░ 
             ░  ░  ░      ░  ░   ░        ░             ░ 
                                ░                 
                "HARDN" - The Linux Security Project
                ----------------------------------------
                 A project focused on improving Linux
                security by automating, containerizing
                            Hardening and
                     System protection measures.
                         License: MIT License
                            Version: 1.5.6
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)

# GET DIR
script_dir = os.path.dirname(os.path.abspath(__file__))

# FILE PATH - to dependents 
HARDN_QUBE_PATH = os.path.join(script_dir, "HARDN_qubes.py")
HARDN_DARK_PATH = os.path.join(script_dir, "HARDN_dark.py")

print("HARDN_QUBE_PATH:", HARDN_QUBE_PATH)
print("HARDN_DARK_PATH:", HARDN_DARK_PATH)

# SECURITY HARDENING FUNCTIONS
def configure_apparmor():
    status_gui.update_status("Configuring AppArmor for Mandatory Access Control...")
    exec_command("apt install -y apparmor apparmor-profiles apparmor-utils")
    exec_command("systemctl enable --now apparmor")

def configure_firejail():
    status_gui.update_status("Configuring Firejail for Application Sandboxing...")
    exec_command("apt install -y firejail")
    exec_command("firejail --list")

# SECURITY TOOLS
def remove_clamav():
    status_gui.update_status("Removing ClamAV...")
    exec_command("apt remove --purge -y clamav clamav-daemon")
    exec_command("rm -rf /var/lib/clamav")

def install_eset_nod32():
    status_gui.update_status("Installing ESET NOD32 (ES32) Antivirus...")
    exec_command("wget -q https://download.eset.com/com/eset/apps/home/av/linux/latest/eset_nod32av_64bit.deb -O /tmp/eset.deb")
    exec_command("dpkg -i /tmp/eset.deb || apt --fix-broken install -y")
    exec_command("rm -f /tmp/eset.deb")

def setup_auto_updates():
    status_gui.update_status("Configuring Auto-Update for Security Packages...")
    cron_jobs = [
        "0 3 * * * /opt/eset/esets/sbin/esets_update",
        "0 2 * * * apt update && apt upgrade -y",
        "0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1"
    ]
    for job in cron_jobs:
        exec_command(f"(crontab -l 2>/dev/null; echo '{job}') | crontab -")

def configure_tcp_wrappers(): # thank you Kiukcat :)
    status_gui.update_status("Configuring TCP Wrappers...")
    exec_command("apt install -y tcpd")

def configure_fail2ban():
    status_gui.update_status("Setting up Fail2Ban...")
    exec_command("apt install -y fail2ban")
    exec_command("systemctl restart fail2ban")
    exec_command("systemctl enable --now fail2ban")

import shutil
import subprocess
# Added VM compatibility in case it's running boot loader or EFI- thanks Alex :)
def configure_grub():
    status_gui.update_status("Configuring GRUB Security Settings...")
    
    # Check if GRUB is available
    grub_cmd = shutil.which("update-grub") or shutil.which("grub-mkconfig")

    if grub_cmd:
        subprocess.run([grub_cmd, "-o", "/boot/grub/grub.cfg"], check=True)
    else:
        print("Warning: GRUB update command not found. Skipping GRUB update.")
        print("If running inside a VM, this may not be necessary.")

def configure_firewall():
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw allow out 80,443/tcp")
    exec_command("ufw --force enable && ufw reload")

def disable_usb(): # We can set this to just put in monitor mode*
    status_gui.update_status("Locking down USB devices...")
    exec_command("echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf")
    exec_command("modprobe -r usb-storage || echo 'USB storage module in use, cannot unload.'")
# if usb is in use it won't allow any changes 
def software_integrity_check():
    status_gui.update_status("Software Integrity Check...")
    exec_command("debsums -s")

def run_audits():
    status_gui.update_status("Running Security Audits...")
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")

def scan_with_eset():
    status_gui.update_status("Scanning system with ESET NOD32 (ES32) Antivirus...")
    exec_command("/opt/eset/esets/sbin/esets_scan /home")

# START HARDENING PROCESS
def start_hardening():
    threading.Thread(target=lambda: [
        remove_clamav(), # Remove ClamAV
        install_eset_nod32(), # Install ES32
        setup_auto_updates(), # Enable auto-updates for security packages
        configure_tcp_wrappers(), # Put in TCP Wrappers
        configure_fail2ban(), # Build Fail2Ban
        configure_grub(), # Pump the GRUB
        configure_firewall(), # Set UFW
        configure_apparmor(), # Add AppArmor 
        configure_firejail(), # Add Firejail 
        disable_usb(), # Stop all USB
        software_integrity_check(), # Check software
        run_audits(), # Lynis audits
        scan_with_eset(), # Run ES32 malware scan
        status_gui.complete() # GUI finish 
    ], daemon=True).start()

# MAIN
def main():
    global status_gui  # global
    print_ascii_art()
    status_gui = StatusGUI()  
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()