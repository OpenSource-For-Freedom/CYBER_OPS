import os
import subprocess
import shutil
import sys
import signal
import time
import logging
import threading
import tkinter as tk
from tkinter import ttk  
from datetime import datetime
from hard3n_tk import Hard3nGUI  

# ROOT ENSURE
def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

# PRINT BANNER
def print_ascii_art():
    art = """
    --------------------------------------------------------------------------
                H|   H|  AAAAA    RRRR    DDDD    333333    NN     N|
      ======== H|   H|  A    A   R   R   D   D       33    N N    N| ========
      ======= HHHHH    AAAAAA   RRRR    D   D     33      N|  N  N| =========
      ====== H|   H|  A    A   R  R    D   D       33    N|   N N| ==========
            H|   H|  A    A   R   R   DDDD    333333    N|    NN|
    --------------------------------------------------------------------------
                "HARD3N" - The Linux Security Project
                ----------------------------------------
                 A project focused on improving Linux
                security by automating, containerizing
                            Hardening and
                     System protection measures.
                         License: MIT License
                            Version: 1.4.0
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)

# LOGGING SETUP
LOG_DIR = os.path.expanduser("~/security_logs")
os.makedirs(LOG_DIR, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
SCRIPT_LOG = os.path.join(LOG_DIR, f"script_execution_{DATE}.log")

logging.basicConfig(
    filename=SCRIPT_LOG,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log(message):
    print(message)
    logging.info(message)

# STATUS GUI 
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARD3N - System Hardening Progress")
        self.root.geometry("500x300")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 14), wraplength=480)
        self.label.pack(pady=20)

        self.progress = ttk.Progressbar(self.root, length=400, mode="determinate")  
        self.progress.pack(pady=10)

        self.close_button = tk.Button(self.root, text="Close", command=self.root.quit, state=tk.DISABLED)
        self.close_button.pack(pady=10)

        self.total_steps = 12
        self.current_step = 0

    def update_status(self, message, progress=None):
        self.label.config(text=message)
        if progress is not None:
            self.progress["value"] = progress
        else:
            self.current_step += 1
            progress_percent = int((self.current_step / self.total_steps) * 100)
            self.progress["value"] = progress_percent
        self.root.update_idletasks()

    def complete(self):
        self.label.config(text="System Hardening Complete!")
        self.progress["value"] = 100
        self.close_button.config(state=tk.NORMAL)
        self.root.update_idletasks()

    def run(self):
        self.root.mainloop()

status_gui = StatusGUI()

# SYSTEM HARDENING FUNCTIONS

def ensure_security_tools():
    tools = ["ufw", "fail2ban", "clamav", "apparmor", "apparmor-utils", "bubblewrap"]
    for tool in tools:
        if shutil.which(tool) is None:
            log(f"{tool} not found. Installing...")
            exec_command(f"apt install -y {tool}")

def configure_firewall():
    update_status("Configuring Firewall")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw enable")

def enforce_password_policies():
    update_status("Enforcing Password Policies")
    exec_command("chage -M 90 -m 7 -W 14 $(whoami)")

def restrict_sudo_access():
    update_status("Restricting Sudo Access")
    exec_command("echo '$(whoami) ALL=(ALL) ALL, !/bin/su, !/usr/bin/passwd' | sudo tee -a /etc/sudoers")

def harden_grub():
    update_status("Hardening GRUB Security")
    exec_command("echo 'GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash apparmor=1 security=apparmor\"' | sudo tee -a /etc/default/grub")
    exec_command("update-grub")

def harden_network():
    update_status("Applying Network Hardening")
    exec_command("echo 'net.ipv4.conf.all.rp_filter = 1' | sudo tee -a /etc/sysctl.conf")
    exec_command("sysctl -p")

def track_setgid_permissions():
    update_status("Tracking SetGID Permissions")
    exec_command("find / -mount -perm -2000 -type f -exec ls -ld {} \\; > /home/user/setgid_.txt")
    exec_command("chown user:user /home/user/setgid_.txt")

def setup_audit_logs():
    update_status("Enabling Security Audit Logs")
    exec_command("auditctl -e 1")

def enable_auto_updates():
    """Enables unattended security updates."""
    update_status("Enabling Automatic Security Updates")
    exec_command("apt install -y unattended-upgrades")
    exec_command("dpkg-reconfigure -plow unattended-upgrades")

def setup_security_cron_jobs():
    """Creates cron jobs for regular security maintenance."""
    update_status("Setting up security automation")
    
    cron_jobs = [
        "@daily apt update && apt upgrade -y",
        "@weekly lynis audit system >> /var/log/lynis_weekly.log",
        "@weekly find / -perm -2000 -type f -exec ls -ld {} \\; > /home/user/setgid_.txt"
    ]

    for job in cron_jobs:
        exec_command(f"(crontab -l 2>/dev/null; echo \"{job}\") | crontab -")

def run_audits():
    update_status("Running Security Audits")
    exec_command("freshclam")
    exec_command("clamscan -r /home --infected --log=/var/log/clamav_scan.log")
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")

# MAIN FUNCTION
def start_hardening():
    ensure_security_tools()
    threading.Thread(target=lambda: [
        configure_firewall(),
        enforce_password_policies(),
        restrict_sudo_access(),
        harden_grub(),
        harden_network(),
        track_setgid_permissions(),
        setup_audit_logs(),
        enable_auto_updates(),
        setup_security_cron_jobs(),
        run_audits()
    ], daemon=True).start()

def main():
    print_ascii_art()
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()
