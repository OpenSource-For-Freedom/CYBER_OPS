import os
import subprocess
import shutil
import sys
import signal
import time
import logging
import threading
import getpass
import tkinter as tk
from tkinter import ttk  
from datetime import datetime

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
                            Version: 1.5.1
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

# STATUS GUI 
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARDN - System Hardening Progress")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 12), wraplength=680)
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, length=600, mode="determinate")  
        self.progress.pack(pady=10)

        self.text_area = tk.Text(self.root, height=20, width=90, state=tk.DISABLED)
        self.text_area.pack(pady=10)

        self.close_button = tk.Button(self.root, text="Close", command=self.root.quit, state=tk.DISABLED)
        self.close_button.pack(pady=10)

        self.total_steps = 15
        self.current_step = 0

    def update_status(self, message, progress=None):
        self.label.config(text=message)
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.yview(tk.END)

        if progress is not None:
            self.progress["value"] = progress
        else:
            self.current_step += 1
            progress_percent = int((self.current_step / self.total_steps) * 100)
            self.progress["value"] = progress_percent

        self.root.update_idletasks()

    def complete(self):
        self.update_status("System Hardening Complete!", 100)
        self.close_button.config(state=tk.NORMAL)

    def run(self):
        self.root.mainloop()

status_gui = StatusGUI()

# SECURITY CONFIG
def configure_firewall():
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw --force enable")

def configure_kernel_security():
    status_gui.update_status("Configuring Kernel Security Settings...")
    exec_command("update-grub")

def configure_fail2ban():
    status_gui.update_status("Configuring Fail2Ban...")
    exec_command("apt install -y fail2ban")
    exec_command("systemctl restart fail2ban")
    exec_command("systemctl enable fail2ban")

def install_sophos():
    status_gui.update_status("Installing Sophos Antivirus...")
    exec_command("wget -qO- https://downloads.sophos.com/linux/sav-linux-free.tgz | tar -xz")
    exec_command("cd sophos-av && sudo ./install.sh")

def update_sophos():
    status_gui.update_status("Updating Sophos Antivirus...")
    exec_command("/opt/sophos-av/bin/savupdate")

def setup_sophos_cron():
    status_gui.update_status("Setting up Sophos Auto-Update in Cron...")
    cron_job = "0 3 * * * /opt/sophos-av/bin/savupdate"  
    exec_command(f'(crontab -l 2>/dev/null; echo "{cron_job}") | crontab -')

# RUN SECURITY AUDITS
def run_audits():
    status_gui.update_status("Running Security Audits with Sophos...")
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")
    
    def run_sophos_scan():
        status_gui.update_status("Scanning system with Sophos Antivirus...")
        exec_command("/opt/sophos-av/bin/savscan /home")
        status_gui.update_status("Security Audits Completed!", 100)

    threading.Thread(target=run_sophos_scan, daemon=True).start()

def start_hardening():
    def run_hardening():
        configure_firewall()
        configure_kernel_security()
        configure_fail2ban()
        install_sophos()
        update_sophos()
        setup_sophos_cron()
        run_audits()
        status_gui.complete()

    threading.Thread(target=run_hardening, daemon=True).start()

def main():
    print_ascii_art()
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()