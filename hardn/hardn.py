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
# from hardn_tk import HardnGUI  

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
                            Version: 1.4.5
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
        self.root.geometry("600x400")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 12), wraplength=580)
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, length=500, mode="determinate")  
        self.progress.pack(pady=10)

        self.text_area = tk.Text(self.root, height=15, width=70, state=tk.DISABLED)
        self.text_area.pack(pady=10)

        self.close_button = tk.Button(self.root, text="Close", command=self.root.quit, state=tk.DISABLED)
        self.close_button.pack(pady=10)

        self.total_steps = 12
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

# EXECUTE COMMAND & LOG IN GUI
def exec_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.strip()
        status_gui.update_status(f"{command}\n{output}\n")
        return output
    except subprocess.CalledProcessError as e:
        status_gui.update_status(f"{command}\nError: {e.stderr.strip()}\n")
        return None

# GRUB and CPU
def enable_cpu_mitigations():
    status_gui.update_status("Applying CPU & IOMMU Mitigations")

    exec_command("cp /etc/default/grub /etc/default/grub.bak")

    # update sec for GRUB 
    exec_command(
        'sed -i \'s/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="mitigations=auto spectre_v2=on '
        'spec_store_bypass_disable=on l1tf=full,force mds=full tsx=off tsx_async_abort=full '
        'l1d_flush=on mmio_stale_data=full retbleed=auto iommu=force iommu.passthrough=0 iommu.strict=1 '
        'intel_iommu=on amd_iommu=force_isolation efi=disable_early_pci_dma" /\' /etc/default/grub'
    )

    exec_command("update-grub")

# SYSTEM HARDENING
def configure_firewall():
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw --force enable")

def enforce_password_policies():
    status_gui.update_status("Enforcing Password Policies...")
    exec_command("chage -M 90 -m 7 -W 14 $(whoami)")

def track_setgid_permissions():
    status_gui.update_status("Tracking SetGID Permissions...")
    exec_command("find / -mount -perm -2000 -type f -exec ls -ld {} \\; > /root/setgid_permissions.txt")
    exec_command("chown $(whoami):$(whoami) /root/setgid_permissions.txt")

def enable_auto_updates():
    status_gui.update_status("Enabling Automatic Security Updates...")
    exec_command("apt install -y unattended-upgrades")
    exec_command('echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | sudo debconf-set-selections')
    exec_command("dpkg-reconfigure -f noninteractive unattended-upgrades")

def setup_security_cron_jobs():
    status_gui.update_status("Setting up security automation...")
    cron_jobs = [
        "@daily apt update && apt upgrade -y",
        "@weekly lynis audit system >> /var/log/lynis_weekly.log",
        "@weekly find / -perm -2000 -type f -exec ls -ld {} \\; > ~/setgid_permissions.txt"
    ]
    for job in cron_jobs:
        exec_command(f"(crontab -l 2>/dev/null; echo \"{job}\") | crontab -")

# RUN SECURITY AUDITS (ClamAV runs in the background)
def run_audits():
    status_gui.update_status("Running Security Audits...")
    exec_command("freshclam &")  # bkgrnd
    log_file = f"/var/log/clamav_scan_{DATE}.log"
    exec_command(f"clamscan -r /home --infected --log={log_file} &")  # bkgrnd
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")

# MAIN FUNCTION
def start_hardening():
    threading.Thread(target=lambda: [
        configure_firewall(),
        enforce_password_policies(),
        track_setgid_permissions(),
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
