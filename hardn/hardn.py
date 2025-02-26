import os
import subprocess
import shutil
import sys
import signal
import time
import shlex
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

# Logging 
LOG_DIR = "/var/log/hardn" # best directory IMO
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"hardn_security_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# GUI stuff and buttons edited 
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARDN Linux - Security Hardening Progress")
        self.root.geometry("800x500")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Initializing system hardening...", font=("Mono", 14))
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, length=700, mode="determinate")
        self.progress.pack(pady=10)

        self.text_area = tk.Text(self.root, height=20, width=90, state=tk.DISABLED)
        self.text_area.pack(pady=10)

        self.close_button = tk.Button(self.root, text="Close", command=self.root.quit, state=tk.DISABLED)
        self.close_button.pack(pady=10)

        self.total_steps = 10
        self.current_step = 0

    def update_status(self, message):
        self.label.config(text=message)
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.yview(tk.END)

        self.current_step += 1
        progress_percent = int((self.current_step / self.total_steps) * 100)
        self.progress["value"] = progress_percent
        self.root.update_idletasks()

    def complete(self):
        self.update_status("System Hardening Complete!")
        self.close_button.config(state=tk.NORMAL)

    def run(self):
        self.root.mainloop()

status_gui = StatusGUI()

# Command assit 
def exec_command(command):
    try:
        result = subprocess.run(shlex.split(command), check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.strip()
        status_gui.update_status(f"{command}\n{output}\n")
        logging.info(f"Executed: {command}\nOutput: {output}")
        return output # helps the gui function alongside the commands 
    except subprocess.CalledProcessError as e:
        error_msg = f"Error: {e.stderr.strip()}"
        status_gui.update_status(error_msg)
        logging.error(f"Failed: {command}\n{error_msg}")
        return None

# Security Hardening Functions
def remove_clamav(): # just in case it's natively downloaded
    status_gui.update_status("Removing ClamAV...")
    exec_command("apt remove --purge -y clamav clamav-daemon")
    exec_command("rm -rf /var/lib/clamav")

def install_eset_nod32(): # this will be replaced with LEGION at some point, still here for test only
    status_gui.update_status("Installing ESET NOD32 Antivirus...")
    exec_command("wget -q https://download.eset.com/com/eset/apps/home/av/linux/latest/eset_nod32av_64bit.deb -O /tmp/eset.deb")
    exec_command("dpkg -i /tmp/eset.deb || apt --fix-broken install -y")
    exec_command("rm -f /tmp/eset.deb")

def setup_auto_updates():
    status_gui.update_status("Configuring Auto-Update for ESET NOD32...")
    eset_update_cmd = "/opt/eset/esets/sbin/esets_update"
    if os.path.exists(eset_update_cmd):
        exec_command(f"(crontab -l 2>/dev/null; echo '0 3 * * * {eset_update_cmd}') | crontab -")
    else:
        status_gui.update_status("ESET Update Command Not Found.")

def configure_fail2ban():
    status_gui.update_status("Setting up Fail2Ban...")
    exec_command("apt install -y fail2ban")
    exec_command("systemctl enable --now fail2ban")

def configure_grub():
    status_gui.update_status("Configuring Secure Boot & GRUB...")
    grub_settings = """
    GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lockdown,yama,integrity"
    """
    with open("/etc/default/grub", "a") as grub_file:
        grub_file.write(grub_settings + "\n")
    exec_command("update-grub")

def configure_firewall(): # still wanting to only allow approve url downloads instead of 80 downloads for conical and Debian
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw allow out 443/tcp")
    exec_command("ufw allow out 80/tcp") # still trying to determine a way to allow conical or http updates internally... 
    exec_command("ufw enable")
# usb blocking for now, 
def disable_usb():# would like to enable this as an option over just all-block...
    status_gui.update_status("Disabling USB Storage...")
    exec_command("echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf")
    exec_command("modprobe -r usb-storage")

def software_integrity_check():
    status_gui.update_status("Software Integrity Check...")
    exec_command("debsums -s")

def run_audits(): # I feel this should be stronger... 
    status_gui.update_status("Running Security Audits...")
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")
    exec_command("/opt/eset/esets/sbin/esets_scan /home")

# Start main file and verify 
def start_hardening():
    threading.Thread(target=lambda: [
        remove_clamav(),
        install_eset_nod32(),
        setup_auto_updates(),
        configure_fail2ban(),
        configure_grub(),
        configure_firewall(),
        disable_usb(),
        software_integrity_check(),
        run_audits()
    ], daemon=True).start()
# if this is the last
# Run Main 
def main():
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    print_ascii_art()
    main()
