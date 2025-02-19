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
        self.root.title("System Hardening Progress")
        self.root.geometry("800x500")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 14), wraplength=780)
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, length=700, mode="determinate")  
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

# EXECUTE COMMAND & LOG IN GUI
def exec_command(command):
    try:
        result = subprocess.run(shlex.split(command), check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.strip()
        status_gui.update_status(f"{command}\n{output}\n")
        return output
    except subprocess.CalledProcessError as e:
        status_gui.update_status(f"{command}\nError: {e.stderr.strip()}\n")
        return None

# REMOVE CLAMAV
def remove_clamav():
    status_gui.update_status("Removing ClamAV...")
    exec_command("apt remove --purge -y clamav clamav-daemon")
    exec_command("rm -rf /var/lib/clamav")

# INSTALL ESET NOD32
def install_eset_nod32():
    status_gui.update_status("Installing ESET NOD32 Antivirus...")
    exec_command("wget -q https://download.eset.com/com/eset/apps/home/av/linux/latest/eset_nod32av_64bit.deb -O /tmp/eset.deb")
    exec_command("dpkg -i /tmp/eset.deb || apt --fix-broken install -y")
    exec_command("rm -f /tmp/eset.deb")

# ENSURE AUTO-UPDATES FOR ESET
def setup_auto_updates():
    status_gui.update_status("Setting up ESET NOD32 Auto-Update in Cron...")
    eset_update_command = "/opt/eset/esets/sbin/esets_update"
    if os.path.exists(eset_update_command):
        exec_command(f"(crontab -l 2>/dev/null; echo '0 3 * * * {eset_update_command}') | crontab -")
        status_gui.update_status("ESET Auto-Update Scheduled!")
    else:
        status_gui.update_status("Error: ESET Update Command Not Found.")

# CONFIGURE FAIL2BAN
def configure_fail2ban():
    status_gui.update_status("Configuring Fail2Ban...")
    exec_command("apt install -y fail2ban")
    exec_command("systemctl restart fail2ban")
    exec_command("systemctl enable fail2ban")

# CONFIGURE GRUB SECURITY SETTINGS
def configure_grub():
    status_gui.update_status("Configuring GRUB Security Settings...")
    grub_settings = """
    GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=apparmor,landlock,lockdown,yama,integrity,bpf apparmor=1 security=apparmor"
    """
    with open("/etc/default/grub", "a") as grub_file:
        grub_file.write(grub_settings + "\n")
    exec_command("update-grub")

# CONFIGURE FIREWALL
def configure_firewall():
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw allow 80,443/tcp")
    exec_command("ufw allow out 80,443/tcp")
    exec_command("ufw --force enable")

# RUN SECURITY AUDITS
def run_audits():
    status_gui.update_status("Running Security Audits...")
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")
    status_gui.update_status("Scanning system with ESET NOD32...")
    exec_command("/opt/eset/esets/sbin/esets_scan /home")
    status_gui.update_status("Security Audits Completed!")

# USB DEVICE LOCKDOWN
def disable_usb():
    status_gui.update_status("Locking down USB devices...")
    exec_command("echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf")
    exec_command("modprobe -r usb-storage")

# SOFTWARE INTEGRITY CHECK
def software_integrity_check():
    status_gui.update_status("Checking software integrity...")
    exec_command("debsums -s")

# MAIN FUNCTION
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

def main():
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()