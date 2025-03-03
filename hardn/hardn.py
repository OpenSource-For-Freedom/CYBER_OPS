import os
import subprocess
import sys
import shlex
import pexpect
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
# thanks @kiukcat
import os
import subprocess
import sys
import shlex
import logging
import threading
import shutil
import tkinter as tk
from tkinter import ttk, messagebox  
from datetime import datetime

def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

def exec_command(command, status_gui=None):
    try:
        if status_gui:
            status_gui.update_status(f"Executing: {command}")
        print(f"Executing: {command}")
        process = subprocess.run(
            command, shell=True, check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120
        )
        if status_gui:
            status_gui.update_status(f"Completed: {command}")
        print(process.stdout)
    except subprocess.CalledProcessError as e:
        if status_gui:
            status_gui.update_status(f"Error executing '{command}': {e.stderr}")
        print(f"Error executing command '{command}': {e.stderr}")
    except subprocess.TimeoutExpired:
        if status_gui:
            status_gui.update_status(f"Command timed out: {command}")
        print(f"Command timed out: {command}")

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
      GitHub: https://github.com/OpenSource-For-Freedom/HARDN.git
    """
    print(art)

# GET DIR
script_dir = os.path.dirname(os.path.abspath(__file__))

# FILE PATH - to dependents 
HARDN_QUBE_PATH = os.path.join(script_dir, "HARDN_qubes.py")
HARDN_DARK_PATH = os.path.join(script_dir, "HARDN_dark.py")

print("HARDN_QUBE_PATH:", HARDN_QUBE_PATH)
print("HARDN_DARK_PATH:", HARDN_DARK_PATH)

# GUI
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARDN Security Hardening")
        self.root.geometry("600x400")
        self.root.configure(bg='#333333')

        self.label = ttk.Label(self.root, text="HARDN is securing your system...", font=("Helvetica", 12), background='#333333', foreground='white')
        self.label.pack(pady=20)

        self.progress = ttk.Progressbar(self.root, length=500, mode="determinate")
        self.progress.pack(pady=10)

        self.status_text = tk.StringVar()
        self.status_label = ttk.Label(self.root, textvariable=self.status_text, background='#333333', foreground='white')
        self.status_label.pack(pady=5)

        self.log_text = tk.Text(self.root, height=10, width=70, bg='#222222', fg='white')
        self.log_text.pack(pady=10)
        
        self.task_count = 0
        self.total_tasks = 10  # UPDATES - with actual steps and follows process bar

    def update_status(self, message):
        self.task_count += 1
        self.progress["value"] = (self.task_count / self.total_tasks) * 100
        self.status_text.set(message)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def complete(self):
        self.progress["value"] = 100
        self.status_text.set("Hardening complete!")
        
    def run(self):
        self.root.mainloop()
        
        
# SECURITY HARDENING FUNCTIONS
def configure_apparmor():
    status_gui.update_status("Configuring AppArmor for Mandatory Access Control...")
    exec_command("apt install -y apparmor apparmor-profiles apparmor-utils")
    exec_command("systemctl enable --now apparmor")

def configure_firejail():
    status_gui.update_status("Configuring Firejail for Application Sandboxing...")
    exec_command("apt install -y firejail")
    exec_command("firejail --list")
    
def enforce_password_policies():
    exec_command("apt install -y libpam-pwquality", status_gui)
    exec_command("echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3' >> /etc/pam.d/common-password", status_gui)
    
    
# SECURITY TOOLS
def remove_clamav():
    status_gui.update_status("Removing ClamAV...")
    exec_command("apt remove --purge -y clamav clamav-daemon")
    exec_command("rm -rf /var/lib/clamav")
    
def install_rkhunter():
    status_gui.update_status("Installing Rootkit Hunter (rkhunter)...")
    exec_command("apt install -y rkhunter", status_gui)
    exec_command("rkhunter --update", status_gui)
    exec_command("rkhunter --propupd", status_gui)
    
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
    
def run_lynis_audit():
    status_gui.update_status("Running Lynis security audit...")
    exec_command("lynis audit system", status_gui)    

import shutil
import subprocess
# Added VM compatibility in case it's running boot loader or EFI- thanks Alex :)
def configure_grub():
    status_gui.update_status("Configuring GRUB Security Settings...")
    
    # Check if GRUB is available - Alex pointed it out running it on Oracle VM
    grub_cmd = shutil.which("update-grub") or shutil.which("grub-mkconfig")

    if grub_cmd:
        subprocess.run([grub_cmd, "-o", "/boot/grub/grub.cfg"], check=True)
    else:
        print("Warning: GRUB update command not found. Skipping GRUB update.")
        print("If running inside a VM, this may not be necessary.")

def configure_firewall(): # simplified for use, not most secure version at this time
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw allow out 80,443/tcp")
    exec_command("ufw --force enable && ufw reload")
    
def secure_grub():
    status_gui.update_status("Configuring GRUB Secure Boot Password...")
    grub_password = "SuperSecurePassword123!"
    child = pexpect.spawn("grub-mkpasswd-pbkdf2")
    child.expect("Enter password: ")
    child.sendline(grub_password)
    child.expect("Reenter password: ")
    child.sendline(grub_password)
    child.expect(pexpect.EOF)
    output = child.before.decode()
    
    hashed_password = ""
    for line in output.split("\n"):
        if "PBKDF2 hash of your password is" in line:
            hashed_password = line.split("is ")[1].strip()
            break
    
    if not hashed_password:
        status_gui.update_status("Failed to generate GRUB password hash.")
        return
    
    grub_config = f"set superusers=\"admin\"\npassword_pbkdf2 admin {hashed_password}\n"
    with open("/etc/grub.d/00_password", "w") as f:
        f.write(grub_config)
    
    exec_command("update-grub", status_gui)
    
#def enable_aide():
 #   exec_command("apt install -y aide aide-common", status_gui)
  #  exec_command("aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db", status_gui)

def harden_sysctl():
    exec_command("sysctl -w net.ipv4.conf.all.accept_redirects=0", status_gui)
    exec_command("sysctl -w net.ipv4.conf.all.send_redirects=0", status_gui)    

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
    def run_tasks():
        print_ascii_art()
        exec_command("apt update && apt upgrade -y", status_gui)
        enforce_password_policies()
        exec_command("apt install -y fail2ban", status_gui)
        exec_command("systemctl enable --now fail2ban", status_gui)
        configure_firewall()
        exec_command("apt install -y rkhunter", status_gui)
        exec_command("rkhunter --update && rkhunter --propupd", status_gui)
        #enable_aide()
        exec_command("lynis audit system", status_gui)
        harden_sysctl()
        secure_grub()
        exec_command("apt install -y apparmor apparmor-profiles apparmor-utils", status_gui)
        exec_command("systemctl enable --now apparmor", status_gui)
        status_gui.complete()
    
    threading.Thread(target=run_tasks, daemon=True).start()

# MAIN
def main():
    global status_gui  # global
    print_ascii_art()
    status_gui = StatusGUI()  
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()