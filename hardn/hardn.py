import os
import subprocess
import sys
import shlex
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox  # Added messagebox for GUI popups
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

# nasty banner 
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
                            Version: 1.5.3
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)

# Paths to the deep 
HARDN_QUBE_PATH = os.path.abspath("HARDN_qubes.py")
HARDN_DARK_PATH = os.path.abspath("HARDN_dark.py")

# GUI + ask for dark file after hardn finishes
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

        self.complete_button = tk.Button(self.root, text="Continue to Advanced Security", command=self.show_advanced_options, state=tk.DISABLED)
        self.complete_button.pack(pady=10)

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
        self.complete_button.config(state=tk.NORMAL)

    def run(self):
        self.root.mainloop()

status_gui = StatusGUI()

# EXECUTE COMMAND
def exec_command(command):
    try:
        result = subprocess.run(shlex.split(command), check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.strip()
        status_gui.update_status(f"{command}\n{output}\n")
        logging.info(f"Executed: {command}\nOutput: {output}")
        return output
    except subprocess.CalledProcessError as e:
        error_msg = f"Error: {e.stderr.strip()}"
        status_gui.update_status(error_msg)
        logging.error(f"Failed: {command}\n{error_msg}")
        return None

# SECURITY FUNCTIONS
def remove_clamav():
    status_gui.update_status("Removing ClamAV...")
    exec_command("apt remove --purge -y clamav clamav-daemon")
    exec_command("rm -rf /var/lib/clamav")

def configure_tcp_wrappers():
    status_gui.update_status("Configuring TCP Wrappers...")
    exec_command("apt install -y tcpd")

    allowed_services = ["sshd", "vsftpd", "telnetd", "xinetd"]
    trusted_ips = ["192.168.1.", "10.0.0."]

    allow_rules = "\n".join([f"{service}: {', '.join(trusted_ips)}" for service in allowed_services])
    with open("/etc/hosts.allow", "w") as allow_file:
        allow_file.write(f"{allow_rules}\n")

    with open("/etc/hosts.deny", "w") as deny_file:
        deny_file.write("ALL: ALL\n")

    status_gui.update_status("TCP Wrappers configured. Restarting services...")
    exec_command("systemctl restart ssh")
    exec_command("systemctl restart vsftpd")

def configure_fail2ban():
    status_gui.update_status("Setting up Fail2Ban...")
    exec_command("apt install -y fail2ban")
    exec_command("systemctl restart fail2ban")
    exec_command("systemctl enable --now fail2ban")

def configure_firewall():
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw allow out 80,443/tcp")
    exec_command("ufw --force enable && ufw reload")

def disable_usb():
    status_gui.update_status("Locking down USB devices...")
    exec_command("echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf")
    exec_command("modprobe -r usb-storage || echo 'USB storage module in use, cannot unload.'")

def software_integrity_check():
    status_gui.update_status("Software Integrity Check...")
    exec_command("debsums -s")

def run_audits():
    status_gui.update_status("Running Security Audits...")
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")

# Start the full security hardening process
def start_hardening():
    threading.Thread(target=lambda: [
        remove_clamav(),
        configure_tcp_wrappers(),
        install_eset_nod32(),
        setup_auto_updates(),
        configure_fail2ban(),
        configure_firewall(),
        disable_usb(),
        software_integrity_check(),
        run_audits(),
        status_gui.complete()
    ], daemon=True).start()

# Run Main
def main():
    print_ascii_art()
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()
