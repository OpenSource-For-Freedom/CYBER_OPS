import os
import subprocess
import sys
import shlex
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox  # added 
from datetime import datetime

# ROOT 
def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

# THE NASTY 
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

# PATHS TO HIRE
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

    def show_advanced_options(self):
        """Show Advanced Security Options after main run"""
        self.advanced_window = tk.Toplevel(self.root)
        self.advanced_window.title("Advanced Security Options")
        self.advanced_window.geometry("500x300")
        
        tk.Label(self.advanced_window, text="Would you like to enable additional security features?", font=("Mono", 12)).pack(pady=10)

        qube_button = tk.Button(self.advanced_window, text="Run HARDN Qube (TOR & Sandbox)", command=self.run_hardn_qube)
        qube_button.pack(pady=5)

        dark_button = tk.Button(self.advanced_window, text="Run HARDN Dark (Deep Lockdown)", command=self.run_hardn_dark)
        dark_button.pack(pady=5)

        close_button = tk.Button(self.advanced_window, text="Exit", command=self.advanced_window.destroy)
        close_button.pack(pady=10)

    def run(self):
        self.root.mainloop()

status_gui = StatusGUI()

# EXECUTE sub
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

# SECURITY
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

    status_gui.update_status("TCP Wrappers configured. Checking services...")

    # CHECK fo ssh and VSFTPD pre-load
    services = {"SSH": "sshd", "vsftpd": "vsftpd"}
    for service_name, service in services.items():
        check_service = exec_command(f"systemctl list-units --type=service | grep -i {service}")
        if check_service:
            exec_command(f"systemctl restart {service}")
            status_gui.update_status(f"{service_name} restarted successfully.")
        else:
            status_gui.update_status(f"Warning: {service_name} service not found. Skipping restart.")


# START ALL
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
