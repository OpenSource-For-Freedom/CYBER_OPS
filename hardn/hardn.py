import os
import subprocess
import sys
import shlex
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox  # Added 
from datetime import datetime
# Tie in wazuh SIEM
# Tie in VM support and containerization 
# Tie in API response and SSH again
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
                            Version: 1.5.3
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)

# DEP FILES TO THE DEEP
script_dir = os.path.dirname(os.path.abspath(__file__))  # Get script's directory

HARDN_QUBE_PATH = os.path.join(script_dir, "HARDN_qubes.py")
HARDN_DARK_PATH = os.path.join(script_dir, "HARDN_dark.py")



# EXECUTE 
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
# GUI + ask for dark file after hardn finishes
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARDN Linux - Security Hardening Progress")
        self.root.geometry("800x500")
        self.root.resizable(False, False)

        # DARK MODE - WE ARE BATMAN
        self.root.configure(bg="#2E2E2E")

        self.label = tk.Label(self.root, text="Initializing system hardening...", font=("Mono", 14), fg="white", bg="#2E2E2E")
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, length=700, mode="determinate")
        self.progress.pack(pady=10)

        self.text_area = tk.Text(self.root, height=20, width=90, state=tk.DISABLED, bg="#1E1E1E", fg="white", insertbackground="white")
        self.text_area.pack(pady=10)

        # BUTTON CHANGE - to disabled until first cript completes
        self.complete_button = tk.Button(self.root, text="Continue to Advanced Security", command=self.show_advanced_options, state=tk.DISABLED, bg="#404040", fg="white")
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
        self.complete_button.config(state=tk.NORMAL)  # second button
# SHOW ADVANCED - the second gui
    def show_advanced_options(self):
        """Show Advanced Security Options after main run"""
        self.advanced_window = tk.Toplevel(self.root)
        self.advanced_window.title("Advanced Security Options")
        self.advanced_window.geometry("600x400")
        self.advanced_window.configure(bg="#2E2E2E")

        tk.Label(self.advanced_window, text="Would you like to enable additional security features?", font=("Mono", 12), fg="white", bg="#2E2E2E").pack(pady=10)

        # LOG
        self.log_output = tk.Text(self.advanced_window, height=10, width=70, state=tk.DISABLED, bg="#1E1E1E", fg="white", insertbackground="white")
        self.log_output.pack(pady=10)

        # BUTTONS FOR SECOND GUI
        qube_button = tk.Button(self.advanced_window, text="Run HARDN Qube (TOR & Sandbox)", command=self.run_hardn_qube, bg="#404040", fg="white")
        qube_button.pack(pady=5)

        dark_button = tk.Button(self.advanced_window, text="Run HARDN Dark (Deep Lockdown)", command=self.run_hardn_dark, bg="#404040", fg="white")
        dark_button.pack(pady=5)

        close_button = tk.Button(self.advanced_window, text="Exit", command=self.advanced_window.destroy, bg="#404040", fg="white")
        close_button.pack(pady=10)

    def run_hardn_qube(self):
        """Executes HARDN Qube for TOR-based lockdown"""
        if os.path.exists(HARDN_QUBE_PATH):
            self.log_output.config(state=tk.NORMAL)
            self.log_output.insert(tk.END, "Running HARDN Qube...\n")
            self.log_output.config(state=tk.DISABLED)
            subprocess.Popen(["python3", HARDN_QUBE_PATH])
        else:
            self.log_output.config(state=tk.NORMAL)
            self.log_output.insert(tk.END, "Error: HARDN Qube script not found.\n")
            self.log_output.config(state=tk.DISABLED)

    def run_hardn_dark(self):
        """Executes HARDN Dark for full system lockdown"""
        if os.path.exists(HARDN_DARK_PATH):
            self.log_output.config(state=tk.NORMAL)
            self.log_output.insert(tk.END, "Running HARDN Dark...\n")
            self.log_output.config(state=tk.DISABLED)
            subprocess.Popen(["python3", HARDN_DARK_PATH])
        else:
            self.log_output.config(state=tk.NORMAL)
            self.log_output.insert(tk.END, "Error: HARDN Dark script not found.\n")
            self.log_output.config(state=tk.DISABLED)

    def run(self):
        self.root.mainloop()

# SECURITY 
def remove_clamav():
    status_gui.update_status("Removing ClamAV...")
    exec_command("apt remove --purge -y clamav clamav-daemon")
    exec_command("rm -rf /var/lib/clamav")

def configure_tcp_wrappers():
    status_gui.update_status("Configuring TCP Wrappers...")
    exec_command("apt install -y tcpd")

def configure_fail2ban():
    status_gui.update_status("Setting up Fail2Ban...")
    exec_command("apt install -y fail2ban")
    exec_command("systemctl restart fail2ban")
    exec_command("systemctl enable --now fail2ban")

def configure_grub():
    status_gui.update_status("Configuring GRUB Security Settings...")
    exec_command("update-grub")

def configure_firewall():
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw default deny incoming")
    exec_command("ufw default allow outgoing")
    exec_command("ufw allow out 80,443/tcp")
    exec_command("ufw --force enable && ufw reload")

def disable_usb(): # we can set this to just put in monitor mode*
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
        remove_clamav(), # pull clamv
        configure_tcp_wrappers(), # put in tcp wrap
        configure_fail2ban(), # build f2b
        configure_grub(), # pump the grub
        configure_firewall(), # set ufw
        disable_usb(), # stop all usb
        software_integrity_check(), # cehck soft
        run_audits(), #lynis audits
        status_gui.complete() # gui finish 
    ], daemon=True).start()

# MAIN
def main():
    global status_gui  # ensure global
    print_ascii_art()
    status_gui = StatusGUI()  
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()
