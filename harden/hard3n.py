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
                            Version: 1.3.4
                           Dev: Tim "TANK" Burns
      GitHub: https://github.com/OpenSource-For-Freedom/Linux.git
    """
    print(art)

# STATUS TRACK
status_step = 0  
total_steps = 8  

# STATUS 
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARD3N - System Hardening Progress")
        self.root.geometry("550x350")
        self.root.resizable(False, False)

        self.label = tk.Label(self.root, text="Starting system hardening...", font=("Mono", 14), wraplength=500)
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, length=450, mode="determinate")  
        self.progress.pack(pady=5)

        self.log_window = tk.Text(self.root, height=8, width=60, state=tk.DISABLED)
        self.log_window.pack(pady=5)

        self.toggle_button = tk.Button(self.root, text="Show Logs", command=self.toggle_logs)
        self.toggle_button.pack(pady=5)

        self.close_button = tk.Button(self.root, text="Close", command=self.root.quit, state=tk.DISABLED)
        self.close_button.pack(pady=5)

        self.total_steps = total_steps
        self.current_step = 0
        self.show_logs = False

    def update_status(self, message, progress=None):
        """Updates the GUI progress"""
        self.label.config(text=message)
        if progress is not None:
            self.progress["value"] = progress
        else:
            self.current_step += 1
            progress_percent = int((self.current_step / self.total_steps) * 100)
            self.progress["value"] = progress_percent
        self.root.update_idletasks()

    def add_log(self, message):
        """Adds log output to the GUI log window"""
        self.log_window.config(state=tk.NORMAL)
        self.log_window.insert(tk.END, message + "\n")
        self.log_window.config(state=tk.DISABLED)
        self.log_window.see(tk.END)

    def toggle_logs(self):
        """Toggles between log view and progress bar"""
        self.show_logs = not self.show_logs
        self.log_window.pack_forget() if not self.show_logs else self.log_window.pack(pady=5)
        self.toggle_button.config(text="Hide Logs" if self.show_logs else "Show Logs")

    def complete(self):
        """Marks completion of process"""
        self.label.config(text="System Hardening Complete!")
        self.progress["value"] = 100
        self.close_button.config(state=tk.NORMAL)
        self.root.update_idletasks()

    def run(self):
        """Runs the GUI"""
        self.root.mainloop()

status_gui = StatusGUI()

# GET DISK SIZE
def get_total_scan_size(scan_dirs):
    """Calculates the total disk space used by the directories being scanned."""
    total_size = 0
    for directory in scan_dirs:
        try:
            output = subprocess.check_output(f"du -sb {directory} 2>/dev/null", shell=True, text=True).split()[0]
            total_size += int(output)
        except (subprocess.CalledProcessError, IndexError, ValueError):
            log(f"Skipping {directory}: Unable to calculate size.")
    
    log(f"Total disk space to scan: {total_size / (1024**3):.2f} GB")  
    status_gui.update_status(f"Total scan size: {total_size / (1024**3):.2f} GB")  
    return total_size

# GUI LOG AND STAT
def log(message):
    """Handles logging for both console and GUI"""
    print(message)
    logging.info(message)
    status_gui.add_log(message)
    
def exec_command(command, check=True, silent=False):
    """Executes shell commands with logging and error handling.
    
    Args:
        command (str): The shell command to execute.
        check (bool): Whether to raise an error if the command fails.
        silent (bool): If True, does not log stdout output unless there's an error.

    Returns:
        tuple: (stdout, stderr) from the command execution.
    """
    try:
        result = subprocess.run(command, shell=True, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not silent:
            log(f"Command executed: {command}\nOutput: {result.stdout.strip()}")
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else "No error message provided."
        log(f"Command failed: {command}\nError: {error_message}")
        return None, error_message  # Returns error message for further handling

def update_status(step_name):
    """Updates both the console log and GUI with progress markers."""
    global status_step
    status_step += 1
    message = f"[{status_step}/{total_steps}] {step_name}..."
    
    log(message)  
    status_gui.update_status(message)  

# CLAMAV SCANNING WITH ESTIMATED TIME
def run_audits():
    update_status("Running Security Audits")
    exec_command("freshclam")

    scan_dirs = ["/home", "/var/log", "/etc", "/usr/bin"]
    total_scan_size = get_total_scan_size(scan_dirs)
    scanned_size = 0

    process = subprocess.Popen(
        "clamscan -r /home --infected --max-filesize=100M --max-scansize=500M --log=/var/log/clamav_scan.log",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    start_time = time.time()
    dots = ["Scanning...", "Scanning..", "Scanning."]

    for index, line in enumerate(iter(process.stdout.readline, '')):
        if "Scanned files" in line:
            scanned_size += 100 * 1024 * 1024 
            progress_percent = min(int((scanned_size / total_scan_size) * 100), 100)
            elapsed_time = time.time() - start_time
            estimated_time = (elapsed_time / (scanned_size + 1)) * (total_scan_size - scanned_size)
            status_gui.update_status(f"{dots[index % 3]} {progress_percent}% complete - ETA: {int(estimated_time)}s", progress_percent)
    
    process.wait()
    exec_command("lynis audit system --quick | tee /var/log/lynis_audit.log")
    update_status("Security audits completed.")

# START
def start_hardening():
    threading.Thread(target=lambda: [
        run_audits()
    ], daemon=True).start()

# MAIN
def main():
    print_ascii_art()
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()
