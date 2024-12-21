import subprocess
import sys
import os
import importlib.util  # For importing hard3n_qube.py dynamically
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog

# Define log directory and file
LOG_DIR = "/var/log/security_scans"
os.makedirs(LOG_DIR, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
SCRIPT_LOG = os.path.join(LOG_DIR, f"script_execution_{DATE}.log")

# Log function
def log(message):
    with open(SCRIPT_LOG, 'a') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %T')} {message}\n")
    print(message)

# Execute a shell command and check for success
def exec_e(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"Command succeeded: {command}")
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        log(f"Error executing command: {command}\n{e.stderr.decode()}")
        sys.exit(1)

# Execute the hard3n_deep.sh script
def run_hard3n_deep():
    log("Executing 'hard3n_deep.sh'...")
    script_path = "/path/to/hard3n_deep.sh"  # Replace with actual path
    exec_e(f"sudo bash {script_path}")
    log("'hard3n_deep.sh' executed successfully!")

# Import and run the hard3n_qube.py script
def run_hard3n_qube():
    log("Executing 'hard3n_qube.py'...")
    script_path = "/path/to/hard3n_qube.py"  # Replace with actual path
    
    # Dynamically import hard3n_qube.py
    spec = importlib.util.spec_from_file_location("hard3n_qube", script_path)
    hard3n_qube = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hard3n_qube)

    # Call main functions from the imported script
    if hasattr(hard3n_qube, "run_qube_hardening"):
        hard3n_qube.run_qube_hardening()
        log("'hard3n_qube.py' executed successfully!")
    else:
        log("Error: 'run_qube_hardening' function not found in 'hard3n_qube.py'")
        sys.exit(1)

# Security setup process
def run_security_setup():
    ensure_tkinter_installed()
    update_system()
    install_security_tools()
    enable_apparmor()
    setup_ufw()
    configure_ssh()
    enable_fail2ban()
    setup_clamav()
    run_lynis()

    # Run dependent scripts
    try:
        run_hard3n_deep()
        run_hard3n_qube()
    except SystemExit:
        log("Critical error: Execution stopped.")
        show_message("Error", "A dependent script failed. Review the logs.")
        sys.exit(1)

    reboot_system()

# GUI setup
def create_gui():
    root = tk.Tk()
    root.title("System Hardening Setup")
    root.geometry("400x200")

    start_button = tk.Button(root, text="Start Hardening", command=run_security_setup)
    start_button.pack(pady=20)

    root.mainloop()

# Main execution
if __name__ == "__main__":
    create_gui()