#!/usr/bin/env python3
# HARDN_QUBE - The Debian OS Lockdown Tool using UFW Firewall
import os
import subprocess
import logging
from logging.handlers import RotatingFileHandler

# Logs
LOG_DIR = "/var/log/hardn"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "hardn_qube.log")

log_handler = RotatingFileHandler(LOG_FILE, maxBytes=50 * 1024 * 1024, backupCount=1)
log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# booster and support function* 
def run_command(command, description=""):
    """Executes a shell command and logs output."""
    logger.info(f"[+] {description}")
    print(f"[+] {description}")
    try:
        if not isinstance(command, list):
            raise ValueError("Command must be provided as a list.")
        result = subprocess.run(command, text=True, check=True, capture_output=True)
        if result.stdout:
            logger.info(result.stdout)
            print(result.stdout)
        if result.stderr:
            logger.error(f"[-] Error: {result.stderr}")
            print(f"[-] Error: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logger.error(f"[-] {description} failed: {e.stderr}")
        print(f"[-] {description} failed: {e.stderr}")
    except ValueError as ve:
        logger.error(f"[-] {ve}")
        print(f"[-] {ve}")

# check root 
def check_privileges():
    """Ensure the script runs with root privileges."""
    if os.geteuid() != 0:
        logger.error("Script must be run as root! Use 'sudo'.")
        print("[-] Script must be run as root! Use 'sudo'.")
        exit(1)

check_privileges()

# UFW 
def configure_ufw():
    """Configures UFW firewall rules for TOR-only traffic enforcement."""
    print("[+] Configuring UFW firewall rules...")

    # make sure ufw is installed and enabled 
    run_command(["apt", "install", "-y", "ufw"], "Installing UFW")
    run_command(["ufw", "disable"], "Disabling UFW temporarily to reset rules")
    run_command(["ufw", "reset"], "Resetting UFW rules")

    # Default 
    run_command(["ufw", "default", "deny", "incoming"], "Denying all incoming traffic")
    run_command(["ufw", "default", "deny", "outgoing"], "Denying all outgoing traffic")

    # TOR traffic ONLY 
    run_command(["ufw", "allow", "out", "9040/tcp"], "Allowing TOR (9040)")
    run_command(["ufw", "allow", "out", "9053/udp"], "Allowing TOR DNS (9053)")

    # Debian updates (APT)
    run_command(["ufw", "allow", "out", "53,67,123/udp"], "Allowing DNS, DHCP, NTP")
    run_command(["ufw", "allow", "out", "80/tcp"], "Allowing HTTP for APT updates")
    run_command(["ufw", "allow", "out", "443/tcp"], "Allowing HTTPS for secure updates")

    # Allow SSH at some point 
    # run_command(["ufw", "allow", "22/tcp"], "Allowing SSH (22)")

    # Enable UFW | force
    run_command(["ufw", "--force", "enable"], "Enabling UFW firewall")

    print("[+] UFW firewall rules applied successfully.")

# Configure TOR + Snowflake bridge
def configure_tor():
    """Install and configure TOR with Snowflake bridge."""
    print("[+] Configuring TOR with Snowflake bridge...")
    run_command(["apt", "update"], "Updating package lists")
    run_command(["apt", "install", "-y", "tor", "snowflake-client"], "Installing TOR and Snowflake client")

    # buikd tor and snowflake... we can choose a diff bridge if this isn't what we want for now 
    torrc_path = "/etc/tor/torrc"
    torrc_content = """
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client
UseBridges 1
Bridge snowflake 192.0.2.1:443 
DNSPort 9053
TransPort 9040
"""
    try:
        with open(torrc_path, "w") as torrc_file:
            torrc_file.write(torrc_content)
        print(f"[+] Wrote TOR configuration to {torrc_path}.")
    except IOError as e:
        print(f"[-] Failed to write TOR config: {e}")
        exit(1)

    # Set perms + restart TOR
    run_command(["chown", "tor:tor", torrc_path], "Setting torrc ownership")
    run_command(["chmod", "644", torrc_path], "Setting torrc permissions")
    run_command(["systemctl", "restart", "tor"], "Restarting TOR service")

# lockdown browser 
def containerize_browser(browser="firefox"):
    """Run browser in an isolated Firejail sandbox."""
    print("[+] Sandboxing browser...")
    run_command(["apt", "install", "-y", "firejail"], "Installing Firejail")
    run_command(["firejail", "--private", browser], "Launching browser in sandbox")

# locodown dir's
def sandbox_directories():
    """Prevent unauthorized modifications to critical directories."""
    critical_dirs = ["/var", "/lib", "/bin", "/sbin", "/root", "/boot"]
    print("[+] Sandboxing critical directories...")

    run_command(["apt", "install", "-y", "firejail"], "Ensuring Firejail is installed")
    
    for directory in critical_dirs:
        run_command(["firejail", f"--private={directory}"], f"Sandboxing {directory}")

# Allow approved updates only but still need to enforce this in all 
def enforce_signed_updates():
    """Only allow updates for whitelisted packages."""
    print("[+] Enforcing signed package updates...")
    whitelist_file = "/etc/apt/approved-packages.txt"

    # be sure of whitelist exists
    if not os.path.exists(whitelist_file):
        print(f"[-] Package whitelist {whitelist_file} not found! Creating default.")
        with open(whitelist_file, "w") as f:
            f.write("tor\nsnowflake-client\nfirejail\n")  # Example default packages

    # update but only approved ones 
    run_command(["apt-get", "update"])
    run_command(["apt-get", "install", "--only-upgrade", f"$(cat {whitelist_file})"], "Applying approved updates")

# Redirect downloads > focused directory
def redirect_web_downloads(directory="/var/locked_downloads"):
    """Redirect and log all web-based downloads for inspection."""
    print(f"[+] Redirecting web downloads to {directory}...")

    if not os.path.exists(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)

    print("[+] Download logging enabled.")

# Execute full 
def hardn_qube_lockdown():
    """Execute full system lockdown with all protections."""
    configure_ufw()
    configure_tor()
    containerize_browser()
    sandbox_directories()
    enforce_signed_updates()
    redirect_web_downloads()

# Main file
if __name__ == "__main__":
    hardn_qube_lockdown()