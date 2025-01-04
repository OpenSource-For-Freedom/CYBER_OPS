#!/usr/bin/env python3

import os
import subprocess
import sys
import logging

# Setup logging
logging.basicConfig(filename="/var/log/hard3n_qube.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# run handling
def run_command(command, description=""):
    logger.info(f"[+] {description}")
    print(f"[+] {description}")
    try:
        result = subprocess.run(command, shell=True, text=True, check=True, capture_output=True)
        if result.stdout:
            logger.info(result.stdout)
            print(result.stdout)
        if result.stderr:
            logger.error(f"[-] Error: {result.stderr}")
            print(f"[-] Error: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logger.error(f"[-] Error: {description} failed. {e.stderr}")
        print(f"[-] Error: {description} failed. {e.stderr}")
        sys.exit(1)

# Verify higher
if os.geteuid() != 0:
    logger.error("This script must be run as root. Please use 'sudo'.")
    print("[-] This script must be run as root. Please use 'sudo'.")
    sys.exit(1)

# Lock down NIC, spin up TOR, DNS, and extra steps
def lockdown_nic():
    print("[+] Locking down the NIC...")
    run_command("nmcli networking off", "Disabling all networking via NetworkManager")
    run_command("ip link set lo up", "Enabling loopback interface")
    print("[+] NIC locked down. Only loopback interface is active.")

# Configure TOR with Snowflake bridge
def configure_tor():
    print("[+] Configuring TOR with Snowflake bridge...")

    # Install TOR and Snowflake
    run_command("apt update && apt install -y tor snowflake-client", "Installing TOR and Snowflake client")

    # TOR configuration
    torrc_content = """
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client
UseBridges 1
Bridge snowflake 192.0.2.1:1
DNSPort 9053
TransPort 9040
"""
    with open("/etc/tor/torrc", "w") as torrc_file:
        torrc_file.write(torrc_content)

    # Restart TOR service
    run_command("systemctl restart tor", "Restarting TOR service")
    print("[+] TOR configured with Snowflake bridge.")

# Configure DNS for loopback (127.0.0.1)
def configure_dns_loopback():
    print("[+] Configuring loopback as DNS...")
    resolv_conf_content = """
# TOR DNS
nameserver 127.0.0.1
"""
    with open("/etc/resolv.conf", "w") as resolv_conf_file:
        resolv_conf_file.write(resolv_conf_content)
    
    print("[+] DNS configured to use loopback (127.0.0.1).")

# Containerize browser activity + need to add it fro chrome and safari
def containerize_browser():
    print("[+] Containerizing browser activity...")
    run_command("apt install -y firejail", "Installing Firejail sandboxing tool")
    browser_container_command = "firejail --net=none firefox"
    print(f"[+] Browser container command: {browser_container_command}")

# Block web-based downloads
def block_web_downloads():
    print
