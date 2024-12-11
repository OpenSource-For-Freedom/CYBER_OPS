#!/usr/bin/env python3

import os
import subprocess
import sys

# run error handling 
def run_command(command, description=""):
    print(f"[+] {description}")
    result = subprocess.run(command, shell=True, text=True)
    if result.returncode != 0:
        print(f"[-] Error: {description} failed.")
        sys.exit(1)

# Verify root 
if os.geteuid() != 0:
    print("[-] This script must be run as root. Please use 'sudo'.")
    sys.exit(1)

# Step 1: Lock down the NIC
def lockdown_nic():
    print("[+] Locking down the NIC...")
    run_command("nmcli networking off", "Disabling all networking via NetworkManager")
    run_command("ip link set lo up", "Enabling loopback interface")
    print("[+] NIC locked down. Only loopback interface is active.")

# Step 2: Configure TOR with **Snowflake** bridge
def configure_tor():
    print("[+] Configuring TOR with Snowflake bridge...")
    # Install TOR if not already installed
    run_command("apt update && apt install -y tor", "Installing TOR")
    
    # slap in TOR
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

# Step 3: Set loopback as DNS
def configure_dns_loopback():
    print("[+] Configuring loopback as DNS...")
    resolv_conf_content = "nameserver 127.0.0.1\n"
    with open("/etc/resolv.conf", "w") as resolv_conf_file:
        resolv_conf_file.write(resolv_conf_content)
    print("[+] DNS configured to use loopback.")

# Step 4: Containerize browser activity
def containerize_browser():
    print("[+] Containerizing browser activity...")
    # Ensure Firejail is installed
    run_command("apt install -y firejail", "Installing Firejail sandboxing tool")
    
    # Run Firefox in Firejail
    browser_container_command = "firejail --net=none firefox"
    print(f"[+] Browser container command: {browser_container_command}")
    print("[+] To launch the browser, run the above command manually.")
    # Optionally uncomment the next line to auto-launch the browser in a container:
    # run_command(browser_container_command, "Launching browser in Firejail")

# Step 5: Disable web-based downloads
def block_web_downloads():
    print("[+] Blocking web-based downloads...")
    iptables_rules = [
        "iptables -A OUTPUT -p tcp --dport 80 -j REJECT",
        "iptables -A OUTPUT -p tcp --dport 443 -j REJECT",
    ]
    for rule in iptables_rules:
        run_command(rule, f"Applying rule: {rule}")
    print("[+] Web-based downloads are blocked.")

# Step 6: TCPDump for Network Monitoring
def setup_tcpdump():
    print("[+] Setting up tcpdump for network monitoring...")
    # Install tcpdump
    run_command("apt install -y tcpdump", "Installing tcpdump")
    
    # Start tcpdump with a 12MB log limit
    tcpdump_command = (
        "tcpdump -i lo -w /var/log/tcpdump_log.pcap -C 12 -Z root"
    )
    print(f"[+] Tcpdump command: {tcpdump_command}")
    print("[+] Tcpdump will log up to 12MB in /var/log/tcpdump_log.pcap.")
    # comment the next line to stop tcpdump automatically:
    run_command(tcpdump_command, "Starting tcpdump")

# Origin file to run all steps
def main():
    print("[+] Hard3n_Qube.py starting...")
    
    # Step 0: Ensure HARD3N.sh has run (manual validation for now)
    print("[!] Please ensure HARD3N.sh has completed before running this script.")
    input("Press Enter to continue if HARD3N.sh has finished, or Ctrl+C to exit.")

    # Run all steps
    lockdown_nic()
    configure_tor()
    configure_dns_loopback()
    containerize_browser()
    block_web_downloads()
    setup_tcpdump()
    
    print("[+] Hard3n_Qube.py completed successfully.")

if __name__ == "__main__":
    main()