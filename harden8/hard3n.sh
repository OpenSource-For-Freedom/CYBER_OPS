#!/bin/bash

#### All credit goes to the Kicksecure/Whonix team for these files, modifications to them have been slight...   ####
#### Take note regarding this file in particular, modifications have been made from the original, allowing      ####
    #### for a higher level of security... thanks        ####
#### 			again to the Kicksecure/Whonix crew, keeping helping us learn and grow!                         ####
##
## Copyright (C) 2019 - 2023 ENCRYPTED SUPPORT LP <adrelanos@whonix.org>                     
## See the file COPYING for copying conditions.
##
## Enables all known mitigations for CPU vulnerabilities.
##

## Enable known mitigations for CPU vulnerabilities
sed -i 's/^GRUB_CMDLINE_LINUX="/& mitigations=auto spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full tsx=off tsx_async_abort=full kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full retbleed=auto /' /etc/default/grub
update-grub

# Print the ASCII
echo "        -----------------------------------------------------------------------"
echo "                    H   H   AAAAA   RRRR    DDDD    333333    NN    N"
echo "          ======== H   H  A     A  R   R   D   D       33    N N   N"
echo "          ======= HHHHH  AAAAAAA  RRRR    D   D     33      N  N  N"
echo "          ====== H   H  A     A  R  R    D   D       33    N   N N"
echo "                H   H  A     A  R   R   DDDD    333333    N    NN"
echo "        -----------------------------------------------------------------------"
echo "                    \"HARD3N\" - The Linux Security Project"
echo "                    ----------------------------------------"
echo "                     A project focused on improving Linux"
echo "                    security by automating, containerizing"
echo "                                Hardening and"
echo "                         System protection measures."
echo "                             License: MIT License"
echo "                                Version: 1.3"
echo "                               Dev: Tim + Kiu"
echo "          GitHub: https://github.com/OpenSource-For-Freedom/Linux.git"
echo ""
echo ""
echo ""

## e, errexit | u, nounset | -o pipefail
set -euo pipefail

## Log spec file directory
LOG_DIR="/var/log/security_scans"
sudo mkdir -p "$LOG_DIR"
DATE=$(date +"%Y%m%d_%H%M%S")
SCRIPT_LOG="$LOG_DIR/script_execution_$DATE.log"

echo "Starting system hardening at $(date)" | sudo tee -a "$SCRIPT_LOG"

## Check if-as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Please re-run this script with sudo or as root." | sudo tee -a "$SCRIPT_LOG"
    exit 1
fi

## Define utility functions
exec_e() {
    "$@"
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed. Exiting script." | sudo tee -a "$SCRIPT_LOG"
        exit 1
    fi
    echo "$1 completed successfully." | sudo tee -a "$SCRIPT_LOG"
}

## Update system 
echo "Updating system packages..."
exec_e apt update && exec_e apt upgrade -yy

## Install sec tools
echo "Installing security tools..."
exec_e apt install -yy podman firejail bubblewrap ufw fail2ban clamav lynis apparmor apparmor-utils

## Check for Snap
if ! command -v snap &> /dev/null; then
    echo "SNAP not found. Installing Snap..." | sudo tee -a "$SCRIPT_LOG"
    exec_e apt install -y snapd
fi

## Install and spin up LXD
if ! command -v lxd &> /dev/null; then
    echo "LXD not found. Installing LXD via Snap..." | sudo tee -a "$SCRIPT_LOG"
    exec_e snap install lxd
fi

## Enable AppArmor
echo "Enabling AppArmor..."
exec_e systemctl enable --now apparmor

## Configure UFW simply 
echo "Setting up UFW firewall..."
exec_e ufw enable
exec_e ufw default deny incoming
exec_e ufw default allow outgoing

# SSH and ask for port 
read -p "Do you need SSH access? (y/n): " SSH_NEEDED
if [[ "$SSH_NEEDED" == "y" ]]; then
    read -p "Enter inbound port for SSH (default 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    if [[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" -ge 1 && "$SSH_PORT" -le 65535 ]]; then
        exec_e ufw allow "$SSH_PORT"
    else
        echo "Invalid port. SSH configuration skipped."
    fi
else
    echo "SSH access is disabled."
fi

## Configure Fail2Ban
echo "Enabling Fail2Ban..."
exec_e systemctl enable --now fail2ban

## Configure ClamAV
echo "Setting up ClamAV..."
exec_e freshclam
exec_e clamscan -r / --log="$LOG_DIR/clamav_scan_$DATE.log"

## Run Lynis (v) wpuld like to run as pentest later
echo "Running Lynis system audit..."
exec_e lynis audit system | tee "$LOG_DIR/lynis_audit_$DATE.log"

## Podman Containerization >> Firefox
echo "Setting up Podman for Firefox container..."
exec_e podman pull docker.io/jess/firefox
exec_e podman run -it --rm --net=none docker.io/jess/firefox

## Configure sysctl for kernel 
echo "Applying sysctl hardening..."
cat <<EOF | sudo tee /etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF
exec_e sysctl --system

## Reboot prompt
read -p "Reboot required to apply all changes. Reboot now? (y/n): " REBOOT
if [[ "$REBOOT" == "y" ]]; then
    sudo reboot
else
    echo "Please reboot manually to apply changes."
fi