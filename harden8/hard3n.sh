#!/bin/bash

#### All credit goes to the Kicksecure/Whonix team for these files, modifications to them have been slight...   ####
#### Take note regarding this file in particular, modifications have been made from the original, allowing      ####
#### for a higher level of security... thanks        ####
#### 			again to the Kicksecure/Whonix crew, keeping helping us learn and grow!                 ####
##
## Copyright (C) 2019 - 2023 ENCRYPTED SUPPORT LP <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## Enables all known mitigations for CPU vulnerabilities.
##
## https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html
## https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
## https://forums.whonix.org/t/should-all-kernel-patches-for-cpu-bugs-be-unconditionally-enabled-vs-performance-vs-applicability/7647

## Enable known mitigations for CPU vulnerabilities
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX mitigations=auto"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX spectre_v2=on"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX spec_store_bypass_disable=on"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX l1tf=full,force"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX mds=full"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX tsx=off tsx_async_abort=full"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX kvm.nx_huge_pages=force"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX l1d_flush=on"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX mmio_stale_data=full"
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX retbleed=auto"

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
echo "                                Version: 1.2"
echo "                               Dev: Tim + Kiu"
echo "          GitHub: https://github.com/OpenSource-For-Freedom/Linux.git"
echo ""
echo ""
echo ""

## e, errexit | u, nounset (treats unset variables as errors, ensuring better uniformity)
## -o pipefail, ensures that if a command in a pipeline fails, the overall exit status of the pipeline is the status of the last command to fail, rather than just the status of the last command
set -euo pipefail

## Log spec file directory
LOG_DIR="/var/log/security_scans"
sudo mkdir -p "$LOG_DIR"
DATE=$(date +"%Y%m%d_%H%M%S")
SCRIPT_LOG="$LOG_DIR/script_execution_$DATE.log"

echo "Starting system hardening at $(date)" | sudo tee -a "$SCRIPT_LOG"

## check if a package is installed (simpler)
is_package_installed() {
    dpkg -l "$1" | grep -q "^ii"
}

## log messages
log() {
    echo "$(date +"%Y-%m-%d %T") $1" | sudo tee -a "$SCRIPT_LOG"
}

## Verify if script is executed as root 
if [ "$(id -u)" -ne 0 ]; then
    log "Error: Please re-run this script with sudo or as root."
    exit 1
fi

## check if a command executed successfully
check_success() {
    if [ $? -ne 0 ]; then
        log "Error: $1 failed. Exiting script."
        exit 1
    else
        log "$1 completed successfully."
    fi
}

## Exec extended, logging and checking command was good
exec_e() {
    "$@"
    check_success "$1"
}

## Update system 
echo "Updating SEC_system packages..."
exec_e apt update && exec_e apt upgrade -yy

## Install security tools (Podman, LXC, Firejail, etc.)
echo "Installing security tools..."
exec_e apt install -yy \
    podman \
    firejail \
    bubblewrap \
    ufw \
    fail2ban \
    clamav \
    lynis \
    apparmor apparmor-utils

## Check if Snap is installed install if not
if ! command -v snap &> /dev/null; then
    log "SNAP not found. Installing Snap..."
    exec_e sudo apt update
    exec_e sudo apt install -y snapd
fi

## Check if LXD is installed install if not
if ! command -v lxd &> /dev/null; then
    log "LXD not found. Installing LXD via Snap..."
    exec_e sudo snap install lxd
fi

## Optional**** If you still want to add the PPA (for apt-based installation):
if ! command -v lxd &> /dev/null; then
    log "Adding LXD PPA..."
    exec_e sudo apt install -y software-properties-common
    exec_e sudo add-apt-repository ppa:ubuntu-lxc/lxd-stable
    exec_e sudo apt update
    exec_e sudo apt install -y lxd
fi

## Enable AppArmor
echo "Enabling AppArmor..."
exec_e sudo systemctl enable --now apparmor

## Enable UFW  basic 
echo "Setting up UFW firewall..."
exec_e sudo ufw enable
exec_e sudo ufw default deny incoming
exec_e sudo ufw default allow outgoing

# Ask user if SSH is needed and on what port
read -p "Do you need SSH access? (y/n): " SSH_NEEDED
if [[ "$SSH_NEEDED" == "y" ]]; then
    read -p "Enter inbound port for SSH (default 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}  # Default to port 22 if not specified
    read -p "Enter outbound port for SSH (default 22): " SSH_OUT_PORT
    SSH_OUT_PORT=${SSH_OUT_PORT:-22}  # Default to port 22 if not specified
    echo "Allowing SSH inbound and outbound on port $SSH_PORT and $SSH_OUT_PORT"
    exec_e sudo ufw allow "$SSH_PORT"
    exec_e sudo ufw allow out "$SSH_OUT_PORT"
else
    echo "SSH access is disabled."
fi

## Fail2Ban
echo "Enabling Fail2Ban..."
exec_e sudo systemctl enable --now fail2ban

## ClamAV
echo "Setting up ClamAV..."
exec_e sudo freshclam
exec_e sudo clamscan -r / --log="$LOG_DIR/clamav_scan_$DATE.log"

## Lynis
echo "Running Lynis system audit..."
exec_e sudo lynis audit system | tee "$LOG_DIR/lynis_audit_$DATE.log"

## Podman 
echo "Setting up Podman for Firefox container..."
if ! is_package_installed podman; then
    echo "Podman not installed, installing..."
    exec_e sudo apt install -yy podman
fi

# Pull Firefox container image
echo "Pulling Firefox container image..."
exec_e sudo podman pull jess/firefox

# Run Firefox in a container with network isolation (trial, would say we need to containerize any web-based search engine if it's downloaded after the fact)
echo "Running Firefox in a container (network isolation)..."
exec_e sudo podman run -it --rm --net=none jess/firefox

## LXC/LXD containerization *all
echo "Setting up LXC/LXD containers..."
if ! is_package_installed lxd; then
    echo "LXD not installed, installing..."
    exec_e sudo apt install -yy lxd lxd-client
    exec_e sudo lxd init --auto
fi

# Create an LXC container for Firefox, only includes Firefox for now
echo "Creating LXC container for Firefox..."
exec_e sudo lxc launch ubuntu:20.04 firefox-container
exec_e sudo lxc exec firefox-container -- apt update && sudo apt install -yy firefox
exec_e sudo lxc exec firefox-container -- firefox

## Firejail sandboxing for applications (Firefox example but make this default for any post downloaded search engine)
echo "Setting up Firejail sandbox for Firefox..."
exec_e firejail
