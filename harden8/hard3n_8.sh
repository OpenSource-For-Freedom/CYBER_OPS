#!/bin/bash
## Harden and sandbox Debian Linux

set -euo pipefail

## Root check
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Please run this script as root or with sudo."
    exit 1
fi

## Logging setup
LOG_DIR="/var/log/security_scans"
DATE=$(date +"%Y%m%d_%H%M%S")
SCRIPT_LOG="$LOG_DIR/script_execution_$DATE.log"

mkdir -p "$LOG_DIR"
echo "Starting hardening and sandboxing script at $(date)" | tee -a "$SCRIPT_LOG"

log() {
    echo "$(date +"%Y-%m-%d %T") $1" | tee -a "$SCRIPT_LOG"
}

## Check command success
check_success() {
    if [ $? -ne 0 ]; then
        log "Error: $1 failed. Exiting script."
        exit 1
    else
        log "$1 completed successfully."
    fi
}

exec_e() {
    "$@"
    check_success "$1"
}

## Basic kernel hardening with AppArmor and GRUB configuration
log "Applying kernel-level security settings."
exec_e "cp -Rv ./etc/default/grub.d/* /etc/default/grub.d"
if command -v update-grub &>/dev/null; then
    exec_e update-grub
else
    exec_e grub-mkconfig -o /boot/grub/grub.cfg
fi

echo "System will restart in 10 seconds if you do not cancel with Ctrl+C."
sleep 10
exec_e reboot

## Package check
is_package_installed() {
    dpkg -l "$1" | grep -q "^ii"
}

## Sandbox APT configurations
log "Configuring APT sandboxing and reducing install recommendations."
echo 'APT::Sandbox::Seccomp "true";' | tee /etc/apt/apt.conf.d/01seccomp
echo -e 'APT::AutoRemove::RecommendsImportant "false";\nAPT::Install-Recommends "0";\nAPT::Install-Suggests "0";' | tee /etc/apt/apt.conf.d/01defaultrec

## Update and minimal install for necessary packages
exec_e apt update

## UFW installation and configuration
if ! is_package_installed ufw; then
    exec_e apt install -yy ufw --no-install-recommends --no-install-suggests
    exec_e ufw enable
    exec_e ufw default deny incoming
    exec_e systemctl --now enable ufw
    exec_e ufw reload
fi

## Additional security tools installation
log "Installing additional security tools for enhanced monitoring and control."
PACKAGES=("clamav" "rkhunter" "chkrootkit" "fail2ban" "lynis" "aide" "apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils" "firejail" "bubblewrap")
for package in "${PACKAGES[@]}"; do
    if ! is_package_installed "$package"; then
        exec_e apt install -yy $package --no-install-recommends --no-install-suggests
    fi
done

log "Security tools installed successfully."

## Firejail sandboxing
log "Applying sandboxing for selected applications using Firejail."
FIREJAIL_APPS=("firefox" "curl" "wget")
for app in "${FIREJAIL_APPS[@]}"; do
    if command -v "$app" &>/dev/null; then
        exec_e ln -sf /usr/bin/firejail "/etc/firejail/$app.profile"
    fi
done

## AppArmor configurations
log "Applying AppArmor policies."
exec_e apparmor_parser -r /etc/apparmor.d/*

## AIDE initialization
if [ ! -f /var/lib/aide/aide.db ]; then
    log "Initializing AIDE database."
    exec_e aideinit -y -f
fi

## Configure fail2ban for brute force protection
log "Setting up fail2ban configurations."
if [ -f /etc/fail2ban/jail.local ]; then
    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
fi

cat <<EOF | tee /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF

exec_e systemctl restart fail2ban

## External hardening script execution
source harden8_deep.sh
if [ $? -ne 0 ]; then
    log "Error: harden8_deep.sh did not run successfully."
    exit 1
else
    log "harden8_deep.sh dependency ran successfully."
fi

## Run security scans
exec_e clamscan -r / --log="$LOG_DIR/clamav_scan_$DATE.log"
exec_e rkhunter --cronjob --update --quiet
exec_e chkrootkit | tee "$LOG_DIR/chkrootkit_scan_$DATE.log"

log "Daily security scans completed. Logs stored in $LOG_DIR"