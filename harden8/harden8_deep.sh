#!/bin/bash
set -euo pipefail

## Logging function
LOG_FILE="/var/log/harden8_deep.log"
log() {
    echo "$(date +"%Y-%m-%d %T") $1" | sudo tee -a "$LOG_FILE"
}

## Disable core dumps
disable_core_dumps() {
    log "Disabling core dumps..."
    if ! grep -q '^\* hard core 0;' /etc/security/limits.conf; then
        echo '* hard core 0' | sudo tee -a /etc/security/limits.conf
        log "Core dumps disabled successfully."
    else
        log "Core dumps already disabled."
    fi
}

## Configure TCP Wrappers and access controls
configure_tcp_wrappers() {
    log "Configuring TCP Wrappers and access controls..."

    # Deny all by default
    if ! grep -q '^ALL: ALL' /etc/hosts.deny; then
        echo "ALL: ALL" | sudo tee -a /etc/hosts.deny
        log "All connections denied by default."
    else
        log "Default deny rule already set in /etc/hosts.deny."
    fi

    # Deny SSH by default (optional: customize as needed)
    if ! grep -q '^sshd: ALL' /etc/hosts.deny; then
        echo "sshd: ALL" | sudo tee -a /etc/hosts.deny
        log "SSH denied by default in /etc/hosts.deny."
    else
        log "SSH deny rule already set in /etc/hosts.deny."
    fi

    # Configure non-local login restrictions
    if ! grep -q '^-:ALL:ALL EXCEPT LOCAL' /etc/security/access.conf; then
        echo "-:ALL:ALL EXCEPT LOCAL" | sudo tee -a /etc/security/access.conf
        log "Non-local login restrictions configured."
    else
        log "Non-local login restriction already set."
    fi
}

## Main Execution
log "Starting harden8_deep hardening script."

disable_core_dumps
configure_tcp_wrappers
## Potentially add more deep hardening features ahead

log "harden8_deep Hardening complete."
echo "harden8_deep Hardening complete. Logs stored in $LOG_FILE."
