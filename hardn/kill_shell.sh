#!/bin/bash

SCRIPT_NAME="kill_shell.sh"
SCRIPT_PATH="/usr/local/bin/$SCRIPT_NAME"
LOG_FILE="/var/log/reverse_shell_watch.log"
CRON_JOB="* * * * * root $SCRIPT_PATH"

# Write the detect + kill logic to file
write_kill_script() {
    sudo tee "$SCRIPT_PATH" > /dev/null << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/reverse_shell_watch.log"

echo "[$(date)] Running reverse shell scan..." >> $LOG_FILE

# Kill bash shells via /dev/tcp
for pid in $(ps aux | grep '[b]ash -i' | grep '/dev/tcp' | awk '{print $2}'); do
    echo "[$(date)] Killing suspicious bash reverse shell: PID $pid" >> $LOG_FILE
    kill -9 "$pid"
    logger "[SECURITY] Killed suspicious bash reverse shell (PID $pid)"
done

# Kill Netcat shells piping to bash
for pid in $(ps aux | grep '[n]c' | grep '/bin/bash' | awk '{print $2}'); do
    echo "[$(date)] Killing suspicious netcat reverse shell: PID $pid" >> $LOG_FILE
    kill -9 "$pid"
    logger "[SECURITY] Killed suspicious Netcat reverse shell (PID $pid)"
done
EOF

    sudo chmod +x "$SCRIPT_PATH"
}

# Set up cron job
install_cron_job() {
    if ! sudo grep -q "$SCRIPT_PATH" /etc/crontab; then
        echo "Installing cron job..."
        echo "$CRON_JOB" | sudo tee -a /etc/crontab > /dev/null
    else
        echo "Cron job already exists."
    fi
}

# Run setup
write_kill_script
install_cron_job

echo "Reverse shell defense script installed and scheduled via cron."