#!/bin/bash
# Print an ASCII banner
echo "
  _  _____ _    _      ___ _  _ ___ _    _    
 | |/ /_ _| |  | |    / __| || | __| |  | |   
 | ' < | || |__| |__  \__ \ __ | _|| |__| |__ 
 |_|\_\___|____|____| |___/_||_|___|____|____|
------------------------------------------------                                          
A REVERSE SHELL DETECTION & PREVENTION SCRIPT
"

# Log file to store detected reverse shell attempts
LOG_FILE="/var/log/reverse_shell_attempts.log"

# RUST directory scanning - multithreading
RUST_CODE=$(cat <<'EOF'
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::channel;
use std::thread;
use std::process::Command;

fn main() {
    // Ensure the program is running as root
    if !is_root() {
        eprintln!("This program must be run as root.");
        std::process::exit(1);
    }

    let dir_to_scan = "/tmp"; // Directory to scan for suspicious files
    let suspicious_patterns = ["bash", "sh", "nc", "perl", "python", "php"];
    let (tx, rx) = channel();

    if let Ok(entries) = fs::read_dir(dir_to_scan) {
        for entry in entries {
            let tx = tx.clone();
            thread::spawn(move || {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(content) = fs::read_to_string(&path) {
                            for pattern in &suspicious_patterns {
                                if content.contains(pattern) {
                                    tx.send(format!(
                                        "Suspicious file detected: {} (contains: {})",
                                        path.display(),
                                        pattern
                                    ))
                                    .unwrap();
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    drop(tx); // Close the sending side
    for message in rx {
        println!("{}", message);
    }
}

// Function to check if the program is running as root
fn is_root() -> bool {
    match Command::new("id").arg("-u").output() {
        Ok(output) => {
            if let Ok(uid) = String::from_utf8(output.stdout) {
                return uid.trim() == "0";
            }
        }
        Err(_) => {}
    }
    false
}
EOF
)

# Function to compile and run the Rust directory scanner
run_rust_scanner() {
    echo "$RUST_CODE" > /tmp/scanner.rs
    rustc /tmp/scanner.rs -o /tmp/scanner
    /tmp/scanner >> "$LOG_FILE"
    rm -f /tmp/scanner.rs /tmp/scanner
}

# Function to monitor network connections for reverse shell attempts
monitor_connections() {
    netstat -tunp | grep -E 'ESTABLISHED.*(bash|sh|nc|perl|python|php)' | while read -r line; do
        echo "$(date): Suspicious connection detected: $line" >> "$LOG_FILE"
        # Extract the source IP address
        SRC_IP=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
        echo "$(date): Blocking IP: $SRC_IP" >> "$LOG_FILE"
        # Block the source IP using iptables
        iptables -A INPUT -s "$SRC_IP" -j DROP
    done
}

# check  log file for new attempts
check_logs() {
    tail -n 10 "$LOG_FILE"
}

# Schedule the script using cron
schedule_cron() {
    (crontab -l 2>/dev/null; echo "*/30 * * * * /bin/bash $0") | crontab -
    echo "$(date): Script scheduled to run every 30 minutes via cron." >> "$LOG_FILE"
}

# Main function
main() {
    monitor_connections
    run_rust_scanner
    check_logs
}

# Check if the script is being run manually or via cron
if [[ "$1" == "--cron" ]]; then
    main
else
    schedule_cron
    echo "Script scheduled via cron. Logs will be updated every 30 minutes."
fi