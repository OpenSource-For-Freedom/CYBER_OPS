#!/bin/bash
# Print ASCII banner

# run persist: sudo bash kill_shell.sh --systemctl



echo "
  _  _____ _    _      ___ _  _ ___ _    _    
 | |/ /_ _| |  | |    / __| || | __| |  | |   
 | ' < | || |__| |__  \__ \ __ | _|| |__| |__ 
 |_|\_\___|____|____| |___/_||_|___|____|____|
------------------------------------------------                                          
A REVERSE SHELL DETECTION & PREVENTION SCRIPT
"





if [[ "$1" == "--help" ]]; then
    echo -e "Usage: $0 [--cron | --systemctl | --help]"
    echo -e "  --cron        Run scan and detection once (used by cron)"
    echo -e "  --systemctl   Install and start as a persistent systemd service"
    echo -e "  --help        Show this help message"
    exit 0
fi





LOG_FILE="/var/log/reverse_shell_attempts.log"
LOG_MAX=1000






install_dependencies() {
    REQUIRED_PKGS=(rustc iproute2 iptables awk cut tail wc grep cron)

    echo "[*] Checking and installing missing dependencies..."
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null; then
            echo "[+] Installing: $pkg"
            apt-get update -y && apt-get install -y "$pkg"
        else
            echo "[OK] $pkg is already installed."
        fi
    done
}


RUST_CODE=$(cat <<'EOF'
use std::fs;
use std::env;
use std::sync::mpsc::channel;
use std::thread;
use std::process::Command;

fn main() {
    if !is_root() {
        eprintln!("This program must be run as root.");
        std::process::exit(1);
    }

    let args: Vec<String> = env::args().collect();
    let dir_to_scan = args.get(1).unwrap_or(&"/tmp".to_string());
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
                                    let _ = tx.send(format!(
                                        "Suspicious file detected: {} (contains: {})",
                                        path.display(),
                                        pattern
                                    ));
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    drop(tx);
    for message in rx {
        println!("{}", message);
    }
}

fn is_root() -> bool {
    match Command::new("id").arg("-u").output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim() == "0",
        Err(_) => false,
    }
}
EOF
)


run_rust_scanner() {
    echo "$RUST_CODE" > /tmp/scanner.rs
    rustc /tmp/scanner.rs -o /tmp/scanner
    /tmp/scanner /tmp >> "$LOG_FILE"
    rm -f /tmp/scanner.rs /tmp/scanner
}


monitor_connections() {
    ss -tunp | grep -E 'ESTAB.*(bash|sh|nc|perl|python|php)' | while read -r line; do
        echo "$(date): Suspicious connection detected: $line" >> "$LOG_FILE"
        SRC_IP=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
        echo "$(date): Blocking IP: $SRC_IP" >> "$LOG_FILE"
        iptables -C INPUT -s "$SRC_IP" -j DROP 2>/dev/null || iptables -A INPUT -s "$SRC_IP" -j DROP
    done
}


trim_log() {
    if [ $(wc -l < "$LOG_FILE") -gt "$LOG_MAX" ]; then
        tail -n "$LOG_MAX" "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
}


check_logs() {
    echo -e "\n--- Last 10 entries ---"
    tail -n 10 "$LOG_FILE"
    echo -e "------------------------\n"
}


schedule_cron() {
    (crontab -l 2>/dev/null; echo "*/30 * * * * /bin/bash $0 --cron") | crontab -
    echo "$(date): Script scheduled to run every 30 minutes via cron." >> "$LOG_FILE"
}


install_systemd_service() {
    SERVICE_FILE="/etc/systemd/system/kill_shell.service"

    echo "[*] Creating systemd service at $SERVICE_FILE..."

    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Reverse Shell Detector and Blocker
After=network.target

[Service]
ExecStart=/bin/bash $0 --cron
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl enable kill_shell.service
    systemctl start kill_shell.service

    echo "$(date): kill_shell systemd service installed and started." >> "$LOG_FILE"
}

# MAIN 
main() {
    install_dependencies
    monitor_connections
    run_rust_scanner
    trim_log
    check_logs
}


case "$1" in
    --cron)
        main
        ;;
    --systemctl)
        install_dependencies
        install_systemd_service
        ;;
    *)
        install_dependencies
        schedule_cron
        echo "Script scheduled via cron. Logs will be updated every 30 minutes."
        ;;
esac