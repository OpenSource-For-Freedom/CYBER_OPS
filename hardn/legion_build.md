legion/
│── src/                        # Source code directory
│   │── main.c                  # Core Legion scanning engine
│   │── scanner.rs              # Rust-based high-performance scanner
│   │── yara_integrations.c      # YARA & ClamAV scanner
│   │── ebpf_monitor.bpf.c       # eBPF-based real-time monitoring
│   │── api.c                    # Handles API requests for logging
│── include/                     # Header files for modularity
│   │── legion.h                 # Common definitions & function prototypes
│   │── yara.h                   # YARA scanner headers
│── dashboard/                   # Web-based dashboard
│   │── server.py                # Flask API for scan results
│   │── static/                   # Frontend UI files
│   │── templates/                # HTML templates
│── data/                        # Malware signatures & configurations
│   │── signatures.txt           # Legion signature database
│   │── whitelist.txt            # Whitelisted files
│   │── rules.yar                # YARA rules
│── scripts/                     # Utility scripts
│   │── update_signatures.sh     # Auto-update malware signatures
│   │── install.sh               # Automated installer script
│── tests/                       # Test cases for validation
│── docs/                        # Documentation files
│   │── README.md                # Overview & setup instructions
│   │── INSTALL.md               # Installation guide
│   │── INTEGRATIONS.md          # List of Legion integrations
│── config/                      # Config files
│   │── legion.conf              # Main configuration file
│── Makefile                     # Automates compilation & linking
│── LICENSE                      # Open-source license
│── .gitignore                   # Ignore unnecessary files