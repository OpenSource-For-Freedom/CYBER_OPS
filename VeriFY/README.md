# VeriFy - The Network Security Project

## Overview
VeriFy is a network security project designed to enhance security through automation, containerization, and system protection measures. It provides tools for network scanning, packet analysis, and security auditing to ensure system integrity.

## Features
- **Nmap Port Scanning:** Performs network scanning to detect open ports and services.
- **Packet Analysis:** Analyzes network traffic using PCAP files.
- **Automated Security Checks:** Uses various tools to validate network security status.
- **Graphical User Interface (GUI):** Provides an intuitive interface for users to conduct security scans.

## Installation
### Prerequisites
Ensure you have the following dependencies installed before running VeriFy:

- Python 3.x
- `nmap`
- `dpkt`
- `pythonping`
- `tkinter`

You can install the necessary dependencies using:
```sh
pip install python-nmap dpkt pythonping
```

### Running VeriFy
To start the application, run the following command:
```sh
python verify.py
```

## Usage
### 1. Running a Network Scan
- Input the target IP address.
- Select an output directory to save scan results.
- Click **Start Scan** to begin the process.

### 2. Packet Analysis
- After scanning, you will be prompted to upload a PCAP file.
- VeriFy will analyze packet data and display results.

### 3. Admin Privileges
VeriFy must be run with administrative privileges to access network scanning tools.
```sh
sudo python verify.py
```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author
**Tim "TANK" Burns**

