

# HARDN - The Linux Security Project  
**A secure approach to system hardening on Debian-based Linux.**  

HARDN is built for those who **take security seriously** but don't want to spend hours configuring their system manually. It locks down essential security settings, automates safe networking, and ensures system integrity with **just a few commands**.
> "Made by a Marine, for everyone" Tim Says
---

## Table of Contents
- [What HARDN Does](#what-hardn-does)
- [Getting Started](#getting-started)
- [How the Files Work](#how-the-files-work)
- [Customization](#customization)
- [Contributing](#contributing)
- [License](#license)

---

## What HARDN Does
- **Hardens your system automatically** by setting up a firewall, securing permissions, and blocking unnecessary services.
- **Gives you control** over deeper security features like TOR-based routing (`HARDN_QUBE`) and full system lockdown (`HARDN_DARK`).
- **Provides a user-friendly interface** so you can enable or disable features as needed.
- **Ensures safer web downloads** by verifying files before execution.

---

## Getting Started

### 1. Clone the Repository
```git clone https://github.com/YOUR_GITHUB_USERNAME/HARDN.git
```
    cd HARDN
```
2. Install Dependencies

### You’ll need Python 3 and pip installed. Then run:
```
      pip install -r requirements.txt
```
3. Install HARDN as a System Command
```
      pip install -e .
```
### This allows you to run HARDN anywhere with:
```
      hardn
```
4. Run HARDN

### For the graphical interface:
```
      hardn
```
### For the command-line version:
```
    python3 hardn/hardn.py
```
### How the Files Work

HARDN is split into modules, each handling different security aspects.

### File	Purpose
hardn.py	The main script that starts the GUI and runs basic system hardening.
hardn_qubes.py	Routes network traffic through TOR and sandboxes browser activity for extra anonymity.
hardn_dark.py	Deep lockdown: disables USB, locks down permissions, and restricts non-local logins.
secure_download.py	Ensures safe web downloads by verifying every file before execution.
hardn_tk.py	Handles the GUI components for HARDN.
setup.py	Allows you to install HARDN as a package so it runs like a regular system command.
requirements.txt	Lists all necessary dependencies.

### Customization

**Want to modify security settings?**
	•	Firewall rules: Edit configure_firewall() in hardn.py.
	•	TOR-based routing: Modify hardn_qubes.py.
	•	USB blocking: Can be toggled in the GUI or by modifying hardn_dark.py.