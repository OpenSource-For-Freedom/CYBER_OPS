# SCOPE.md

## HARDN Security Scope

HARDN is designed to be a comprehensive Linux security framework, functioning as an "Autopilot" for system hardening, attack surface prevention, and availability assurance. The goal is to mitigate a wide range of cyber threats by leveraging cutting-edge security tools and methodologies.

## Attack Vectors Mitigated
### 1. **Network-based Attacks**
- Denial-of-Service (DDoS)
- Man-in-the-Middle (MITM)
- Packet sniffing & spoofing
- Unauthorized remote access

### 2. **Malware & Virus Threats**
- Trojans, worms, and ransomware
- Rootkits and hidden persistence mechanisms
- Supply chain attacks targeting software dependencies
- File-based and memory-resident threats

### 3. **Privilege Escalation & Exploits**
- Kernel exploits
- Misconfigured sudo and privilege escalations
- Code execution vulnerabilities (buffer overflows, RCE)
- Process injection and hijacking

### 4. **Container & Virtual Machine Security**
- Container escape attacks
- Privilege abuse within Kubernetes and Docker environments
- Misconfigured VM access policies
- Unauthorized resource consumption and lateral movement

### 5. **Data Exfiltration & Unauthorized Access**
- Insider threats and credential theft
- Side-channel attacks
- Unauthorized API and database access
- Endpoint data leakage and unauthorized file transfers

## **Current Tools and Tools to come**

HARDN integrates industry-leading security tools to enforce protections against these threats:

|------------Tool--------|--------------Purpose--------------------|
|------------------------|-----------------------------------------|
# Current Debian Packages & Applications Used in HARDN

### Core Security Packages
- `suricata` – Network-based intrusion detection/prevention
- `ossec-hids-agent` – Host-based intrusion detection system
- `wazuh-agent` – Security monitoring and compliance
- `clamav` – Antivirus scanning
- `fail2ban` – Intrusion prevention for SSH & web services
- `tor` – Anonymity and traffic obfuscation
- `ufw` – Firewall management (simplified `iptables`)
- `apparmor` – Mandatory access control system
- `auditd` – System auditing and security monitoring

### Network & Traffic Control
- `iptables` – Packet filtering and NAT
- `firewalld` – Dynamic firewall management
- `wireguard` – Secure VPN tunneling
- `tcpdump` – Network packet analysis
- `nmap` – Network scanning and reconnaissance
- `net-tools` – Network troubleshooting utilities
- `dnsmasq` – Local DNS resolution and DHCP

### Malware & Threat Detection
- `rkhunter` – Rootkit detection
- `chkrootkit` – Rootkit scanning tool
- `lynis` – System auditing and security scanning
- `legion` – Custom malware scanner (HARDN-specific)
- `clamtk` – GUI frontend for ClamAV

### Container & Virtualization Security
- `docker` – Containerized application management
- `podman` – Rootless container engine
- `qemu-kvm` – Virtual machine emulation
- `virt-manager` – GUI for managing KVM VMs
- `seccomp` – Secure computing mode for containers

### System Hardening & Utilities
- `grsecurity` – Kernel-level security patches
- `auditd` – System auditing and logging
- `logwatch` – Log analysis and reporting
- `unattended-upgrades` – Automated security updates
- `tripwire` – Integrity monitoring and intrusion detection
- `selinux-utils` – SELinux policy enforcement

### Hardn_Dark Additional Packages
- `crowdsec` – Collaborative security threat detection
- `open-snitch` – Application firewall for outbound connections
- `bpfcc-tools` – eBPF-based security monitoring
- `falco` – Runtime security monitoring for containers
- `grml-rescueboot` – Secure boot recovery environment

This list covers the core Debian packages and security applications integrated into **HARDN** and **HARDN_DARK** for robust Linux hardening.

## Future Enhancements
HARDN will continue evolving to enhance security for modern infrastructure, including:
- **Containerized management for isolated workloads**
- **Virtual machine automation for threat mitigation**
- **Legion control enhancements for expanded scanning and real-time reporting**
- **LegionFACT for vulnerability detection in source code**
- **Agentless security monitoring for VMs and Kubernetes environments**
- **Centralized security dashboard for streamlined visibility**

HARDN aims to simplify security without sacrificing protection, providing a robust framework for securing Linux environments.
