
<p align="center">
    <img src="Images/octocat-1736601186918.png">
</p>

##                                       ***Developer: Tim Burns***
##                                   

# **The Linux + DevSec Project**  


---



### **HARDN** - A single Linux package to sandbox a Debian OS and support systems, both endpoint and server.



### **CRACK** - a single WPA cracking tool to ensure your wifi is secure


                                                            

### **VeriFy** - A NEt Scanning tool that enumerates open ports, using dpkt and outputs that report on a file path for pen testers and red team members. 



---
# **Overview**  

In the development of this repository, we aim to include all facets of **kernel hardening**, **penetration testing**, and **OS security** for Debian Linux systems, ensuring both security and stability.

This document outlines the pre-release activities that need to be completed before finalizing the project release. These tasks are designed to reinforce security, improve performance, and streamline user management.

By following these guidelines, you will enhance system security, maintain stability, and optimize Debian-based systems for performance and resilience.

---

# HARDN "The first Takeoff 🚀
## The Primary Focus prior to testing Exterior Attacks

## **Pre-Release Activities & Research**

### **System Hardening Research**

- **Review and analyze hardening scripts**  
  Study system-hardening scripts like **harbian-audit** to identify security best practices.  
  **Objective:** Adopt tested hardening methods for better security.  

### **Permission Security**  

- **Evaluate special permissions**  
  Permissions like `setuid`, `setgid`, and `sticky` can be a security risk.  
  **Objective:** Remove unnecessary permissions while ensuring system stability.  

### **User Group Configuration**  

- **Console User Group Analysis in Whonix**  
  Investigate **Whonix's** console user groups to improve security management.  
  **Objective:** Reduce the risk of privilege escalation.  
  - a huge thank you to @kiukiucat for adding this. 

---


Tool,Description
- Lynis,Security auditing tool for Unix-based systems.
- Fail2Ban,Protects against brute-force attacks.
- UFW,Easy-to-configure firewall utility.
- AppArmor,Mandatory Access Control (MAC) for enforcing policies.
- ClamAV,(or our own tool) Open-source antivirus software.
- Firejail,Sandboxing tool for application isolation.

<p align="center">
    <img src="octocat-1736601186918.png">
</p>


<p align="center">
    <img src="https://t.bkit.co/w_67775e3ddda15.gif">
</p>




