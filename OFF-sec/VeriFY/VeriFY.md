## "VeriFY" a new format using Open Source Network Scanning tools. 
```
<center>

 ▄█    █▄     ▄████████    ▄████████  ▄█     ▄████████ ▄██   ▄   
███    ███   ███    ███   ███    ███ ███    ███    ███ ███   ██▄ 
███    ███   ███    █▀    ███    ███ ███▌   ███    █▀  ███▄▄▄███ 
███    ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ ███▌  ▄███▄▄▄     ▀▀▀▀▀▀███ 
███    ███ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   ███▌ ▀▀███▀▀▀     ▄██   ███ 
███    ███   ███    █▄  ▀███████████ ███    ███        ███   ███ 
███    ███   ███    ███   ███    ███ ███    ███        ███   ███ 
 ▀██████▀    ██████████   ███    ███ █▀     ███         ▀█████▀  
                          ███    ███        

</center>
```

**This is the Linux (Unix) file space for endpoint, Server and Sandbox testing and Development**
```
mkdir "network_scans"
```
Don't forget to:
```
sudo apt update && sudo apt full-upgrade -y
```
**PROJECT SCOPE**
---
***P1: VeriFY**
---
The goal in developing this python file is to quickly deploy an internal or external Network Scanning package for Linux Based OS, that outputs the results in a report format onto the users desktop or selected file path. 
---
1. The File imports necessary modules such as os, nmap, csv, time, and pythonping.
2. It will set some constants, including the target IP, Nmap file path, and the output directory for the scan results, which will be edited to allow more user interface.
3. It defines a function to ping the target IP address and check for its reachability.
4. Defines a function to prompt the user for confirmation before proceeding.
5. Defines a function to execute Nmap scans with provided arguments and save the results to CSV files.
6. Checks the reachability of the target IP using the ping_target function.
7. Asks the user for confirmation to proceed using the ask_user_confirmation function.
8. Runs several Nmap scans with different arguments, saves the results to CSV files, and waits until the scans are completed to prduced a legible report of the results.
9. Adding feature: will be inputing a funciotn to update the user on the scan status and any roadblocks. 
10. Includes placeholders for capturing and analyzing network packets using dpkt and saving the analysis results to a separate CSV file.
11. Prints messages based on the script execution status.
---
In a short output upon entering the target IP it determine if the IP is up and live, it then will supply a question asking "1 or 2" to proceed. 
This function will need further development to encap a better output result for the user to understand which direciotn to go based uppn the initial ICMP result. 
