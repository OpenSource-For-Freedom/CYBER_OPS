# still in R&D

import argparse
import subprocess
import os
import logging
# proposing to run headkess gor server and cloud based function, and to call Legion at a 24hr mark using cron
# LOGS 
logging.basicConfig(filename='hardn.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_legion(): # shooting for 24hr rotatiin and automated scanning and runs on systemd, but doesnt act on contact yet...
    """Run Legion scan."""
    legion_path = "./legion"

    if not os.path.exists(legion_path):
        logging.error("Legion executable not found.")
        return

    logging.info("Starting Legion scan...")
    subprocess.run([legion_path])
    logging.info("Legion scan completed.")

def run_qube(): # run qubes after a succesful scan 
    """Run HARDN_Qube security mode."""
    logging.info("Running HARDN_Qube...")
    subprocess.run(["python3", "hardn_qube.py"])
    logging.info("HARDN_Qube execution complete.")

def run_dark(): # run dark with tcp wrappers and verifying full lockdown mode 
    """Run HARDN_Dark mode."""
    logging.info("Running HARDN_Dark...")
    subprocess.run(["python3", "hardn_dark.py"])
    logging.info("HARDN_Dark execution complete.")

def main():
    parser = argparse.ArgumentParser(description="HARDN Security Hardening CLI")
    parser.add_argument("--qube", action="store_true", help="Run HARDN_Qube mode")
    parser.add_argument("--dark", action="store_true", help="Run HARDN_Dark mode")
    parser.add_argument("--legion", action="store_true", help="Run Legion malware scan")

    args = parser.parse_args()

    logging.info("Launching HARDN...")
# dependancies 
    if args.qube:
        run_qube()
    elif args.dark:
        run_dark()
    elif args.legion:
        run_legion()
    else:
        logging.info("No mode selected. Running full HARDN process.")
        run_qube()
        run_dark()
        run_legion()

    logging.info("HARDN complete.")

if __name__ == "__main__":
    main()
