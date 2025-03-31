import subprocess
import os
import sys


def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)







def run_script(script_name):
    subprocess.Popen(['python3', script_name])

if __name__ == "__main__":
    check_root()
    

    kill_verify_script = 'path/to/kill_VeriFY.py'
    kill_crack_script = 'path/to/kill_crack.py'


    run_script(kill_verify_script)
    run_script(kill_crack_script)

    print("Both kill_VeriFY.py and kill_crack.py are running in the background.")