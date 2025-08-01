import subprocess

def run_minimega(script_path="launch_vms.mm"):
    with open(script_path, "r") as script:
        subprocess.run(["sudo", "minimega"])