import subprocess
import os
import argparse

def run_minimega_script(script_path: str):
    """
    Run each command from a minimega script file using "minimega -e"
    """
    if not os.path.isfile(script_path):
        raise FileNotFoundError(f"Script not found: {script_path}")
    
    with open(script_path, "r") as script_file:
        for line in script_file:
            command = line.strip()
            if not command or command.startswith("#"):
                continue # skip empty lines and comments
            print(f"[+] Running: {command}")
            result = subprocess.run(
                ["sudo", "minimega", "-e", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.stderr.strip():
                print("[stderr]", result.stderr.strip())

def main():
    parser = argparse.ArgumentParser(description="Run MiniMega commands from a .mm script")
    parser.add_argument(
        "script",
        help = "Path to the .mm script file to execute"
    )

    args = parser.parse_args()
    run_minimega_script(args.script)


if __name__ == "__main__":
    main()