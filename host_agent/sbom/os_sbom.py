# sbom.py
import os
import subprocess

def collect_linux_packages():
    packages = []
    try:
        if os.path.exists("/usr/bin/dpkg-query"):
            result = subprocess.run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                                    capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1]})
        elif os.path.exists("/usr/bin/rpm"):
            result = subprocess.run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"],
                                    capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1]})
    except Exception as e:
        print(f"[sbom] Linux package collection error: {e}")
    return packages
