# sbom.py
import os
import subprocess
import platform
from datetime import datetime

def detect_os_metadata():
    os_info = {"name": "unknown", "version": "unknown"}
    try:
        if platform.system() == "Windows":
            os_info["name"] = "windows"
            os_info["version"] = platform.version()
        elif os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        os_info["name"] = line.strip().split("=", 1)[1].strip('"')
                    elif line.startswith("VERSION_ID="):
                        os_info["version"] = line.strip().split("=", 1)[1].strip('"')
    except Exception as e:
        print(f"[sbom] Failed to parse /etc/os-release: {e}")
    return os_info

def collect_linux_packages():
    packages = []
    try:
        if os.path.exists("/usr/bin/dpkg-query"):
            result = subprocess.run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                                    capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "type": "deb"
                    })
        elif os.path.exists("/usr/bin/rpm"):
            result = subprocess.run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"],
                                    capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "type": "rpm"
                    })
    except Exception as e:
        print(f"[sbom] Linux package collection error: {e}")
    return packages

def normalize_purl(name: str, version: str) -> str:
    slug = re.sub(r'[^a-zA-Z0-9\-\.]+', '-', name.strip().lower()).strip('-')
    return f"pkg:generic/{slug}@{version.strip()}"

def collect_windows_packages():
    import winreg

    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    packages = []

    for hive, path in registry_paths:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            packages.append({
                                "name": name,
                                "version": version,
                                "type": "windows"
                            })
                    except Exception:
                        continue
        except Exception:
            continue
    
    return packages
    
def collect_packages():
    if platform.system() == "Windows":
        return collect_windows_packages()
    else:
        return collect_linux_packages()

def generate_cyclonedx_sbom(packages, tool_name="host-agent", tool_version="0.1.0"):
    os_info = detect_os_metadata()
    timestamp = datetime.utcnow().isoformat(timespec='seconds') + "Z"

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "operating-system",
                "name": os_info["name"],
                "version": os_info["version"]
            },
            "tools": [
                {
                    "vendor": "custom",
                    "name": tool_name,
                    "version": tool_version
                }
            ]
        },
        "components": []
    }

    for pkg in packages:
        purl_type = "deb" if pkg.get("type") == "deb" else "rpm"
        purl = f"pkg:{purl_type}/{os_info['name']}/{pkg['name']}@{pkg['version']}"
        sbom["components"].append({
            "type": "application",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": purl
        })

    return sbom
