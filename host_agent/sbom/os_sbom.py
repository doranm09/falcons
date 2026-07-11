# sbom.py
import os
import re
import platform
import shutil
import subprocess
from datetime import datetime
from urllib.parse import quote as urlquote
import uuid

def detect_os_metadata():
    """
    Returns a dict like {"name": "ubuntu", "version": "22.04"} or {"name": "windows", "version": "10.0.22631"}
    """
    os_info = {"name": "unknown", "version": "unknown"}
    try:
      sys = platform.system()
      if sys == "Windows":
          os_info["name"] = "windows"
          # platform.version() is fine; win32_ver gives more fields if you want them
          os_info["version"] = platform.version()
      elif os.path.exists("/etc/os-release"):
          with open("/etc/os-release", encoding="utf-8") as f:
              for line in f:
                  if line.startswith("ID="):
                      os_info["name"] = line.strip().split("=", 1)[1].strip().strip('"')
                  elif line.startswith("VERSION_ID="):
                      os_info["version"] = line.strip().split("=", 1)[1].strip().strip('"')
    except Exception as e:
        print(f"[sbom] Failed to parse OS metadata: {e}")
    return os_info

def collect_linux_packages():
    """
    Returns list of dicts: {"name": str, "version": str, "type": "deb"|"rpm"|"apk"}
    """
    packages = []
    try:
        if os.path.exists("/usr/bin/dpkg-query"):
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1], "type": "deb"})
        elif os.path.exists("/usr/bin/rpm"):
            result = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1], "type": "rpm"})
        else:
            apk_path = shutil.which("apk")
            if not apk_path:
                for candidate in ("/sbin/apk", "/usr/sbin/apk", "/bin/apk", "/usr/bin/apk"):
                    if os.path.exists(candidate):
                        apk_path = candidate
                        break
            if not apk_path:
                return packages
            result = subprocess.run(
                [apk_path, "info", "-v"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                package_text = line.strip()
                if not package_text or package_text.startswith("WARNING:"):
                    continue
                match = re.match(r"^(?P<name>.+)-(?P<version>\d[^\\s]*)$", package_text)
                if not match:
                    continue
                packages.append({
                    "name": match.group("name"),
                    "version": match.group("version"),
                    "type": "apk",
                })
    except Exception as e:
        print(f"[sbom] Linux package collection error: {e}")
    return packages

def collect_windows_packages():
    """
    Returns list of dicts: {"name": str, "version": str, "type": "windows"}
    """
    packages = []
    try:
        import winreg
    except Exception:
        # Not on Windows, or winreg unavailable
        return packages

    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in registry_paths:
        try:
            with winreg.OpenKey(hive, path) as key:
                subkey_count = winreg.QueryInfoKey(key)[0]
                for i in range(subkey_count):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            if name and version:
                                packages.append({"name": name, "version": version, "type": "windows"})
                    except Exception:
                        continue
        except Exception:
            continue
    return packages

def collect_packages():
    if platform.system() == "Windows":
        return collect_windows_packages()
    return collect_linux_packages()

# ---------- PURL helpers ----------

_RPM_DISTROS = {"rhel", "centos", "rocky", "almalinux", "fedora", "sles", "opensuse", "opensuse-leap"}
_DEB_DISTROS = {"debian", "ubuntu", "raspbian", "linuxmint", "kali"}
_APK_DISTROS = {"alpine"}

def _slugify_name_for_purl(name: str) -> str:
    """
    Produce a lower-cased, URL-escaped name suitable for purl path segment.
    We keep alphanum, dot, dash, plus underscore; replace others with dash before quoting,
    then percent-encode any remaining unsafe chars just in case.
    """
    base = re.sub(r"[^A-Za-z0-9._+-]+", "-", name.strip().lower()).strip("-")
    return urlquote(base, safe="._+-")  # keep these unescaped

def make_purl(pkg: dict, os_info: dict) -> str:
    """
    Create a best-effort valid purl for the package and host OS.
    - deb:   pkg:deb/<distro>/<name>@<version>
    - rpm:   pkg:rpm/<distro>/<name>@<version>   (distro optional if unknown)
    - apk:   pkg:apk/<distro>/<name>@<version>
    - windows/other: pkg:generic/<name>@<version>
    """
    name = _slugify_name_for_purl(pkg.get("name", "unknown"))
    version = str(pkg.get("version", "")).strip() or "unknown"

    ptype = pkg.get("type")
    distro = os_info.get("name", "unknown").lower()

    if ptype == "deb":
        ns = distro if distro in _DEB_DISTROS else None
        return f"pkg:deb/{ns + '/' if ns else ''}{name}@{urlquote(version, safe='')}"
    elif ptype == "rpm":
        ns = distro if distro in _RPM_DISTROS else None
        return f"pkg:rpm/{ns + '/' if ns else ''}{name}@{urlquote(version, safe='')}"
    elif ptype == "apk":
        ns = distro if distro in _APK_DISTROS else None
        return f"pkg:apk/{ns + '/' if ns else ''}{name}@{urlquote(version, safe='')}"
    else:
        # Windows and anything else -> generic
        return f"pkg:generic/{name}@{urlquote(version, safe='')}"

def generate_cyclonedx_sbom(packages, tool_name="host-agent", tool_version="0.1.0"):
    """
    Build a CycloneDX 1.6 BOM with reasonable purls and bom-refs.
    """
    os_info = detect_os_metadata()
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
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
        purl = make_purl(pkg, os_info)
        bom_ref = purl  # safe, stable bom-ref
        sbom["components"].append({
            "bom-ref": bom_ref,
            "type": "application",
            "name": pkg.get("name", "unknown"),
            "version": str(pkg.get("version", "unknown")),
            "purl": purl,
        })

    return sbom
