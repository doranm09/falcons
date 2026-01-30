import os
import xml.etree.ElementTree as ET
from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.latest import Gmp

GVM_HOST = os.environ.get("GVM_HOST", "openvas")
GVM_PORT = int(os.environ.get("GVM_PORT", "9390"))
GVM_USER = os.environ.get("GVM_USER", "admin")
GVM_PASS = os.environ.get("GVM_PASS", "admin")
GVM_SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH")

# Scan configuration options
SCAN_CONFIGS = {
    "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
    "base": "d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663",
    "discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
    "empty": "085569ce-73ed-11df-83c3-002264764cea",
    "host_discovery": "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
    "log4shell": "e3efebc5-fc0d-4cb6-b1b4-55309d0a89f6",
    "system_discovery": "bbca7412-a950-11e3-9109-406186ea4fc5"
}

# Port list options
PORT_LISTS = {
    "iana_tcp": "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
    "iana_tcp_udp": "4a4717fe-57d2-11e1-9a26-406186ea4fc5",
    "nmap_top_udp_tcp": "730ef368-57e2-11e1-a90f-406186ea4fc5"
}

def extract_id_from_response(xml_string: str) -> str:
    root = ET.fromstring(xml_string)
    return root.attrib.get("id")

def openvas_session():
    if GVM_SOCKET_PATH:
        conn = UnixSocketConnection(path=GVM_SOCKET_PATH)
    else:
        conn = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)
    gmp = Gmp(conn)
    gmp.connect()
    gmp.authenticate(GVM_USER, GVM_PASS)
    return gmp

def _find_target_id(gmp, name):
    targets = gmp.get_targets()
    if hasattr(targets, "xpath"):
        matches = targets.xpath(f"//target[name='{name}']/@id")
        return matches[0] if matches else None
    root = ET.fromstring(targets)
    for target in root.findall(".//{*}target"):
        if target.findtext("{*}name") == name:
            return target.attrib.get("id")
    return None

def create_target(gmp, cidr, port_list_id=None):
    port_list_id = port_list_id or PORT_LISTS["iana_tcp"]
    target_name = f"Target {cidr}"
    response = gmp.create_target(
        name=target_name,
        hosts=[cidr],
        port_list_id=port_list_id,
    )
    if hasattr(response, "xpath"):
        return response.xpath("create_target_response/@id")[0]
    target_id = extract_id_from_response(response)
    if target_id:
        return target_id
    try:
        root = ET.fromstring(response)
    except ET.ParseError:
        root = None
    if root is not None:
        status = root.attrib.get("status_text", "").lower()
        if "exists" in status:
            existing_id = _find_target_id(gmp, target_name)
            if existing_id:
                return existing_id
    return None

def resolve_scan_config_id(config_name: str) -> str:
    if not config_name:
        return SCAN_CONFIGS["full_and_fast"]
    key = config_name.strip().lower().replace(" ", "_")
    return SCAN_CONFIGS.get(key, SCAN_CONFIGS["full_and_fast"])

def get_scanner_id(gmp):
    scanners = gmp.get_scanners()
    if hasattr(scanners, "xpath"):
        matches = scanners.xpath("//scanner[contains(name, 'OpenVAS')]/@id")
        if matches:
            return matches[0]
        return scanners.xpath("//scanner/@id")[0]
    root = ET.fromstring(scanners)
    openvas_id = None
    fallback_id = None
    for scanner in root.findall(".//{*}scanner"):
        scanner_id = scanner.attrib.get("id")
        if not fallback_id and scanner_id:
            fallback_id = scanner_id
        name = (scanner.findtext("{*}name") or "").lower()
        if "openvas" in name and scanner_id:
            openvas_id = scanner_id
            break
    if openvas_id:
        return openvas_id
    if fallback_id:
        return fallback_id
    raise ValueError("No scanner IDs available from gvmd")


def start_scan(gmp, target_id, config_name=None):
    config_id = resolve_scan_config_id(config_name)
    scanner_id = get_scanner_id(gmp)
    task = gmp.create_task(f"Scan {target_id}", config_id, target_id, scanner_id)
    if hasattr(task, "xpath"):
        task_id = task.xpath("create_task_response/@id")[0]
    else:
        task_id = extract_id_from_response(task)
    gmp.start_task(task_id)
    return task_id

def get_report_id(gmp, task_id):
    task = gmp.get_task(task_id)
    if hasattr(task, "xpath"):
        return task.xpath("//task/last_report/report/@id")[0]
    root = ET.fromstring(task)
    report = root.find(".//{*}task/{*}last_report/{*}report")
    if report is None:
        report = root.find(".//{*}report")
    if report is None or "id" not in report.attrib:
        raise ValueError("No report ID found in task response")
    return report.attrib["id"]

def download_report(gmp, report_id):
    return gmp.get_report(report_id=report_id, report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5')  # XML

def get_task_status(gmp, task_id):
    task = gmp.get_task(task_id)
    if hasattr(task, "xpath"):
        status = task.xpath("//task/status/text()")
        progress = task.xpath("//task/progress/text()")
        report_id = task.xpath("//task/last_report/report/@id")
        return {
            "status": status[0] if status else None,
            "progress": progress[0] if progress else None,
            "report_id": report_id[0] if report_id else None,
        }
    root = ET.fromstring(task)
    report = root.find(".//{*}last_report/{*}report")
    return {
        "status": root.findtext(".//{*}status"),
        "progress": root.findtext(".//{*}progress"),
        "report_id": report.attrib.get("id") if report is not None else None,
    }
