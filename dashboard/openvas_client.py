import os
import xml.etree.ElementTree as ET
from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp

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
    gmp.login(GVM_USER, GVM_PASS)
    return gmp

def create_target(gmp, cidr):
    response = gmp.create_target(name=f"Target {cidr}", hosts=cidr)
    return response.xpath("create_target_response/@id")[0]

def resolve_scan_config_id(config_name: str) -> str:
    if not config_name:
        return SCAN_CONFIGS["full_and_fast"]
    key = config_name.strip().lower().replace(" ", "_")
    return SCAN_CONFIGS.get(key, SCAN_CONFIGS["full_and_fast"])


def start_scan(gmp, target_id, config_name=None):
    config_id = resolve_scan_config_id(config_name)
    task = gmp.create_task(name=f"Scan {target_id}", config_id=config_id, target_id=target_id)
    task_id = task.xpath("create_task_response/@id")[0]
    gmp.start_task(task_id)
    return task_id

def get_report_id(gmp, task_id):
    task = gmp.get_task(task_id)
    return task.xpath("//task/last_report/report/@id")[0]

def download_report(gmp, report_id):
    return gmp.get_report(report_id=report_id, report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5')  # XML
