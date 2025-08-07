#!/usr/bin/env python3

import argparse
import time
import xml.etree.ElementTree as ET
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

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

def run_openvas_scan(socket_path, username, password, target_ip,
                     target_name="AutoTarget", output_path="scan_report.html",
                     scan_config_key="full_and_fast", port_list_key="iana_tcp_udp",
                     port_range="1-65535"):

    scan_config_id = SCAN_CONFIGS.get(scan_config_key.lower())
    port_list_id = PORT_LISTS.get(port_list_key.lower())

    if not scan_config_id:
        raise ValueError(f"Invalid scan config key '{scan_config_key}'. Options: {list(SCAN_CONFIGS.keys())}")
    if not port_list_id:
        raise ValueError(f"Invalid port list key '{port_list_key}'. Options: {list(PORT_LISTS.keys())}")

    connection = UnixSocketConnection(path=socket_path)
    with Gmp(connection=connection) as gmp:
        gmp.authenticate(username, password)
        print("[+] Connected to GVM")

        # Try to create target
        target_response = gmp.create_target(name=target_name, hosts=[target_ip],
                                            port_list_id=port_list_id, port_range=port_range)
        print(f"[DEBUG] target_response {target_response}")

        if 'status="400"' in target_response and "Target exists already" in target_response:
            print(f"[!] Target '{target_name}' already exists. Retrieving ID...")
            targets_xml = gmp.get_targets()
            targets_root = ET.fromstring(targets_xml)
            existing = targets_root.find(f".//target[name='{target_name}']")
            if existing is not None:
                target_id = existing.attrib.get("id")
                print(f"[+] Found existing target '{target_name}' with ID {target_id}")
            else:
                raise RuntimeError(f"Target '{target_name}' exists but ID could not be found.")
        else:
            target_id = extract_id_from_response(target_response)
            print(f"[+] Created target '{target_name}' with ID {target_id}")
            print(f"[+] Using scan config '{scan_config_key}' (ID: {scan_config_id})")

        # Get scanner ID
        scanners_xml = gmp.get_scanners()
        scanner_id = ET.fromstring(scanners_xml).find(".//scanner").attrib.get("id")
        print(f"[+] Using scanner ID: {scanner_id}")

        # Create task
        task_response = gmp.create_task(
            name=f"Scan {target_ip}",
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        task_id = extract_id_from_response(task_response)
        print(f"[+] Created task with ID {task_id}")

        # Start task
        report_response = gmp.start_task(task_id)
        print(f"[DEBUG] start_task response: {report_response}")
        report_root = ET.fromstring(report_response)

        # Extract report_id from the correct XML location
        report_id_elem = report_root.find(".//report_id")
        if report_id_elem is not None:
            report_id = report_id_elem.attrib.get("id")
        else:
            raise RuntimeError("Failed to extract report ID from start_task response")

        print(f"[+] Scan started (Report ID: {report_id})")
        # Wait for scan to complete
        while True:
            status = ET.fromstring(gmp.get_task(task_id)).findtext(".//status")
            print(f"[.] Task status: {status}")
            if status == "Done":
                break
            time.sleep(10)

        # Fetch report
        report_xml = gmp.get_report(
            report_id=report_id,
            details=True,
            report_format_id="c402cc3e-b531-11e1-9163-406186ea4fc5"
        )
        report_data = ET.fromstring(report_xml).findtext(".//report_format[name='HTML']/../report")

        with open(output_path, "w") as f:
            f.write(report_data or "")
        print(f"[+] Report written to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run an OpenVAS scan via GMP socket")
    parser.add_argument("--socket", default="/run/gvmd/gvmd.sock", help="Path to gvmd socket")
    parser.add_argument("--user", default="admin", help="GMP username")
    parser.add_argument("--password", default="admin", help="GMP password")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--output", default="scan_report.html", help="Output HTML report path")
    parser.add_argument("--scan-config", default="full_and_fast", help=f"Scan config (options: {', '.join(SCAN_CONFIGS.keys())})")
    parser.add_argument("--port-list", default="iana_tcp_udp", help=f"Port list (options: {', '.join(PORT_LISTS.keys())})")
    parser.add_argument("--port-range", default="1-65535", help="Port range to scan (e.g. '1-65535')")

    args = parser.parse_args()

    run_openvas_scan(
        socket_path=args.socket,
        username=args.user,
        password=args.password,
        target_ip=args.target,
        output_path=args.output,
        scan_config_key=args.scan_config,
        port_list_key=args.port_list,
        port_range=args.port_range
    )
