#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

def list_port_lists(socket_path="/opt/gvm-run/gvmd.sock", username="admin", password="admin"):
    connection = UnixSocketConnection(path=socket_path)
    with Gmp(connection=connection) as gmp:
        gmp.authenticate(username, password)
        port_lists_xml = gmp.get_port_lists()
        root = ET.fromstring(port_lists_xml)
        print(f"{'Port List Name':<40} | {'ID'}")
        print("-" * 90)
        for portlist in root.findall("port_list"):
            name = portlist.findtext("name")
            list_id = portlist.attrib.get("id")
            print(f"{name:<40} | {list_id}")

if __name__ == "__main__":
    list_port_lists()
