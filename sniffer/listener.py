from scapy.all import get_if_list

def list_interfaces():
    return get_if_list()
