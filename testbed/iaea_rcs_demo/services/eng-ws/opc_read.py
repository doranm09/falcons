#!/opt/eng-ws/venv/bin/python
import argparse
import json

from opcua import Client


DEFAULT_POINTS = [
    "average_pressure",
    "health_code",
    "hv_owner",
    "hv_applied",
    "pvb_owner",
    "pvb_applied",
    "pvc_owner",
    "pvc_applied",
    "heat_owner",
    "heat_applied",
    "bridge_online",
    "bridge_poll_errors",
]


def get_namespace_index(client, namespace_uri):
    namespace_array = client.get_namespace_array()
    for index, value in enumerate(namespace_array):
        if value == namespace_uri:
            return index
    raise RuntimeError(f"namespace not found: {namespace_uri}")


def main():
    parser = argparse.ArgumentParser(description="Read one or more OPC UA nodes from a PLC bridge")
    parser.add_argument("endpoint", help="OPC UA endpoint, for example opc.tcp://10.1.1.14:4840/main")
    parser.add_argument(
        "--namespace",
        required=True,
        help="Namespace URI, for example urn:iaea-rcs-demo:main",
    )
    parser.add_argument(
        "--nodes",
        nargs="+",
        default=DEFAULT_POINTS,
        help="Node names to read",
    )
    args = parser.parse_args()

    client = Client(args.endpoint, timeout=4)
    client.connect()
    try:
        namespace_index = get_namespace_index(client, args.namespace)
        values = {}
        for node_name in args.nodes:
            node = client.get_node(f"ns={namespace_index};s={node_name}")
            values[node_name] = node.get_value()
        print(json.dumps(values, indent=2, sort_keys=True))
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
