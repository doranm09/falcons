#!/usr/bin/env python3
import os
import socket
import struct
import time
from dataclasses import dataclass
from threading import Lock

from opcua import Server, ua


@dataclass(frozen=True)
class Point:
    name: str
    area: str
    function: int
    address: int


@dataclass(frozen=True)
class OverrideTarget:
    prefix: str
    node_name: str
    host: str
    unit_id: int


COMMON_POINTS = [
    Point("hv_owner", "actuators", 4, 106),
    Point("hv_applied", "actuators", 4, 107),
    Point("hv_last_writer", "actuators", 4, 108),
    Point("hv_status", "actuators", 4, 109),
    Point("pvb_owner", "actuators", 4, 110),
    Point("pvb_applied", "actuators", 4, 111),
    Point("pvb_last_writer", "actuators", 4, 112),
    Point("pvb_status", "actuators", 4, 113),
    Point("pvc_owner", "actuators", 4, 114),
    Point("pvc_applied", "actuators", 4, 115),
    Point("pvc_last_writer", "actuators", 4, 116),
    Point("pvc_status", "actuators", 4, 117),
    Point("heat_owner", "actuators", 4, 118),
    Point("heat_applied", "actuators", 4, 119),
    Point("heat_last_writer", "actuators", 4, 120),
    Point("heat_status", "actuators", 4, 121),
    Point("average_pressure", "summary", 3, 13),
    Point("health_code", "summary", 3, 14),
    Point("exported_hv_owner", "summary", 3, 15),
    Point("exported_hv_command", "summary", 3, 16),
    Point("exported_pvb_owner", "summary", 3, 17),
    Point("exported_pvb_command", "summary", 3, 18),
    Point("exported_pvc_owner", "summary", 3, 19),
    Point("exported_pvc_command", "summary", 3, 20),
    Point("exported_heat_owner", "summary", 3, 21),
    Point("exported_heat_command", "summary", 3, 22),
]

PROFILE_POINTS = {
    "main": [
        Point("pt455_pv", "sensors", 4, 100),
        Point("pt455_status", "sensors", 4, 101),
        Point("pt456_pv", "sensors", 4, 102),
        Point("pt456_status", "sensors", 4, 103),
        Point("pt457_pv", "sensors", 4, 104),
        Point("pt457_status", "sensors", 4, 105),
        Point("exported_pt455", "summary", 3, 10),
        Point("exported_pt456", "summary", 3, 11),
        Point("exported_pt457", "summary", 3, 12),
    ],
    "backup": [
        Point("pt456_pv", "sensors", 4, 100),
        Point("pt456_status", "sensors", 4, 101),
        Point("pt457_pv", "sensors", 4, 102),
        Point("pt457_status", "sensors", 4, 103),
        Point("pt458_pv", "sensors", 4, 104),
        Point("pt458_status", "sensors", 4, 105),
        Point("exported_pt456", "summary", 3, 10),
        Point("exported_pt457", "summary", 3, 11),
        Point("exported_pt458", "summary", 3, 12),
    ],
}

DEFAULT_OVERRIDE_TARGETS = {
    "main": [
        OverrideTarget("hv", "hv_override_command", "10.3.13.1", 11),
        OverrideTarget("pvb", "pvb_override_command", "10.3.13.2", 12),
        OverrideTarget("pvc", "pvc_override_command", "10.3.13.3", 13),
        OverrideTarget("heat", "heat_override_command", "10.3.13.5", 14),
    ],
    "backup": [
        OverrideTarget("hv", "hv_override_command", "10.4.23.1", 11),
        OverrideTarget("pvb", "pvb_override_command", "10.4.23.2", 12),
        OverrideTarget("pvc", "pvc_override_command", "10.4.23.3", 13),
        OverrideTarget("heat", "heat_override_command", "10.4.23.5", 14),
    ],
}

DEFAULT_OVERRIDE_CONTROLLER_IDS = {
    "main": 1,
    "backup": 2,
}

PROFILE = os.getenv("PLC_OPC_PROFILE", "").strip().lower()
POINTS = PROFILE_POINTS.get(PROFILE)
if not POINTS:
    raise SystemExit("PLC_OPC_PROFILE must be set to 'main' or 'backup'")

POINTS = POINTS + COMMON_POINTS
POINT_INDEX = {(point.function, point.address): point.name for point in POINTS}

MODBUS_HOST = os.getenv("PLC_OPC_MODBUS_HOST", "127.0.0.1")
MODBUS_PORT = int(os.getenv("PLC_OPC_MODBUS_PORT", "502"))
MODBUS_UNIT_ID = int(os.getenv("PLC_OPC_MODBUS_UNIT_ID", "1"))
MODBUS_TIMEOUT_SEC = max(float(os.getenv("PLC_OPC_MODBUS_TIMEOUT_SEC", "3.0")), 0.1)

OPC_PORT = int(os.getenv("PLC_OPC_PORT", "4840"))
ENDPOINT_PATH = os.getenv("PLC_OPC_ENDPOINT_PATH", PROFILE).strip("/")
NAMESPACE_URI = os.getenv("PLC_OPC_NAMESPACE", f"urn:iaea-rcs-demo:{PROFILE}")
SERVER_NAME = os.getenv("PLC_OPC_SERVER_NAME", os.getenv("DEVICE_NAME", f"PLC-{PROFILE.upper()}"))
POLL_INTERVAL_SEC = float(os.getenv("PLC_OPC_POLL_INTERVAL_SEC", "1.0"))

ACTUATOR_MODBUS_PORT = int(os.getenv("PLC_OPC_ACTUATOR_MODBUS_PORT", "502"))
OVERRIDE_COMMAND_MIN = int(os.getenv("PLC_OPC_OVERRIDE_COMMAND_MIN", "0"))
OVERRIDE_COMMAND_MAX = int(os.getenv("PLC_OPC_OVERRIDE_COMMAND_MAX", "100"))
OVERRIDE_REAPPLY_SEC = max(float(os.getenv("PLC_OPC_OVERRIDE_REAPPLY_SEC", "0.1")), 0.05)
OVERRIDE_CONTROLLER_ID = int(
    os.getenv(
        "PLC_OPC_OVERRIDE_CONTROLLER_ID",
        str(DEFAULT_OVERRIDE_CONTROLLER_IDS[PROFILE]),
    )
)
OVERRIDE_TARGETS = {target.prefix: target for target in DEFAULT_OVERRIDE_TARGETS[PROFILE]}
LOOP_SLEEP_SEC = max(min(POLL_INTERVAL_SEC, OVERRIDE_REAPPLY_SEC, 0.1), 0.02)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("socket closed during Modbus response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def modbus_request(host: str, port: int, unit_id: int, function: int, payload: bytes) -> bytes:
    transaction_id = int(time.time() * 1000) & 0xFFFF
    request = struct.pack(">HHHB", transaction_id, 0, len(payload) + 2, unit_id) + bytes([function]) + payload
    with socket.create_connection((host, port), timeout=MODBUS_TIMEOUT_SEC) as sock:
        sock.sendall(request)
        header = recv_exact(sock, 7)
        body_length = struct.unpack(">H", header[4:6])[0] - 1
        body = recv_exact(sock, body_length)

    response_function = body[0]
    if response_function & 0x80:
        raise RuntimeError(f"Modbus exception {body[1]} for function {function}")
    return body


def read_modbus_block(host: str, port: int, unit_id: int, function: int, start: int, count: int) -> list[int]:
    body = modbus_request(host, port, unit_id, function, struct.pack(">HH", start, count))
    byte_count = body[1]
    values = []
    for offset in range(0, byte_count, 2):
        values.append(struct.unpack(">H", body[2 + offset:4 + offset])[0])
    return values


def write_modbus_registers(host: str, port: int, unit_id: int, start: int, values: list[int]) -> None:
    encoded = b"".join(struct.pack(">H", value & 0xFFFF) for value in values)
    payload = struct.pack(">HHB", start, len(values), len(encoded)) + encoded
    body = modbus_request(host, port, unit_id, 16, payload)
    if len(body) != 5:
        raise RuntimeError(f"unexpected Modbus write response length {len(body)}")
    written_start, written_count = struct.unpack(">HH", body[1:5])
    if written_start != start or written_count != len(values):
        raise RuntimeError(
            f"unexpected Modbus write acknowledgement start={written_start} count={written_count}"
        )


def read_all_points() -> dict[str, int]:
    values: dict[str, int] = {}
    for function, start, count in ((3, 10, 13), (4, 100, 22)):
        block = read_modbus_block(MODBUS_HOST, MODBUS_PORT, MODBUS_UNIT_ID, function, start, count)
        for index, value in enumerate(block):
            name = POINT_INDEX.get((function, start + index))
            if name:
                values[name] = value
    return values


def normalize_override_command(raw_value) -> int:
    value = int(raw_value)
    if value < 0:
        return -1
    return max(OVERRIDE_COMMAND_MIN, min(OVERRIDE_COMMAND_MAX, value))


def build_server() -> tuple[Server, dict[str, object], dict[str, object]]:
    endpoint = f"opc.tcp://0.0.0.0:{OPC_PORT}/{ENDPOINT_PATH}"
    server = Server()
    server.set_endpoint(endpoint)
    server.set_server_name(SERVER_NAME)
    idx = server.register_namespace(NAMESPACE_URI)

    root = server.nodes.objects.add_object(
        ua.NodeId("telemetry", idx, ua.NodeIdType.String),
        "Telemetry",
    )
    sensors = root.add_object(
        ua.NodeId("telemetry.sensors", idx, ua.NodeIdType.String),
        "Sensors",
    )
    actuators = root.add_object(
        ua.NodeId("telemetry.actuators", idx, ua.NodeIdType.String),
        "Actuators",
    )
    summary = root.add_object(
        ua.NodeId("telemetry.summary", idx, ua.NodeIdType.String),
        "Summary",
    )
    commands = root.add_object(
        ua.NodeId("telemetry.commands", idx, ua.NodeIdType.String),
        "Commands",
    )
    bridge = root.add_object(
        ua.NodeId("telemetry.bridge", idx, ua.NodeIdType.String),
        "Bridge",
    )

    parents = {
        "sensors": sensors,
        "actuators": actuators,
        "summary": summary,
    }

    nodes = {}
    for point in POINTS:
        nodes[point.name] = parents[point.area].add_variable(
            ua.NodeId(point.name, idx, ua.NodeIdType.String),
            point.name,
            0,
        )

    command_nodes = {}
    for target in OVERRIDE_TARGETS.values():
        command_node = commands.add_variable(
            ua.NodeId(target.node_name, idx, ua.NodeIdType.String),
            target.node_name,
            ua.Variant(-1, ua.VariantType.Int16),
        )
        command_node.set_writable()
        command_nodes[target.prefix] = command_node

    commands.add_variable(
        ua.NodeId("override_controller_id", idx, ua.NodeIdType.String),
        "override_controller_id",
        OVERRIDE_CONTROLLER_ID,
    )

    nodes["bridge_online"] = bridge.add_variable(
        ua.NodeId("bridge_online", idx, ua.NodeIdType.String),
        "bridge_online",
        0,
    )
    nodes["bridge_poll_errors"] = bridge.add_variable(
        ua.NodeId("bridge_poll_errors", idx, ua.NodeIdType.String),
        "bridge_poll_errors",
        0,
    )
    nodes["bridge_last_success_epoch"] = bridge.add_variable(
        ua.NodeId("bridge_last_success_epoch", idx, ua.NodeIdType.String),
        "bridge_last_success_epoch",
        0,
    )
    nodes["bridge_write_errors"] = bridge.add_variable(
        ua.NodeId("bridge_write_errors", idx, ua.NodeIdType.String),
        "bridge_write_errors",
        0,
    )
    nodes["bridge_last_write_epoch"] = bridge.add_variable(
        ua.NodeId("bridge_last_write_epoch", idx, ua.NodeIdType.String),
        "bridge_last_write_epoch",
        0,
    )
    nodes["bridge_active_overrides"] = bridge.add_variable(
        ua.NodeId("bridge_active_overrides", idx, ua.NodeIdType.String),
        "bridge_active_overrides",
        0,
    )
    return server, nodes, command_nodes


def main() -> int:
    server, nodes, command_nodes = build_server()
    poll_errors = 0
    write_errors = 0
    override_lock = Lock()
    override_commands = {prefix: -1 for prefix in OVERRIDE_TARGETS}
    override_error_latched = {prefix: False for prefix in OVERRIDE_TARGETS}
    override_suppress = set()
    next_override_write = {prefix: 0.0 for prefix in OVERRIDE_TARGETS}

    def active_override_count() -> int:
        with override_lock:
            return sum(1 for command in override_commands.values() if command >= 0)

    def apply_override(prefix: str, command: int) -> bool:
        nonlocal write_errors
        target = OVERRIDE_TARGETS[prefix]
        try:
            write_modbus_registers(
                target.host,
                ACTUATOR_MODBUS_PORT,
                target.unit_id,
                0,
                [OVERRIDE_CONTROLLER_ID, command],
            )
        except Exception as exc:
            with override_lock:
                write_errors += 1
                current_error_count = write_errors
                was_latched = override_error_latched[prefix]
                override_error_latched[prefix] = True
            nodes["bridge_write_errors"].set_value(current_error_count)
            if not was_latched:
                print(f"openplc-opc-bridge override write error prefix={prefix}: {exc}", flush=True)
            return False

        with override_lock:
            was_latched = override_error_latched[prefix]
            override_error_latched[prefix] = False
        if was_latched:
            print(f"openplc-opc-bridge override write restored prefix={prefix}", flush=True)
        nodes["bridge_last_write_epoch"].set_value(int(time.time()))
        return True

    def make_override_callback(prefix: str):
        node = command_nodes[prefix]

        def _callback(handle, data_value):
            del handle
            raw_value = None
            if data_value is not None and data_value.Value is not None:
                raw_value = data_value.Value.Value

            with override_lock:
                if prefix in override_suppress:
                    override_suppress.remove(prefix)
                    return
                previous = override_commands[prefix]

            try:
                normalized = normalize_override_command(raw_value)
            except Exception as exc:
                print(
                    f"openplc-opc-bridge invalid override prefix={prefix} value={raw_value!r}: {exc}",
                    flush=True,
                )
                normalized = previous

            if normalized != raw_value:
                with override_lock:
                    override_suppress.add(prefix)
                node.set_value(normalized, ua.VariantType.Int16)

            with override_lock:
                override_commands[prefix] = normalized
                if normalized >= 0:
                    next_override_write[prefix] = time.monotonic() + OVERRIDE_REAPPLY_SEC
                else:
                    next_override_write[prefix] = 0.0

            nodes["bridge_active_overrides"].set_value(active_override_count())

            if normalized >= 0:
                if previous != normalized:
                    print(
                        f"openplc-opc-bridge override set prefix={prefix} command={normalized}",
                        flush=True,
                    )
                apply_override(prefix, normalized)
            elif previous >= 0:
                print(f"openplc-opc-bridge override cleared prefix={prefix}", flush=True)

        return _callback

    for prefix, node in command_nodes.items():
        status, _handle = server.iserver.aspace.add_datachange_callback(
            node.nodeid,
            ua.AttributeIds.Value,
            make_override_callback(prefix),
        )
        status.check()

    print(
        f"openplc-opc-bridge profile={PROFILE} endpoint=opc.tcp://0.0.0.0:{OPC_PORT}/{ENDPOINT_PATH}",
        flush=True,
    )
    server.start()
    try:
        next_poll_at = 0.0
        nodes["bridge_active_overrides"].set_value(0)
        while True:
            now_monotonic = time.monotonic()

            if now_monotonic >= next_poll_at:
                try:
                    for name, value in read_all_points().items():
                        nodes[name].set_value(int(value))
                    nodes["bridge_online"].set_value(1)
                    nodes["bridge_last_success_epoch"].set_value(int(time.time()))
                except Exception as exc:
                    poll_errors += 1
                    nodes["bridge_online"].set_value(0)
                    nodes["bridge_poll_errors"].set_value(poll_errors)
                    print(f"openplc-opc-bridge poll error: {exc}", flush=True)
                else:
                    nodes["bridge_poll_errors"].set_value(poll_errors)
                next_poll_at = now_monotonic + POLL_INTERVAL_SEC

            with override_lock:
                due_overrides = [
                    (prefix, command)
                    for prefix, command in override_commands.items()
                    if command >= 0 and now_monotonic >= next_override_write[prefix]
                ]

            for prefix, command in due_overrides:
                apply_override(prefix, command)
                with override_lock:
                    next_override_write[prefix] = time.monotonic() + OVERRIDE_REAPPLY_SEC

            time.sleep(LOOP_SLEEP_SEC)
    finally:
        server.stop()


if __name__ == "__main__":
    raise SystemExit(main())
