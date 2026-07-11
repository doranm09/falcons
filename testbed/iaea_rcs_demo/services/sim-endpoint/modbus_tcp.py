import math
import os
import socketserver
import struct
import time
from dataclasses import dataclass
from threading import Lock, Thread
from typing import Dict, List, Optional


def _parse_int_csv(value: str) -> List[int]:
    result = []
    for item in value.split(","):
        item = item.strip()
        if item:
            result.append(int(item))
    return result


def _parse_controller_map(value: str) -> Dict[str, "ControllerInfo"]:
    controllers = {}
    for item in value.split(";"):
        item = item.strip()
        if not item:
            continue
        controller_id, ip_address, priority = [part.strip() for part in item.split("|", 2)]
        controllers[ip_address] = ControllerInfo(
            controller_id=int(controller_id),
            ip_address=ip_address,
            priority=int(priority),
        )
    return controllers


@dataclass(frozen=True)
class ControllerInfo:
    controller_id: int
    ip_address: str
    priority: int


class DeviceModel:
    def __init__(self) -> None:
        self.profile = os.getenv("MODBUS_PROFILE", "").strip().lower()
        self.base_value = int(os.getenv("MODBUS_BASE_VALUE", "0"))
        self.amplitude = int(os.getenv("MODBUS_AMPLITUDE", "0"))
        self.period_sec = max(float(os.getenv("MODBUS_PERIOD_SEC", "60")), 1.0)
        self.phase_deg = float(os.getenv("MODBUS_PHASE_DEG", "0"))
        self.status_value = int(os.getenv("MODBUS_STATUS_VALUE", "1")) & 0xFFFF
        self.explicit_input_registers = _parse_int_csv(os.getenv("MODBUS_INPUT_REGS", ""))
        self.explicit_holding_registers = _parse_int_csv(os.getenv("MODBUS_HOLDING_REGS", ""))
        self.controller_map = _parse_controller_map(os.getenv("MODBUS_CONTROLLER_MAP", ""))
        self.controller_priorities = {
            controller.controller_id: controller.priority
            for controller in self.controller_map.values()
        }
        self.owner_lease_sec = max(float(os.getenv("MODBUS_OWNER_LEASE_SEC", "2")), 0.1)
        self.command_min = int(os.getenv("MODBUS_COMMAND_MIN", "0"))
        self.command_max = int(os.getenv("MODBUS_COMMAND_MAX", "100"))
        self._lock = Lock()
        self._active_owner_id = 0
        self._owner_deadline = 0.0
        self._applied_command = self._clamp_command(int(os.getenv("MODBUS_INITIAL_COMMAND", "0")))
        self._last_writer_id = 0
        self._last_write_accepted = False
        self._last_write_rejected = False

    def _pressure_transmitter_registers(self) -> List[int]:
        phase = math.radians(self.phase_deg)
        angle = ((time.time() / self.period_sec) * 2.0 * math.pi) + phase
        pv = int(round(self.base_value + (self.amplitude * math.sin(angle))))
        return [pv & 0xFFFF, self.status_value]

    def _clamp_command(self, value: int) -> int:
        return max(self.command_min, min(self.command_max, value)) & 0xFFFF

    def _expire_owner_if_needed_locked(self) -> None:
        if self._active_owner_id and time.monotonic() >= self._owner_deadline:
            self._active_owner_id = 0

    def _actuator_status_word_locked(self) -> int:
        status = 0x0001
        if self._active_owner_id:
            status |= 0x0002
        if self._last_write_accepted:
            status |= 0x0004
        if self._last_write_rejected:
            status |= 0x0008
        return status & 0xFFFF

    def _actuator_holding_registers_locked(self) -> List[int]:
        self._expire_owner_if_needed_locked()
        return [
            self._active_owner_id & 0xFFFF,
            self._applied_command & 0xFFFF,
            self._last_writer_id & 0xFFFF,
            self._actuator_status_word_locked(),
        ]

    def input_registers(self) -> List[int]:
        if self.explicit_input_registers:
            return [value & 0xFFFF for value in self.explicit_input_registers]
        if self.profile == "pressure_transmitter":
            return self._pressure_transmitter_registers()
        if self.profile == "actuator":
            with self._lock:
                return self._actuator_holding_registers_locked()
        return [self.base_value & 0xFFFF]

    def holding_registers(self) -> List[int]:
        if self.explicit_holding_registers:
            return [value & 0xFFFF for value in self.explicit_holding_registers]
        if self.profile == "actuator":
            with self._lock:
                return self._actuator_holding_registers_locked()
        return self.input_registers()

    def write_holding_registers(self, start_address: int, values: List[int], client_ip: str) -> Optional[int]:
        if self.profile != "actuator":
            return 1

        end_address = start_address + len(values)
        if start_address < 0 or end_address > 2:
            return 2

        controller = self.controller_map.get(client_ip)
        requested_owner_id = None
        requested_command = None
        if start_address == 0:
            requested_owner_id = values[0] & 0xFFFF
            if len(values) > 1:
                requested_command = values[1] & 0xFFFF
        elif start_address == 1:
            requested_command = values[0] & 0xFFFF

        with self._lock:
            self._expire_owner_if_needed_locked()
            self._last_writer_id = 0 if controller is None else controller.controller_id
            self._last_write_accepted = False
            self._last_write_rejected = False

            if controller is None:
                self._last_write_rejected = True
                return None

            if requested_owner_id is None:
                requested_owner_id = self._active_owner_id

            if requested_owner_id != controller.controller_id:
                self._last_write_rejected = True
                return None

            current_owner_priority = self.controller_priorities.get(self._active_owner_id, -1)
            can_claim = (
                self._active_owner_id == 0
                or self._active_owner_id == controller.controller_id
                or controller.priority > current_owner_priority
            )
            if not can_claim:
                self._last_write_rejected = True
                return None

            self._active_owner_id = controller.controller_id
            self._owner_deadline = time.monotonic() + self.owner_lease_sec
            if requested_command is not None:
                self._applied_command = self._clamp_command(requested_command)
            self._last_write_accepted = True
        return None


def build_device_model_from_env() -> DeviceModel:
    return DeviceModel()


def _recv_exact(sock, length: int) -> Optional[bytes]:
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _exception_response(function_code: int, exception_code: int) -> bytes:
    return bytes([function_code | 0x80, exception_code])


class _ThreadingModbusServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client_ip = self.client_address[0]
        while True:
            header = _recv_exact(self.request, 7)
            if not header:
                return

            tx_id, protocol_id, length, unit_id = struct.unpack(">HHHB", header)
            if protocol_id != 0 or length < 2:
                return

            pdu = _recv_exact(self.request, length - 1)
            if not pdu:
                return

            function_code = pdu[0]
            if function_code not in (3, 4, 6, 16):
                response_pdu = _exception_response(function_code, 1)
            elif function_code in (3, 4):
                if len(pdu) != 5:
                    response_pdu = _exception_response(function_code, 3)
                else:
                    start_address, quantity = struct.unpack(">HH", pdu[1:5])
                    if quantity == 0 or quantity > 125:
                        response_pdu = _exception_response(function_code, 3)
                    else:
                        if function_code == 4:
                            source = self.server.device_model.input_registers()
                        else:
                            source = self.server.device_model.holding_registers()

                        end_address = start_address + quantity
                        if end_address > len(source):
                            response_pdu = _exception_response(function_code, 2)
                        else:
                            registers = source[start_address:end_address]
                            payload = b"".join(struct.pack(">H", value & 0xFFFF) for value in registers)
                            response_pdu = bytes([function_code, len(payload)]) + payload
            elif function_code == 6:
                if len(pdu) != 5:
                    response_pdu = _exception_response(function_code, 3)
                else:
                    start_address, value = struct.unpack(">HH", pdu[1:5])
                    exception_code = self.server.device_model.write_holding_registers(
                        start_address,
                        [value],
                        client_ip,
                    )
                    if exception_code is None:
                        response_pdu = pdu
                    else:
                        response_pdu = _exception_response(function_code, exception_code)
            else:
                if len(pdu) < 6:
                    response_pdu = _exception_response(function_code, 3)
                else:
                    start_address, quantity, byte_count = struct.unpack(">HHB", pdu[1:6])
                    if quantity == 0 or quantity > 123 or byte_count != quantity * 2 or len(pdu) != 6 + byte_count:
                        response_pdu = _exception_response(function_code, 3)
                    else:
                        values = list(struct.unpack(f">{quantity}H", pdu[6:6 + byte_count]))
                        exception_code = self.server.device_model.write_holding_registers(
                            start_address,
                            values,
                            client_ip,
                        )
                        if exception_code is None:
                            response_pdu = struct.pack(">BHH", function_code, start_address, quantity)
                        else:
                            response_pdu = _exception_response(function_code, exception_code)

            response = struct.pack(">HHHB", tx_id, 0, len(response_pdu) + 1, unit_id) + response_pdu
            self.request.sendall(response)


def start_modbus_server(device_model: DeviceModel, port: int):
    server = _ThreadingModbusServer(("0.0.0.0", port), _ModbusHandler)
    server.device_model = device_model
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
