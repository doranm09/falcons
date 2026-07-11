import math
import os
import socket
import socketserver
import struct
import time
from csv import DictReader
from dataclasses import dataclass
from pathlib import Path
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
class RegisterBridgeSource:
    host: str
    port: int
    unit_id: int
    function: int
    start: int
    count: int


def _parse_register_bridge_map(value: str) -> List["RegisterBridgeSource"]:
    sources = []
    for item in value.split(";"):
        item = item.strip()
        if not item:
            continue
        host, port, unit_id, function, start, count = [part.strip() for part in item.split("|", 5)]
        sources.append(
            RegisterBridgeSource(
                host=host,
                port=int(port),
                unit_id=int(unit_id),
                function=int(function),
                start=int(start),
                count=int(count),
            )
        )
    return sources


@dataclass(frozen=True)
class ControllerInfo:
    controller_id: int
    ip_address: str
    priority: int


@dataclass(frozen=True)
class CsvSample:
    timestamp: float
    values: Dict[str, int]


class DeviceModel:
    def __init__(self) -> None:
        self.profile = os.getenv("MODBUS_PROFILE", "").strip().lower()
        self.base_value = int(os.getenv("MODBUS_BASE_VALUE", "0"))
        self.amplitude = int(os.getenv("MODBUS_AMPLITUDE", "0"))
        self.period_sec = max(float(os.getenv("MODBUS_PERIOD_SEC", "60")), 1.0)
        self.phase_deg = float(os.getenv("MODBUS_PHASE_DEG", "0"))
        self.status_value = int(os.getenv("MODBUS_STATUS_VALUE", "1")) & 0xFFFF
        self.csv_path = os.getenv("MODBUS_CSV_PATH", "").strip()
        self.csv_time_column = os.getenv("MODBUS_CSV_TIME_COLUMN", "Time").strip()
        self.csv_sensor_column = os.getenv("MODBUS_CSV_SENSOR_COLUMN", "").strip()
        self.csv_actuator_columns = [
            item.strip()
            for item in os.getenv("MODBUS_CSV_ACTUATOR_COLUMNS", "").split(",")
            if item.strip()
        ]
        self.explicit_input_registers = _parse_int_csv(os.getenv("MODBUS_INPUT_REGS", ""))
        self.explicit_holding_registers = _parse_int_csv(os.getenv("MODBUS_HOLDING_REGS", ""))
        self.upstream_host = os.getenv("MODBUS_UPSTREAM_HOST", "").strip()
        self.upstream_port = int(os.getenv("MODBUS_UPSTREAM_PORT", "502"))
        self.upstream_unit_id = int(os.getenv("MODBUS_UPSTREAM_UNIT_ID", "1"))
        self.upstream_function = int(os.getenv("MODBUS_UPSTREAM_FUNCTION", "4"))
        self.upstream_start = int(os.getenv("MODBUS_UPSTREAM_START", "0"))
        self.upstream_count = int(os.getenv("MODBUS_UPSTREAM_COUNT", "2"))
        self.upstream_timeout_sec = max(float(os.getenv("MODBUS_UPSTREAM_TIMEOUT_SEC", "1.0")), 0.1)
        self.upstream_cache_sec = max(float(os.getenv("MODBUS_UPSTREAM_CACHE_SEC", "0.2")), 0.0)
        self.upstream_status_on_error = int(os.getenv("MODBUS_UPSTREAM_STATUS_ON_ERROR", "0")) & 0xFFFF
        self._upstream_cache_deadline = 0.0
        self._upstream_cached_values = [0] * max(self.upstream_count, 1)
        self.register_bridge_sources = _parse_register_bridge_map(os.getenv("MODBUS_REGISTER_BRIDGE_MAP", ""))
        self._register_bridge_cache_deadline = 0.0
        self._register_bridge_cached_values = [0] * max(
            1,
            sum(source.count for source in self.register_bridge_sources),
        )
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
        self._hybrid_actuator_count = 3 if self.profile == "hybrid_channel_c" else 1 if self.profile == "hybrid_channel_d" else 0
        self._hybrid_active_owner_ids = [0] * self._hybrid_actuator_count
        self._hybrid_owner_deadlines = [0.0] * self._hybrid_actuator_count
        self._hybrid_applied_commands = [self._applied_command] * self._hybrid_actuator_count
        self._hybrid_last_writer_ids = [0] * self._hybrid_actuator_count
        self._hybrid_last_write_accepted = [False] * self._hybrid_actuator_count
        self._hybrid_last_write_rejected = [False] * self._hybrid_actuator_count
        self._csv_samples = self._load_csv_samples()
        self._start_epoch = time.monotonic()

    def _load_csv_samples(self) -> List[CsvSample]:
        if not self.csv_path:
            return []
        path = Path(self.csv_path)
        if not path.exists():
            raise FileNotFoundError(f"MODBUS_CSV_PATH not found: {path}")
        samples: List[CsvSample] = []
        with path.open(newline="", encoding="utf-8") as handle:
            reader = DictReader(handle)
            for row in reader:
                raw_time = (row.get(self.csv_time_column, "") or "").strip()
                if not raw_time:
                    continue
                try:
                    timestamp = float(raw_time)
                except ValueError:
                    continue
                values: Dict[str, int] = {}
                for key, raw_value in row.items():
                    if key is None:
                        continue
                    text = (raw_value or "").strip()
                    if not text:
                        continue
                    try:
                        values[key] = int(round(float(text)))
                    except ValueError:
                        continue
                samples.append(CsvSample(timestamp=timestamp, values=values))
        if not samples:
            raise RuntimeError(f"no CSV samples loaded from {path}")
        return samples

    def _current_csv_sample(self) -> Optional[CsvSample]:
        if not self._csv_samples:
            return None
        elapsed = time.monotonic() - self._start_epoch
        last = self._csv_samples[0]
        for sample in self._csv_samples:
            if sample.timestamp > elapsed:
                return last
            last = sample
        return self._csv_samples[-1]

    def _pressure_transmitter_registers(self) -> List[int]:
        sample = self._current_csv_sample()
        if sample and self.csv_sensor_column:
            pv = sample.values.get(self.csv_sensor_column, self.base_value)
            return [pv & 0xFFFF, self.status_value]
        phase = math.radians(self.phase_deg)
        angle = ((time.time() / self.period_sec) * 2.0 * math.pi) + phase
        pv = int(round(self.base_value + (self.amplitude * math.sin(angle))))
        return [pv & 0xFFFF, self.status_value]

    def _expire_hybrid_owner_if_needed_locked(self, index: int) -> None:
        if self._hybrid_active_owner_ids[index] and time.monotonic() >= self._hybrid_owner_deadlines[index]:
            self._hybrid_active_owner_ids[index] = 0

    def _hybrid_actuator_status_word_locked(self, index: int) -> int:
        status = 0x0001
        if self._hybrid_active_owner_ids[index]:
            status |= 0x0002
        if self._hybrid_last_write_accepted[index]:
            status |= 0x0004
        if self._hybrid_last_write_rejected[index]:
            status |= 0x0008
        return status & 0xFFFF

    def _hybrid_channel_input_registers_locked(self) -> List[int]:
        registers = self._pressure_transmitter_registers()
        sample = self._current_csv_sample()
        csv_commands = []
        if sample and self.csv_actuator_columns:
            csv_commands = [sample.values.get(column, 0) for column in self.csv_actuator_columns]
        for index in range(self._hybrid_actuator_count):
            self._expire_hybrid_owner_if_needed_locked(index)
            if self._hybrid_active_owner_ids[index] == 0 and index < len(csv_commands):
                self._hybrid_applied_commands[index] = self._clamp_command(csv_commands[index])
            registers.extend(
                [
                    self._hybrid_active_owner_ids[index] & 0xFFFF,
                    self._hybrid_applied_commands[index] & 0xFFFF,
                    self._hybrid_last_writer_ids[index] & 0xFFFF,
                    self._hybrid_actuator_status_word_locked(index),
                ]
            )
        return registers

    def _write_hybrid_channel_registers_locked(
        self,
        start_address: int,
        values: List[int],
        client_ip: str,
    ) -> Optional[int]:
        total_registers = self._hybrid_actuator_count * 2
        end_address = start_address + len(values)
        if start_address < 0 or end_address > total_registers:
            return 2

        controller = self.controller_map.get(client_ip)
        if controller is None:
            for index in range(self._hybrid_actuator_count):
                self._hybrid_last_writer_ids[index] = 0
                self._hybrid_last_write_accepted[index] = False
                self._hybrid_last_write_rejected[index] = True
            return None

        write_index = 0
        while write_index < len(values):
            absolute = start_address + write_index
            actuator_index = absolute // 2
            field_offset = absolute % 2

            self._expire_hybrid_owner_if_needed_locked(actuator_index)
            self._hybrid_last_writer_ids[actuator_index] = controller.controller_id
            self._hybrid_last_write_accepted[actuator_index] = False
            self._hybrid_last_write_rejected[actuator_index] = False

            requested_owner_id = None
            requested_command = None
            if field_offset == 0:
                requested_owner_id = values[write_index] & 0xFFFF
                if write_index + 1 < len(values) and absolute + 1 < total_registers:
                    requested_command = values[write_index + 1] & 0xFFFF
                    write_index += 1
            else:
                requested_command = values[write_index] & 0xFFFF

            if requested_owner_id is None:
                requested_owner_id = self._hybrid_active_owner_ids[actuator_index]

            if requested_owner_id != controller.controller_id:
                self._hybrid_last_write_rejected[actuator_index] = True
                write_index += 1
                continue

            current_owner_priority = self.controller_priorities.get(
                self._hybrid_active_owner_ids[actuator_index],
                -1,
            )
            can_claim = (
                self._hybrid_active_owner_ids[actuator_index] == 0
                or self._hybrid_active_owner_ids[actuator_index] == controller.controller_id
                or controller.priority > current_owner_priority
            )
            if not can_claim:
                self._hybrid_last_write_rejected[actuator_index] = True
                write_index += 1
                continue

            self._hybrid_active_owner_ids[actuator_index] = controller.controller_id
            self._hybrid_owner_deadlines[actuator_index] = time.monotonic() + self.owner_lease_sec
            if requested_command is not None:
                self._hybrid_applied_commands[actuator_index] = self._clamp_command(requested_command)
            self._hybrid_last_write_accepted[actuator_index] = True
            write_index += 1
        return None

    def _read_upstream_registers(self) -> List[int]:
        if not self.upstream_host:
            return self._upstream_cached_values

        now = time.monotonic()
        if now < self._upstream_cache_deadline:
            return self._upstream_cached_values

        transaction_id = int(time.time() * 1000) & 0xFFFF
        request = struct.pack(
            ">HHHBBHH",
            transaction_id,
            0,
            6,
            self.upstream_unit_id,
            self.upstream_function,
            self.upstream_start,
            self.upstream_count,
        )
        try:
            with socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=self.upstream_timeout_sec,
            ) as sock:
                sock.sendall(request)
                header = _recv_exact(sock, 7)
                if not header:
                    raise RuntimeError("no Modbus header from upstream")
                _, protocol_id, length, _ = struct.unpack(">HHHB", header)
                if protocol_id != 0 or length < 2:
                    raise RuntimeError("invalid Modbus header from upstream")
                body = _recv_exact(sock, length - 1)
                if not body:
                    raise RuntimeError("no Modbus body from upstream")
            response_function = body[0]
            if response_function & 0x80:
                raise RuntimeError(f"Modbus exception {body[1]} from upstream")
            byte_count = body[1]
            values = []
            for offset in range(0, byte_count, 2):
                values.append(struct.unpack(">H", body[2 + offset:4 + offset])[0])
            if len(values) != self.upstream_count:
                raise RuntimeError(
                    f"upstream register count mismatch expected={self.upstream_count} got={len(values)}"
                )
            self._upstream_cached_values = values
        except Exception:
            fallback = list(self._upstream_cached_values)
            if fallback:
                fallback[-1] = self.upstream_status_on_error
                self._upstream_cached_values = fallback

        self._upstream_cache_deadline = now + self.upstream_cache_sec
        return self._upstream_cached_values

    def _modbus_register_request(
        self,
        host: str,
        port: int,
        unit_id: int,
        function: int,
        start: int,
        count: int,
    ) -> List[int]:
        transaction_id = int(time.time() * 1000) & 0xFFFF
        request = struct.pack(
            ">HHHBBHH",
            transaction_id,
            0,
            6,
            unit_id,
            function,
            start,
            count,
        )
        with socket.create_connection((host, port), timeout=self.upstream_timeout_sec) as sock:
            sock.sendall(request)
            header = _recv_exact(sock, 7)
            if not header:
                raise RuntimeError("no Modbus header from upstream")
            _, protocol_id, length, _ = struct.unpack(">HHHB", header)
            if protocol_id != 0 or length < 2:
                raise RuntimeError("invalid Modbus header from upstream")
            body = _recv_exact(sock, length - 1)
            if not body:
                raise RuntimeError("no Modbus body from upstream")
        response_function = body[0]
        if response_function & 0x80:
            raise RuntimeError(f"Modbus exception {body[1]} from upstream")
        byte_count = body[1]
        values = []
        for offset in range(0, byte_count, 2):
            values.append(struct.unpack(">H", body[2 + offset:4 + offset])[0])
        if len(values) != count:
            raise RuntimeError(f"upstream register count mismatch expected={count} got={len(values)}")
        return values

    def _read_register_bridge(self) -> List[int]:
        if not self.register_bridge_sources:
            return self._register_bridge_cached_values

        now = time.monotonic()
        if now < self._register_bridge_cache_deadline:
            return self._register_bridge_cached_values

        aggregated: List[int] = []
        cached_index = 0
        for source in self.register_bridge_sources:
            try:
                aggregated.extend(
                    self._modbus_register_request(
                        source.host,
                        source.port,
                        source.unit_id,
                        source.function,
                        source.start,
                        source.count,
                    )
                )
            except Exception:
                fallback = self._register_bridge_cached_values[cached_index:cached_index + source.count]
                if len(fallback) < source.count:
                    fallback = fallback + ([0] * (source.count - len(fallback)))
                aggregated.extend(fallback)
            cached_index += source.count

        self._register_bridge_cached_values = aggregated
        self._register_bridge_cache_deadline = now + self.upstream_cache_sec
        return self._register_bridge_cached_values

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
        if self.profile in ("hybrid_channel_c", "hybrid_channel_d"):
            with self._lock:
                return self._hybrid_channel_input_registers_locked()
        if self.profile == "analog_passthrough":
            return [value & 0xFFFF for value in self._read_upstream_registers()]
        if self.profile == "register_bridge":
            return [value & 0xFFFF for value in self._read_register_bridge()]
        if self.profile == "actuator":
            with self._lock:
                return self._actuator_holding_registers_locked()
        return [self.base_value & 0xFFFF]

    def holding_registers(self) -> List[int]:
        if self.explicit_holding_registers:
            return [value & 0xFFFF for value in self.explicit_holding_registers]
        if self.profile in ("hybrid_channel_c", "hybrid_channel_d"):
            return self.input_registers()
        if self.profile == "actuator":
            with self._lock:
                return self._actuator_holding_registers_locked()
        return self.input_registers()

    def write_holding_registers(self, start_address: int, values: List[int], client_ip: str) -> Optional[int]:
        if self.profile != "actuator":
            if self.profile in ("hybrid_channel_c", "hybrid_channel_d"):
                with self._lock:
                    return self._write_hybrid_channel_registers_locked(start_address, values, client_ip)
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
