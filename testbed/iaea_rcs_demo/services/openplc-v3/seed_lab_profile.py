#!/usr/bin/env python3
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


PERSIST_DIR = Path("/docker_persistent")
WEBSERVER_DIR = Path("/workdir/webserver")


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _normalize_program(content: str) -> str:
    return content.rstrip() + "\n"


def _load_profile(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _upsert_program(conn: sqlite3.Connection, file_name: str, name: str, description: str) -> None:
    cur = conn.cursor()
    cur.execute("SELECT Prog_ID FROM Programs WHERE File = ?", (file_name,))
    row = cur.fetchone()
    timestamp = int(time.time())
    if row:
        cur.execute(
            "UPDATE Programs SET Name = ?, Description = ?, Date_upload = ? WHERE Prog_ID = ?",
            (name, description, timestamp, row[0]),
        )
    else:
        cur.execute(
            "INSERT INTO Programs (Name, Description, File, Date_upload) VALUES (?, ?, ?, ?)",
            (name, description, file_name, timestamp),
        )


def _upsert_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    cur = conn.cursor()
    cur.execute("UPDATE Settings SET Value = ? WHERE Key = ?", (value, key))
    if cur.rowcount == 0:
        cur.execute("INSERT INTO Settings (Key, Value) VALUES (?, ?)", (key, value))


def _replace_slave_devices(conn: sqlite3.Connection, devices: list[dict]) -> None:
    cur = conn.cursor()
    cur.execute("DELETE FROM Slave_dev")
    for index, device in enumerate(devices, start=1):
        cur.execute(
            """
            INSERT INTO Slave_dev (
              dev_id, dev_name, dev_type, slave_id, com_port, baud_rate, parity,
              data_bits, stop_bits, ip_address, ip_port, di_start, di_size,
              coil_start, coil_size, ir_start, ir_size, hr_read_start,
              hr_read_size, hr_write_start, hr_write_size, pause
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                index,
                device["name"],
                device.get("type", "TCP"),
                int(device.get("slave_id", index)),
                device.get("com_port", ""),
                int(device.get("baud_rate", 115200)),
                device.get("parity", "N"),
                int(device.get("data_bits", 8)),
                int(device.get("stop_bits", 1)),
                device.get("ip_address", ""),
                int(device.get("ip_port", 502)),
                int(device.get("di_start", 0)),
                int(device.get("di_size", 0)),
                int(device.get("coil_start", 0)),
                int(device.get("coil_size", 0)),
                int(device.get("ir_start", 0)),
                int(device.get("ir_size", 0)),
                int(device.get("hr_read_start", 0)),
                int(device.get("hr_read_size", 0)),
                int(device.get("hr_write_start", 0)),
                int(device.get("hr_write_size", 0)),
                int(device.get("pause", 0)),
            ),
        )


def _generate_mbconfig(devices: list[dict], polling_ms: int, timeout_ms: int) -> str:
    lines = [
        f'Num_Devices = "{len(devices)}"',
        f'Polling_Period = "{polling_ms}"',
        f'Timeout = "{timeout_ms}"',
        "",
    ]
    for index, device in enumerate(devices):
        lines.extend(
            [
                "# ------------",
                f"#   DEVICE {index}",
                "# ------------",
                f'device{index}.name = "{device["name"]}"',
                f'device{index}.slave_id = "{int(device.get("slave_id", index + 1))}"',
                f'device{index}.protocol = "{device.get("protocol", "TCP")}"',
                f'device{index}.address = "{device.get("ip_address", "")}"',
                f'device{index}.IP_Port = "{int(device.get("ip_port", 502))}"',
                f'device{index}.RTU_Baud_Rate = "{int(device.get("baud_rate", 115200))}"',
                f'device{index}.RTU_Parity = "{device.get("parity", "N")}"',
                f'device{index}.RTU_Data_Bits = "{int(device.get("data_bits", 8))}"',
                f'device{index}.RTU_Stop_Bits = "{int(device.get("stop_bits", 1))}"',
                f'device{index}.RTU_TX_Pause = "{int(device.get("pause", 0))}"',
                "",
                f'device{index}.Discrete_Inputs_Start = "{int(device.get("di_start", 0))}"',
                f'device{index}.Discrete_Inputs_Size = "{int(device.get("di_size", 0))}"',
                f'device{index}.Coils_Start = "{int(device.get("coil_start", 0))}"',
                f'device{index}.Coils_Size = "{int(device.get("coil_size", 0))}"',
                f'device{index}.Input_Registers_Start = "{int(device.get("ir_start", 0))}"',
                f'device{index}.Input_Registers_Size = "{int(device.get("ir_size", 0))}"',
                f'device{index}.Holding_Registers_Read_Start = "{int(device.get("hr_read_start", 0))}"',
                f'device{index}.Holding_Registers_Read_Size = "{int(device.get("hr_read_size", 0))}"',
                f'device{index}.Holding_Registers_Start = "{int(device.get("hr_write_start", 0))}"',
                f'device{index}.Holding_Registers_Size = "{int(device.get("hr_write_size", 0))}"',
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    program_template = _env("PLC_PROGRAM_TEMPLATE")
    program_file = _env("PLC_PROGRAM_FILE")
    profile_file = _env("PLC_MODBUS_PROFILE")
    if not program_template and not profile_file:
        print("openplc-lab: no profile configured, skipping seed", flush=True)
        return 0

    if not program_template or not program_file or not profile_file:
        print("openplc-lab: missing PLC_PROGRAM_TEMPLATE, PLC_PROGRAM_FILE, or PLC_MODBUS_PROFILE", flush=True)
        return 1

    program_name = _env("PLC_PROGRAM_NAME", program_file)
    description = _env("PLC_PROGRAM_DESCRIPTION")
    enip_port = _env("PLC_ENIP_PORT")

    template_path = Path(program_template)
    profile_path = Path(profile_file)
    if not template_path.exists() or not profile_path.exists():
        print("openplc-lab: program template or Modbus profile is missing", flush=True)
        return 1

    profile = _load_profile(profile_path)
    polling_ms = int(_env("PLC_SLAVE_POLLING_MS", str(profile.get("polling_ms", 250))))
    timeout_ms = int(_env("PLC_SLAVE_TIMEOUT_MS", str(profile.get("timeout_ms", 500))))

    program_text = _normalize_program(template_path.read_text(encoding="utf-8"))
    _write_text(PERSIST_DIR / "st_files" / program_file, program_text)
    _write_text(PERSIST_DIR / "active_program", program_file + "\n")
    _write_text(
        PERSIST_DIR / "mbconfig.cfg",
        _generate_mbconfig(profile.get("devices", []), polling_ms, timeout_ms),
    )

    conn = sqlite3.connect(PERSIST_DIR / "openplc.db")
    try:
        _upsert_program(conn, program_file, program_name, description)
        _upsert_setting(conn, "Start_run_mode", _env("PLC_START_RUN_MODE", "true").lower())
        _upsert_setting(conn, "Slave_polling", str(polling_ms))
        _upsert_setting(conn, "Slave_timeout", str(timeout_ms))
        if enip_port:
            _upsert_setting(conn, "Enip_port", enip_port)
        _replace_slave_devices(conn, profile.get("devices", []))
        conn.commit()
    finally:
        conn.close()

    print(f"openplc-lab: compiling {program_file}", flush=True)
    result = subprocess.run(
        ["./scripts/compile_program.sh", program_file],
        cwd=WEBSERVER_DIR,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
