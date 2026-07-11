#!/usr/bin/env python3
"""
Modbus write script to inject values into the PLC's average_pressure register.
This is used to test the IDS process service anomaly detection.

The PLC main (10.1.13.10) exposes its internal registers via Modbus/TCP on port 502.
The average_pressure register is at holding register address 13 (0x000D).

Usage:
    python3 modbus_inject.py [value]

Arguments:
    value    Value to write to average_pressure (default: 0)

Examples:
    python3 modbus_inject.py              # Inject 0 for 10 seconds (triggers anomaly)
    python3 modbus_inject.py 4500         # Inject 4500 for 10 seconds (normal range)
    python3 modbus_inject.py 5000 --duration 15
                                      # Inject for 15 seconds
"""

import argparse
import os
import sys
import time

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

# PLC Main configuration
PLC_MAIN_IP = os.getenv("MODBUS_PLC_IP", "10.1.13.10")
PLC_MAIN_PORT = int(os.getenv("MODBUS_PLC_PORT", "502"))
AVERAGE_PRESSURE_REGISTER = 13  # Holding register address for average_pressure


def _write_register(client, address: int, value: int, unit_id: int = 1):
    return client.write_register(address, value, device_id=unit_id)


def _read_holding_registers(client, address: int, count: int, unit_id: int = 1):
    if hasattr(client, "read_holding_registers"):
        return client.read_holding_registers(address, count=count, device_id=unit_id)

    if hasattr(client, "read_registers"):
        return client.read_registers(address, count)

    raise AttributeError("Modbus client does not support holding register reads")


def write_average_pressure(
    client,
    value: int,
    register: int,
    duration_seconds: float,
    plc_ip: str,
    plc_port: int,
) -> bool:
    """
    Write a value to the average_pressure holding register.

    Args:
        client: ModbusTcpClient instance
        value: Integer value to write (0-65535 for 16-bit register)

    Returns:
        bool: True if write succeeded, False otherwise
    """
    try:
        print(f"[*] Connecting to PLC Main at {plc_ip}:{plc_port}...")
        client.connect()

        print(
            f"[*] Injecting value {value} to holding register {register} "
            f"for {duration_seconds:.1f}s..."
        )
        deadline = time.monotonic() + duration_seconds
        write_count = 0

        while time.monotonic() < deadline:
            result = _write_register(client, register, value, unit_id=1)
            if result.isError():
                print(f"[!] Write failed with error: {result}")
                return False
            write_count += 1

        print(f"[+] Completed {write_count} write(s) to average_pressure register")

        # Read back to verify
        print("[*] Reading back register to verify...")
        read_result = _read_holding_registers(client, register, 1, unit_id=1)

        if read_result.isError():
            print(f"[!] Read failed with error: {read_result}")
            return False

        actual_value = read_result.registers[0]
        print(f"[+] Verified: Register now contains {actual_value}")

        if actual_value == value:
            print(f"[+] SUCCESS: Value matches expected {value}")
        else:
            print(f"[!] WARNING: Value mismatch! Expected {value}, got {actual_value}")
            print("[*] Write succeeded even though the PLC updated the value before verification")

        return True

    except ModbusException as e:
        print(f"[!] Modbus error: {e}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False
    finally:
        client.close()
        print("[*] Connection closed")


def main():
    parser = argparse.ArgumentParser(
        description="Inject values into PLC average_pressure register for IDS testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 modbus_inject.py              # Inject 0 for 10 seconds (triggers anomaly)
    python3 modbus_inject.py 4500         # Inject 4500 for 10 seconds (normal range)
    python3 modbus_inject.py 5000 --duration 15
                                      # Inject for 15 seconds

Normal operating range: ~4545-4585 (based on sensor values)
Anomaly trigger: Values outside normal range will be detected by IDS process service
        """,
    )

    parser.add_argument(
        "value",
        type=int,
        nargs="?",
        default=0,
        help="Value to write to average_pressure register (default: 0)",
    )

    parser.add_argument(
        "--plc-ip",
        type=str,
        default=PLC_MAIN_IP,
        help=f"PLC Main IP address (default: {PLC_MAIN_IP})",
    )

    parser.add_argument(
        "--plc-port",
        type=int,
        default=PLC_MAIN_PORT,
        help=f"PLC Main Modbus port (default: {PLC_MAIN_PORT})",
    )

    parser.add_argument(
        "--register",
        type=int,
        default=AVERAGE_PRESSURE_REGISTER,
        help=f"Register address for average_pressure (default: {AVERAGE_PRESSURE_REGISTER})",
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Injection duration in seconds (default: 10.0)",
    )

    args = parser.parse_args()

    # Validate value range for 16-bit register
    if not (0 <= args.value <= 65535):
        print("[!] Error: Value must be between 0 and 65535 (16-bit register)")
        sys.exit(1)
    if args.duration <= 0:
        print("[!] Error: --duration must be greater than 0")
        sys.exit(1)

    print("=" * 60)
    print("PLC Modbus Injection Script")
    print("=" * 60)
    print(f"Target: {args.plc_ip}:{args.plc_port}")
    print(f"Register: {args.register} (average_pressure)")
    print(f"Value: {args.value}")
    print(f"Duration: {args.duration:.1f}s")
    print("=" * 60)

    # Create Modbus client
    client = ModbusTcpClient(host=args.plc_ip, port=args.plc_port)

    # Perform the write
    success = write_average_pressure(
        client,
        args.value,
        args.register,
        args.duration,
        args.plc_ip,
        args.plc_port,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
