#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import time


ROOT_CONTAINERS = ("plc-main", "plc-backup", "hmi", "engineer-ws")
OPC_TARGETS = (
    ("plc-main", "opc.tcp://10.1.13.10:4840/main", "urn:iaea-rcs-demo:main"),
    ("plc-backup", "opc.tcp://10.2.23.10:4840/backup", "urn:iaea-rcs-demo:backup"),
)


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout


def require_running_containers() -> None:
    output = run("docker", "ps", "--format", "{{.Names}}")
    running = set(output.splitlines())
    missing = [name for name in ROOT_CONTAINERS if name not in running]
    if missing:
        raise SystemExit(f"missing required running containers: {', '.join(missing)}")


def read_opc(endpoint: str, namespace: str) -> dict[str, int]:
    output = run(
        "docker",
        "exec",
        "engineer-ws",
        "opc-read",
        endpoint,
        "--namespace",
        namespace,
    )
    return json.loads(output)


def read_hmi_state() -> dict:
    output = run(
        "docker",
        "exec",
        "hmi",
        "python3",
        "-c",
        (
            "import json, urllib.request; "
            "print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1/api/state', timeout=4))))"
        ),
    )
    return json.loads(output)


def wait_for_verification(timeout_sec: int = 90) -> tuple[dict[str, dict[str, int]], dict]:
    deadline = time.time() + timeout_sec
    last_error = "verification not started"
    while time.time() < deadline:
        try:
            require_running_containers()
            opc_results = {name: read_opc(endpoint, namespace) for name, endpoint, namespace in OPC_TARGETS}
            hmi_state = read_hmi_state()

            for name, values in opc_results.items():
                if int(values.get("bridge_online", 0)) != 1:
                    raise RuntimeError(f"{name} bridge_online={values.get('bridge_online')}")
            for name in ("plc-main", "plc-backup"):
                plc_state = hmi_state["plcs"][name]
                if not plc_state.get("connected"):
                    raise RuntimeError(f"hmi not connected to {name}: {plc_state.get('error', '')}")

            return opc_results, hmi_state
        except Exception as exc:
            last_error = str(exc)
            time.sleep(2)
    raise SystemExit(f"OPC verification timed out after {timeout_sec}s: {last_error}")


def main() -> int:
    opc_results, hmi_state = wait_for_verification()
    print("OPC verification passed")
    for name in ("plc-main", "plc-backup"):
        values = opc_results[name]
        plc_state = hmi_state["plcs"][name]
        print(
            json.dumps(
                {
                    "name": name,
                    "endpoint": plc_state["endpoint"],
                    "namespace": plc_state["namespace"],
                    "bridge_online": values["bridge_online"],
                    "average_pressure": values["average_pressure"],
                    "health_code": values["health_code"],
                    "hv_owner": values["hv_owner"],
                    "hv_applied": values["hv_applied"],
                    "hmi_connected": plc_state["connected"],
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
