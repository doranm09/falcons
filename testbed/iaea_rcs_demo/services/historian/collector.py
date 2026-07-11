import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from influxdb_client import InfluxDBClient, Point
from opcua import Client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

DEVICE_NAME = os.getenv("DEVICE_NAME", "Historian")
DEVICE_ROLE = os.getenv("DEVICE_ROLE", "Layer3 historian")
DEVICE_DESC = os.getenv(
    "DEVICE_DESC",
    "DMZ historian that exposes a status endpoint and polls PLC telemetry",
)
HTTP_PORTS = [
    int(item.strip())
    for item in os.getenv("SERVICE_PORTS", "443,4840").split(",")
    if item.strip()
]
MAIN_OPC_URL = os.getenv("MAIN_OPC_URL", "opc.tcp://10.1.1.14:4840/main")
BACKUP_OPC_URL = os.getenv("BACKUP_OPC_URL", "opc.tcp://10.1.2.15:4840/backup")
INFLUX_URL = os.getenv("INFLUX_URL", "").strip()
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iaea-historian-token")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iaea")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "iaea_rcs")
POLL_INTERVAL = float(os.getenv("HISTORIAN_POLL_INTERVAL", "0.5"))

TAG_KEYS = [
    "average_pressure",
    "health_code",
    "bridge_online",
    "bridge_poll_errors",
    "bridge_write_errors",
    "bridge_active_overrides",
    "hv_owner",
    "hv_applied",
    "pvb_owner",
    "pvb_applied",
    "pvc_owner",
    "pvc_applied",
    "heat_owner",
    "heat_applied",
]
SENSOR_TAG_MAP = {
    "pt455": "pt455_pv",
    "pt456": "pt456_pv",
    "pt457": "pt457_pv",
    "pt458": "pt458_pv",
}

STATE_LOCK = threading.Lock()
STATE = {
    "device": DEVICE_NAME,
    "role": DEVICE_ROLE,
    "description": DEVICE_DESC,
    "status": "starting",
    "influx_url": INFLUX_URL,
    "poll_interval_sec": POLL_INTERVAL,
    "generated_at": 0.0,
    "last_success_epoch": 0.0,
    "last_error": "",
    "profiles": {
        "main": {
            "endpoint": MAIN_OPC_URL,
            "namespace": 2,
            "connected": False,
            "updated_at": 0.0,
            "values": {},
        },
        "backup": {
            "endpoint": BACKUP_OPC_URL,
            "namespace": 2,
            "connected": False,
            "updated_at": 0.0,
            "values": {},
        },
    },
}


def update_state(**kwargs):
    with STATE_LOCK:
        STATE.update(kwargs)
        STATE["generated_at"] = time.time()


def update_profile(profile, **kwargs):
    with STATE_LOCK:
        STATE["profiles"][profile].update(kwargs)
        STATE["generated_at"] = time.time()


def snapshot_state(local_port, path):
    with STATE_LOCK:
        payload = json.loads(json.dumps(STATE))
    payload["path"] = path
    payload["local_port"] = local_port
    return payload


class HistorianStatusHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A003
        return

    def _write_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._write_cors_headers()
        self.end_headers()

    def do_GET(self):
        body = json.dumps(
            snapshot_state(self.server.server_port, self.path),
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._write_cors_headers()
        self.end_headers()
        self.wfile.write(body)


class ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def start_status_servers():
    for port in HTTP_PORTS:
        server = ReusableHTTPServer(("0.0.0.0", port), HistorianStatusHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logging.info("historian status server listening on %s", port)


class OpcSampler:
    def __init__(self, url: str, namespace: str):
        self.url = url
        self.namespace = namespace
        self.client = Client(self.url)

    def __enter__(self):
        self.client.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.disconnect()

    def read_tags(self, tag_names):
        result = {}
        for name in tag_names:
            node_id = f"ns={self.namespace};s={name}"
            try:
                node = self.client.get_node(node_id)
                result[name] = node.get_value()
            except Exception as exc:
                logging.debug("failed to read %s: %s", node_id, exc)
        return result


def write_measurement(write_api, profile, fields):
    if write_api is None:
        return
    point = Point("rcs_metrics").tag("profile", profile)
    for key, value in fields.items():
        point.field(key, value)
    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
    logging.info("wrote %d fields for %s", len(fields), profile)


def sample_loop():
    write_api = None
    if INFLUX_URL:
        client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        write_api = client.write_api()
    else:
        logging.info("historian telemetry persistence disabled; no INFLUX_URL configured")
    while True:
        try:
            sensor_nodes = list(SENSOR_TAG_MAP.values())
            with OpcSampler(MAIN_OPC_URL, 2) as main_sampler:
                main_data = main_sampler.read_tags(TAG_KEYS + sensor_nodes)
            with OpcSampler(BACKUP_OPC_URL, 2) as backup_sampler:
                backup_data = backup_sampler.read_tags(TAG_KEYS + sensor_nodes)

            for target_key, source_key in SENSOR_TAG_MAP.items():
                if source_key in main_data:
                    main_data[target_key] = main_data.pop(source_key)
                if source_key in backup_data:
                    backup_data[target_key] = backup_data.pop(source_key)

            if main_data:
                write_measurement(write_api, "main", main_data)
                update_profile(
                    "main",
                    connected=True,
                    updated_at=time.time(),
                    values=main_data,
                )
            if backup_data:
                write_measurement(write_api, "backup", backup_data)
                update_profile(
                    "backup",
                    connected=True,
                    updated_at=time.time(),
                    values=backup_data,
                )
            update_state(
                status="ok",
                last_success_epoch=time.time(),
                last_error="",
            )
        except Exception as exc:
            logging.warning("historian poll failed: %s", exc)
            update_state(status="degraded", last_error=str(exc))
            update_profile("main", connected=False)
            update_profile("backup", connected=False)
        time.sleep(POLL_INTERVAL)


def main():
    logging.info("historian collector starting (main=%s backup=%s)", MAIN_OPC_URL, BACKUP_OPC_URL)
    start_status_servers()
    sample_loop()

if __name__ == "__main__":
    main()
