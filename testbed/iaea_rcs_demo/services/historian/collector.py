import os
import time
import logging
from opcua import Client
from influxdb_client import InfluxDBClient, Point

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MAIN_OPC_URL = os.getenv("MAIN_OPC_URL", "opc.tcp://10.1.13.10:4840/main")
BACKUP_OPC_URL = os.getenv("BACKUP_OPC_URL", "opc.tcp://10.2.23.10:4840/backup")
INFLUX_URL = os.getenv("INFLUX_URL", "http://historian-db:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iaea-historian-token")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iaea")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "iaea_rcs")
POLL_INTERVAL = float(os.getenv("HISTORIAN_POLL_INTERVAL", "5"))

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
SENSOR_PREFIXES = ["pt455", "pt456", "pt457", "pt458"]


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
    point = Point("rcs_metrics").tag("profile", profile)
    for key, value in fields.items():
        point.field(key, value)
    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
    logging.info("wrote %d fields for %s", len(fields), profile)


def sample_loop():
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api()
    while True:
        try:
            with OpcSampler(MAIN_OPC_URL, 2) as main_sampler:
                main_data = main_sampler.read_tags(TAG_KEYS + SENSOR_PREFIXES)
            with OpcSampler(BACKUP_OPC_URL, 2) as backup_sampler:
                backup_data = backup_sampler.read_tags(TAG_KEYS + SENSOR_PREFIXES)
            if main_data:
                write_measurement(write_api, "main", main_data)
            if backup_data:
                write_measurement(write_api, "backup", backup_data)
        except Exception as exc:
            logging.warning("historian poll failed: %s", exc)
        time.sleep(POLL_INTERVAL)


def main():
    logging.info("historian collector starting (main=%s backup=%s)", MAIN_OPC_URL, BACKUP_OPC_URL)
    sample_loop()

if __name__ == "__main__":
    main()
