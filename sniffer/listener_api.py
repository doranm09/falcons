from flask import Flask, request, jsonify
import threading
import pyshark
import netifaces
import os
import logging
import sys
import json

# Ensure log directory exists
LOG_DIR = './logs/'
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [sniffer] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"{LOG_DIR}/sniffer.log")
    ]
)
log = logging.getLogger("sniffer")

# Flask App
app = Flask(__name__)

listener_thread = None
listener_active = False

def capture_packets(interface):
    global listener_active
    listener_active = True
    try:
        log.info(f"Started capturing on interface: {interface}")
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            if not listener_active:
                break
            # Optional: log each packet if needed
            # log.debug(f"Packet: {packet}")
    except Exception as e:
        log.error(f"Listener error: {e}")
    finally:
        listener_active = False
        log.info("Stopped packet capture")


@app.route('/start', methods=['POST'])
def start_listener():
    global listener_thread, listener_active
    if listener_active:
        return jsonify({"status": "already_running"}), 400

    interface = request.json.get("interface")
    if not interface:
        return jsonify({"error": "Missing interface"}), 400

    log.info(f"Received start request for interface: {interface}")

    listener_thread = threading.Thread(target=capture_packets, args=(interface,))
    listener_thread.start()

    log.info("Listener thread started")
    return jsonify({"status": "started", "interface": interface})


@app.route('/stop', methods=['POST'])
def stop_listener():
    global listener_active
    if listener_active:
        log.info("Received stop request for listener")
        listener_active = False
        return jsonify({"status": "stopping"})
    else:
        return jsonify({"status": "not_running"}), 400


@app.route('/interfaces', methods=['GET'])
def list_interfaces():
    log.info("Listing available interfaces")
    interfaces = netifaces.interfaces()
    return jsonify({"interfaces": interfaces})

@app.route('/sbom', methods=['POST'])
def receive_sbom():
    agent_id = request.headers.get("X-Agent-ID", "unknown")
    timestamp = request.headers.get("X-Timestamp", "")
    sbom_data = request.get_json()

    with open(f"/tmp/received_sbom_{agent_id}.json", "w") as f:
        json.dump(sbom_data, f, indent=2)

    log.info(f"Received SBOM from {agent_id} at {timestamp}")
    return jsonify({"status": "received"}), 200


if __name__ == '__main__':
    log.info("Starting sniffer API service")
    app.run(host='0.0.0.0', port=5000)
