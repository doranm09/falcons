import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.getenv("DEVICE_NAME", "openplc")
ROLE = os.getenv("DEVICE_ROLE", "plc")
DESC = os.getenv("DEVICE_DESC", "")
PORT = int(os.getenv("COMPAT_HTTP_PORT", "44818"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        payload = {
            "device": NAME,
            "role": ROLE,
            "description": DESC,
            "path": self.path,
            "compat_port": PORT,
            "status": "ok",
            "note": "Compatibility listener for legacy 44818 path checks",
        }
        body = json.dumps(payload, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"compatibility listener on {PORT}", flush=True)
    server.serve_forever()
