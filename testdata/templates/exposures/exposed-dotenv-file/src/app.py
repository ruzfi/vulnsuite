#!/usr/bin/env python3
"""Application root serves its .env, leaking database and API secrets.

VULNERABLE by default; set MODE=patched for the remediated behaviour. The two
states differ by the MINIMUM that toggles the flaw, so one image serves both.
"""
import os, http.server, socketserver
PATCHED = os.environ.get("MODE", "vulnerable") == "patched"
PORT = 8080

DOTENV = (
    "APP_ENV=production\n"
    "DB_HOST=10.0.0.5\n"
    "DB_PASSWORD=pr0d-db-s3cret\n"
    "STRIPE_SECRET_KEY=sk_live_51Hxxxxxxxxxxxx\n"
)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?")[0] == "/.env":
            if PATCHED:
                return self._send(404, "Not Found")
            return self._send(200, DOTENV, "text/plain")
        if self.path == "/":
            return self._send(200, "<h1>Acme App</h1>", "text/html")
        self._send(404, "Not Found")
    def _send(self, code, body, ct="text/plain"):
        self.send_response(code); self.send_header("Content-Type", ct); self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self, *a): pass

socketserver.TCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", PORT), H).serve_forever()
