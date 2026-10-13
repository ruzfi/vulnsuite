#!/usr/bin/env python3
"""Simulated IP camera. VULNERABLE: /admin/config is reachable without auth and
leaks credentials (rtsp/wifi)."""
import http.server, socketserver
SECRETS = "rtsp_password=admin123\nwifi_key=SuperSecret\nadmin_token=deadbeef\n"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin/config":
            # VULNERABLE: no authentication check.
            self._send(200, SECRETS)
        elif self.path == "/":
            self._send(200, "IP Camera Web UI")
        else:
            self._send(404, "not found")
    def _send(self, code, body):
        self.send_response(code); self.send_header("Content-Type","text/plain"); self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
socketserver.TCPServer(("0.0.0.0",8080),H).serve_forever()
