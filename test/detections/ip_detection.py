from flask import request

from detections.threat_detection import ThreatDetection

ALLOWED_IPS = ["127.0.0.1", "192.168.0.1"]


class IpDetection(ThreatDetection):
    def analyse(self, *args, **kwargs):
        client_ip = request.remote_addr
        if client_ip not in ALLOWED_IPS:
            self.logging.error(f"Access denied ip {client_ip} not allowed")
            raise PermissionError()
