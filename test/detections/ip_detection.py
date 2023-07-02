from flask import request

from detections.threat_detection import ThreatDetection

ALLOWED_IPS = ["127.0.0.1", "192.168.0.1"]


class IpDetection(ThreatDetection):
    def __init__(self, allowed_ips=ALLOWED_IPS):
        super().__init__()
        self.allowed_ips = allowed_ips

    def analyse(self, *args, **kwargs):
        client_ip = request.remote_addr
        if client_ip not in self.allowed_ips:
            self.logging.error(f"Access denied ip {client_ip} not allowed")
            raise PermissionError()
