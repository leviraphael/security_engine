from flask import request

import datetime

from detections.threat_detection import ThreatDetection

MAX_REQUEST_PER_MINUTE = 5


class DDoSDetection(ThreatDetection):
    def __init__(self):
        super().__init__()
        self.request_counts = {}

    def analyse(self, *args, **kwargs):
        client_ip = request.remote_addr
        current_time = datetime.datetime.now()

        if client_ip in self.request_counts:
            count, last_request_time = self.request_counts[client_ip]
            if (
                current_time - last_request_time < datetime.timedelta(minutes=1)
                and count > MAX_REQUEST_PER_MINUTE
            ):
                # DDoS attack suggest to automatically update allowed ips
                self.logging.error(
                    f"Permissions errors DDoS Attempt with IP {client_ip}"
                )
                raise PermissionError()
            self.request_counts[client_ip] = (count + 1, last_request_time)
        else:
            self.request_counts[client_ip] = (1, current_time)

        return self.request_counts
