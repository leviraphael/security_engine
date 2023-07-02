from flask import request

from detections.threat_detection import ThreatDetection

MALICIOUS_PAYLOAD = ["malicious"]


class MaliciousPayloadDetection(ThreatDetection):
    def analyse(self, *args, **kwargs):
        if args:
            params_and_values = []
            for i in range(len(args)):
                if args[i]:
                    # To support parameter from GET parameters and data/json from POST request
                    params_and_values.extend(list(args[i].keys()))
                    params_and_values.extend(args[i].values())
            if any(value in MALICIOUS_PAYLOAD for value in params_and_values):
                self.logging.error(f"Malicious payload detected for IP {request.remote_addr}")
                raise PermissionError()
