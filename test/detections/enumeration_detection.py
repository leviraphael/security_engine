from fuzzywuzzy import fuzz
from flask import request

from detections.threat_detection import ThreatDetection

ALLOWED_ENDPOINTS = ["/api/endpoint", "/favicon.ico"]
MAX_INCORRECT_REQUESTS = 5


class EnumerationDetection(ThreatDetection):
    def __init__(self):
        super().__init__()
        # Should be flush to disk/redis/db in case of server crash
        self.request_counts = {}

    def analyse(self, *args, **kwargs):
        client_ip = request.remote_addr
        if not self._is_correct_endpoint(request.path):
            if client_ip in self.request_counts:
                count = self.request_counts[client_ip]
                if count > MAX_INCORRECT_REQUESTS:
                    # Enumeration detected
                    self.logging.error(
                        f"Permissions errors enumeration attempt with IP {client_ip}"
                    )
                    raise PermissionError()
                self.request_counts[client_ip] = count + 1
            else:
                self.request_counts[client_ip] = 1

    def _is_correct_endpoint(self, current_endpoint):
        '''
        Using fuzzy logic to detect enumeration, instead of hardcoded detection in case
        of typos
        For example: /api/empoint --> Valid typo
                     /api/enumeration --> Should be blocked

        :param current_endpoint:

        '''
        ratio = max(
            fuzz.ratio(current_endpoint, endpoint) for endpoint in ALLOWED_ENDPOINTS
        )
        return ratio > 80
