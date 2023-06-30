from detections.threat_detection import ThreatDetection

ALLOWED_ENDPOINTS = ["/api/endpoint"]


class EnumerationDetection(ThreatDetection):
    def analyse(self):
        pass
