from flask import request

from detections.threat_detection import ThreatDetection

ALLOWED_UA = ["*"]


class UserAgentDetection(ThreatDetection):
    def __init__(self, allowed_ua=ALLOWED_UA):
        super().__init__()
        self.allowed_ua = allowed_ua

    def analyse(self, *args, **kwargs):
        user_agent = request.environ["HTTP_USER_AGENT"]
        if self.allowed_ua == ["*"]:
            return
        if user_agent not in self.allowed_ua:
            self.logging.error(
                f"User agent {user_agent} not allowed for IP {request.remote_addr}"
            )
            raise PermissionError()
