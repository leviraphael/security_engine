import json

from flask import Flask, jsonify, request
from requests import get

from detections.ddos_detection import DDoSDetection
from detections.ip_detection import IpDetection
from detections.malicious_payload_detection import MaliciousPayloadDetection
from server import logging

app = Flask(__name__)
TARGET = "http://127.0.0.1:5000/"


app.config["detections"] = [IpDetection(), DDoSDetection(), MaliciousPayloadDetection()]


def detect(func):
    def wrapper(*args, **kwargs):
        payload = request.args
        data = json.loads(request.data.decode()) if request.data else None
        try:
            for detection in app.config["detections"]:
                detection.analyse(payload, data)
        except Exception as e:
            if type(e) == PermissionError:
                return jsonify({"error": "Access Denied"}), 403
            else:
                # To decide if we would like to block the traffic here when detection has raised an error
                logging.warning(
                    f"Detection of type {type(detection)} raises error {e} - Detection bypassed"
                )
        return func(*args, **kwargs)

    return wrapper


@app.route("/<path:path>", methods=["GET", "POST"])
@detect
def proxy(path):
    print(f"{TARGET}{path}")
    return get(f"{TARGET}{path}").content


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
