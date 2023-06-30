import pytest

from detections.ddos_detection import DDoSDetection, MAX_REQUEST_PER_MINUTE
from detections.malicious_payload_detection import MaliciousPayloadDetection
from proxy import app


@pytest.fixture
def client(request):
    app.config["detections"] = request.param
    with app.test_client() as client:
        yield client


@pytest.mark.parametrize(
    "client", [[DDoSDetection()]], indirect=True, ids=["ddos only"]
)
def test_ddos(client):
    for i in range(7):
        response = client.get("/api/endpoint")
    assert response.status_code == 403


@pytest.mark.parametrize(
    "client", [[MaliciousPayloadDetection()]], indirect=True, ids=["malicious payload"]
)
def test_malicious_payload(client):
    params = [{}, {"malicious": "params"}]
    for payload in params:
        response = client.get("/api/endpoint", json=payload)
        assert response.status_code == 403 if bool(payload) else 200


@pytest.mark.parametrize(
    "client", [[], [DDoSDetection()]], indirect=True, ids=["no detection", "ddos only"]
)
def test_endpoint_with_detection(client, request):
    for i in range(10):
        response = client.get("/api/endpoint")
        if "ddos only" in request.node.name and i >= MAX_REQUEST_PER_MINUTE + 1:
            assert response.status_code == 403
        else:
            assert response.status_code == 200
