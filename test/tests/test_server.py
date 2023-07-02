import pytest

from detections.ddos_detection import DDoSDetection, MAX_REQUEST_PER_MINUTE
from detections.enumeration_detection import (
    EnumerationDetection,
    MAX_INCORRECT_REQUESTS,
)
from detections.ip_detection import IpDetection
from detections.malicious_payload_detection import MaliciousPayloadDetection
from detections.user_agent_detection import UserAgentDetection

from proxy import app

TARGET_ENDPOINT = "/api/endpoint"


@pytest.fixture
def client(request):
    app.config["detections"] = request.param
    with app.test_client() as client:
        yield client


@pytest.mark.parametrize(
    "client", [[MaliciousPayloadDetection()]], indirect=True, ids=["malicious payload"]
)
def test_malicious_payload(client):
    params = [{}, {"malicious": "params"}]
    for payload in params:
        response = client.get(TARGET_ENDPOINT, json=payload)
        assert response.status_code == 403 if bool(payload) else 200


@pytest.mark.parametrize(
    "client", [[], [DDoSDetection()]], indirect=True, ids=["no detection", "ddos only"]
)
def test_endpoint_with_detection(client, request):
    for i in range(MAX_REQUEST_PER_MINUTE + 3
                   ):
        response = client.get(TARGET_ENDPOINT)
        if "ddos only" in request.node.name and i >= MAX_REQUEST_PER_MINUTE + 1:
            assert response.status_code == 403
        else:
            assert response.status_code == 200


@pytest.mark.parametrize(
    "client", [[EnumerationDetection()]], indirect=True, ids=["enumeration"]
)
def test_enumeration(client):
    for i in range(MAX_INCORRECT_REQUESTS + 2):
        response = client.get("/api/invalid_endpoint")
        if i == MAX_INCORRECT_REQUESTS + 1:
            assert response.status_code == 403
        else:
            assert response.status_code == 200


@pytest.mark.parametrize(
    "client",
    [[UserAgentDetection(["*"])], [UserAgentDetection(["not_white_listed"])]],
    indirect=True,
    ids=["wl", "not_wl"],
)
def test_user_agent_detection(client, request):
    response = client.get(TARGET_ENDPOINT)
    assert response.status_code == 403 if "not_wl" in request.node.name else 200


@pytest.mark.parametrize(
    "client",
    [[IpDetection(["127.0.0.1"])], [IpDetection(["127.0.2.2"])]],
    indirect=True,
    ids=["wl", "not_wl"],
)
def test_ip_detection(client, request):
    response = client.get(TARGET_ENDPOINT)
    assert response.status_code == 403 if request.node.name == "not_wl" else 200
