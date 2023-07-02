# Task

Create an inline security engine that monitors, analyses and potentially blocks incoming API requests based on their identified risks.


# Solution

Create a proxy server handling requests - analyse all requests (GET/POST - assumption) with different threat detections:
* Allowed IPs
* User agent detection
*  DDoS detection:
    * Limit amount of requests per minute for this server MAX_REQUEST_PER_MINUTE = 5
* Malicious payload
    * Block requests where payload is malicious based on MALICIOUS_PAYLOAD list (configurable)
* Enumeration 
    * Limit amount of invalid request per IP (assumption for this example  - used as unique identifier should be improved in case of VPN)
* User agent detection
    * Block malicious user agents


# Technical solution
The main business logic is based on a wrapper:
The wrapper goal is to decide wether to block the requests or not.
The wrapper goes over list of dectections can be easily extended (Need to add a class of type ThreatDetection and to implement the dectection logic)
ThreatDetection.analyse(*args,**kwargs) will raise a PermissonError if the engine decides so. In this case the user will get Forbidden access and the 
request will be blocked

Main logic:

``` python
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
```

To extend the logic use this class:

``` python
class ThreatDetection(abc.ABC):
    def __init__(self):
        self.logging = get_logger()

    @abc.abstractmethod
    def analyse(self, *args, **kwargs):
        raise NotImplementedError()
```

Assumption - All logics are managed in memory but should improved to work with database in case.

# Deployment

```
git clone https://github.com/leviraphael/security_engine.git
```
Note: Python version supported 3.8

Install requirements:
```
pip install -r requirements.txt
```

Deploy dummy server under protection:
```
python server.py
```

Deploy proxy server:
```
python proxy.py
```

Now you app is UP and running (hopefully port and not in used)- check using browser:

```
http://127.0.0.1:8080/api/endpoint
```


Create main with multiple requests (example can be found under tests/requests_samples.py)
By changing request types (GET/POST) or payloads

# Tests

In order to test the application, all pytest are located under tests folder (one postive and negative test for each detection - should be expanded)
```
pytest tests/test_server.py
```

# Monitor
All logs are written in /tmp/app.log file (it will be used as monitor base - should be send to real tool with analysis/monitor capabilities to get alert in real time)

# Future work
1. Extend the number of detections (TLS protocol, server side request forgery, weak encryption, ...)
2. Block IPs after detection (for example after DDoS attack, add the IP to blocked IP)
3. Extend tests coverage (currently one positive and negative for each detection)
4. Create a real monitor based on logs (stored properly in DB)
5. Use DB to store IPs and counters for (DDoS and enumeration attacks)
6. Add more logs 
7. Deploy the proxy on docker
