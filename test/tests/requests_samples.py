import requests

url = 'http://127.0.0.1:8080/api/endpoint'
payload = {
    'param1': 'value1',
    'param2': 'test'
}

response = requests.post(url, json=payload)

print(response.status_code)
print(response.text)