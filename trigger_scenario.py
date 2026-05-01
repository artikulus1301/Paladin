import requests
import sys

url = "http://localhost:8888/api/scenario"
payload = {"scenario": "brute_force", "source": "logs"}
if len(sys.argv) > 1:
    payload["scenario"] = sys.argv[1]
if len(sys.argv) > 2:
    payload["source"] = sys.argv[2]

try:
    r = requests.post(url, json=payload)
    print(r.status_code, r.text)
except Exception as e:
    print(f"Error: {e}")
