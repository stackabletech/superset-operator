import requests
import sys
import logging

logging.basicConfig(
    level="DEBUG", format="%(asctime)s %(levelname)s: %(message)s", stream=sys.stdout
)

http_code = requests.post(
    "http://superset-node-default:8088/api/v1/security/login",
    json={
        "password": "admin",
        "provider": "db",
        "refresh": "true",
        "username": "admin",
    },
).status_code

assert http_code == 200, "Login failed."
