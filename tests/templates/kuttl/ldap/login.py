import requests
import sys
import logging

if __name__ == "__main__":
    result = 0

    log_level = 'DEBUG'  # if args.debug else 'INFO'
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s', stream=sys.stdout)

    http_code = requests.post(f"http://superset-with-ldap-node-default:8088/api/v1/security/login", json={
        "username": "integrationtest",
        "password": "integrationtest",
        "provider": "ldap",
        "refresh": "true",
    }).status_code
    if http_code != 200:
        result = 1

    sys.exit(result)
