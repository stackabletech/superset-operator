import requests
import time

# Create and increase the superset_welcome counter
web_ui_response = requests.get("http://superset-node-default:8088/")
assert web_ui_response.status_code == 200, "Web UI could not be opened."

# Wait for the counter to be consumed by the statsd-exporter
time.sleep(2)

metrics_response = requests.get("http://superset-node-default:9102/metrics")
assert metrics_response.status_code == 200, "Metrics could not be retrieved."

assert "superset_welcome" in metrics_response.text, \
    "The metrics do not contain the superset_welcome counter."
