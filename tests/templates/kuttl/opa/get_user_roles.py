import logging
import os
import sys
import requests

from bs4 import BeautifulSoup

logging.basicConfig(
    level='DEBUG',
    format="%(asctime)s %(levelname)s: %(message)s",
    stream=sys.stdout)

superset_base_url = os.getenv('SUPERSET_BASE_URL', 'localhost:8088')

session = requests.Session()

# Click on "Login" in Superset
login_page = session.get(f'http://{superset_base_url}/login/')
assert login_page.status_code == 200

login_page_html = BeautifulSoup(login_page.text, 'html.parser')
csrf_token = login_page_html.find('input',{'id':'csrf_token'})['value']

# Login with CSRF token
welcome_page = session.post(f'http://{superset_base_url}/login/', data={'username': 'admin','password': 'admin', 'csrf_token': csrf_token})
assert welcome_page.status_code == 200

# Get user roles
user_roles = set(session.get(f'http://{superset_base_url}/api/v1/me/roles/').json()['result']['roles'].keys())
assert user_roles == {'Admin', 'Test'}
