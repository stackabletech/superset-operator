import logging
import sys
import requests

from bs4 import BeautifulSoup

logging.basicConfig(
    level='DEBUG',
    format="%(asctime)s %(levelname)s: %(message)s",
    stream=sys.stdout)

namespace = sys.argv[1]
expected_roles = set(sys.argv[2].split(','))

session = requests.Session()

# Click on "Login" in Superset
login_page = session.get(f'http://superset-external.{namespace}.svc.cluster.local:8088/login/')
assert login_page.status_code == 200

login_page_html = BeautifulSoup(login_page.text, 'html.parser')
csrf_token = login_page_html.find('input',{'id':'csrf_token'})['value']

# Login with CSRF token
welcome_page = session.post(f'http://superset-external.{namespace}.svc.cluster.local:8088/login/', data={'username': 'admin','password': 'admin', 'csrf_token': csrf_token})
assert welcome_page.status_code == 200
logging.debug(welcome_page.url)

# Call an API that will trigger an update of user roles
session.get(f'http://superset-external.{namespace}.svc.cluster.local:8088/api/v1/dashboard/')

# Get user roles
user_roles = set(session.get(f'http://superset-external.{namespace}.svc.cluster.local:8088/api/v1/me/roles/').json()['result']['roles'].keys())
logging.debug('User roles:     %s', user_roles)
logging.debug('Expected roles: %s', expected_roles)
assert user_roles == expected_roles
