import requests
import sys
import logging
from bs4 import BeautifulSoup

logging.basicConfig(
    level='DEBUG',
    format="%(asctime)s %(levelname)s: %(message)s",
    stream=sys.stdout)

session = requests.Session()

# Click on "Sign In with keycloak" in Superset
login_page = session.get("http://superset-external:8088/login/keycloak?next=")

assert login_page.ok, "Redirection from Superset to Keycloak failed"
assert login_page.url.startswith("http://keycloak:8080/realms/superset/protocol/openid-connect/auth?response_type=code&client_id=superset"), \
    "Redirection to the Keycloak login page expected"

# Enter username and password into the Keycloak login page and click on "Sign In"
login_page_html = BeautifulSoup(login_page.text, 'parser.html')
authenticate_url = login_page_html.form['action']
welcome_page = session.post(authenticate_url, data = {
    "username": "test",
    "password": "test"
})

assert welcome_page.ok, "Login failed"
assert welcome_page.url == "http://superset-external:8088/superset/welcome/", \
    "Redirection to the Superset welcome page expected"
