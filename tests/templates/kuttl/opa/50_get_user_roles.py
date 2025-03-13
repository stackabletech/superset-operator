#
# Use the FAB security API to create a new role named "Test".
# Use the UI to login and fetch the user roles (that are resolved from OPA).
# Check that that the user has both the "Admin" role as well as the newly created "Test" role.
#
import logging
import sys

import requests
from bs4 import BeautifulSoup

base_ui_url = ""
base_api_url = ""
bearer_token = ""
csrf_token = ""


def get_bearer_token() -> str:
    payload = {"password": "admin", "provider": "db", "username": "admin"}
    headers = {"Content-Type": "application/json"}
    response = requests.request(
        "POST", f"{base_api_url}/security/login", json=payload, headers=headers
    )
    json: dict[str, object] = response.json()
    logging.info(f"get_bearer_token response {json}")
    return str(json["access_token"])


def get_csrf_token() -> str:
    headers = {"Authorization": f"Bearer {bearer_token}"}
    response = requests.request(
        "GET", f"{base_api_url}/security/csrf_token/", data="", headers=headers
    )
    json: dict[str, object] = response.json()
    logging.info(f"get_csrf_token response {json}")
    return str(json["result"])


def add_role(name: str):
    headers = {
        "X-CSRFToken": csrf_token,
        "Authorization": f"Bearer {bearer_token}",
    }
    response = requests.request(
        "POST", f"{base_api_url}/security/roles", json={"name": name}, headers=headers
    )
    json: dict[str, object] = response.json()
    logging.info(f"add_role response {json}")


def add_permissions_to_role(role_id: int, permissions: list[int]):
    headers = {
        "X-CSRFToken": csrf_token,
        "Authorization": f"Bearer {bearer_token}",
    }
    response = requests.request(
        "POST",
        f"{base_api_url}/security/roles/{role_id}/permissions",
        json={"permission_view_menu_ids": permissions},
        headers=headers,
    )
    json: dict[str, object] = response.json()
    logging.info(f"add_permissions_to_role response {json}")


def get_ui_roles() -> list[str]:
    session = requests.Session()

    # Click on "Login" in Superset
    login_page = session.get(f"{base_ui_url}/login/")
    assert login_page.status_code == 200

    login_page_html = BeautifulSoup(login_page.text, "html.parser")
    csrf_token = login_page_html.find("input", id="csrf_token")
    if csrf_token is None:
        raise Exception("CSRF token not found in on the login page")
    else:
        csrf_token = csrf_token["value"]

    # Login with CSRF token
    welcome_page = session.post(
        f"{base_ui_url}/login/",
        data={"username": "admin", "password": "admin", "csrf_token": csrf_token},
    )
    assert welcome_page.status_code == 200
    logging.debug(welcome_page.url)

    # Force roles to be loaded by the OPA security manager
    # Assign to _ to shut up type checker
    _ = session.get(f"{base_api_url}/dashboard/")

    response = session.get(f"{base_api_url}/me/roles/")
    json: dict[str, object] = response.json()

    logging.info(f"get_ui_roles response {json}")

    return list(json["result"]["roles"].keys())


def main():
    logging.basicConfig(
        level="DEBUG",
        format="%(asctime)s %(levelname)s: %(message)s",
        stream=sys.stdout,
    )

    namespace = sys.argv[1]

    global base_ui_url
    global base_api_url
    global bearer_token
    global csrf_token

    base_ui_url = f"http://superset-external.{namespace}.svc.cluster.local:8088"
    base_api_url = f"http://superset-external.{namespace}.svc.cluster.local:8088/api/v1"
    bearer_token = get_bearer_token()
    csrf_token = get_csrf_token()

    # Create a new role and assign some permissions to it
    add_role("Test")
    # "6" is the new role id (Superset has 5 builtin roles)
    add_permissions_to_role(6, list(range(3)))

    ui_user_roles = get_ui_roles()

    expected_roles = ["Admin", "Test"]
    logging.debug(f"Expected roles: {expected_roles}")
    logging.debug(f"Got UI user roles: {ui_user_roles}")
    assert expected_roles == ui_user_roles


if __name__ == "__main__":
    main()
