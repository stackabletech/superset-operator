#
# Use the FAB security API to create a new role named "Test" and assign it to the "admin" user.
#
# Use the UI to login and fetch all roles assigned to the user that is logged in (admin).
#
# Compare that the FAB API roles and the UI roles (that are resolved from OPA) are the same.
#
import logging
import sys

import requests
from bs4 import BeautifulSoup

base_ui_url = ""
base_api_url = ""
bearer_token = ""
csrf_token = ""


def get_bearer_token():
    payload = {"password": "admin", "provider": "db", "username": "admin"}
    headers = {"Content-Type": "application/json"}
    response = requests.request(
        "POST", f"{base_api_url}/security/login", json=payload, headers=headers
    )
    return response.json()["access_token"]


def get_csrf_token():
    headers = {"Authorization": f"Bearer {bearer_token}"}
    response = requests.request(
        "GET", f"{base_api_url}/security/csrf_token/", data="", headers=headers
    )
    return response.json()["result"]


def add_role(name: str):
    headers = {
        "X-CSRFToken": csrf_token,
        "Authorization": f"Bearer {bearer_token}",
    }
    response = requests.request(
        "POST", f"{base_api_url}/security/roles", json={"name": name}, headers=headers
    )
    return response.json()


def add_permissions_to_role(role_id, permissions):
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
    return response.json()


def get_roles():
    headers = {
        "X-CSRFToken": csrf_token,
        "Authorization": f"Bearer {bearer_token}",
    }

    return requests.request(
        "GET", f"{base_api_url}/security/users/1", headers=headers
    ).json()["result"]["roles"]


def set_user_roles(roles: list[int]):
    headers = {
        "X-CSRFToken": csrf_token,
        "Authorization": f"Bearer {bearer_token}",
    }
    result = requests.request(
        "PUT",
        f"{base_api_url}/security/users/1",
        headers=headers,
        json={"username": "admin", "password": "admin", "roles": roles},
    ).json()

    logging.info(f"Result of setting the roles {roles} to user: {result}")


def get_ui_roles() -> list[str]:
    session = requests.Session()

    # Click on "Login" in Superset
    login_page = session.get(f"{base_ui_url}/login/")
    assert login_page.status_code == 200

    login_page_html = BeautifulSoup(login_page.text, "html.parser")
    csrf_token = login_page_html.find("input", {"id": "csrf_token"})["value"]

    # Login with CSRF token
    welcome_page = session.post(
        f"{base_ui_url}/login/",
        data={"username": "admin", "password": "admin", "csrf_token": csrf_token},
    )
    assert welcome_page.status_code == 200
    logging.debug(welcome_page.url)

    return list(
        session.get(f"{base_api_url}/me/roles/").json()["result"]["roles"].keys()
    )


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
    add_permissions_to_role(6, list(range(3)))

    # Add the new role to the admin user.
    # "1" is the existing "Admin" role id.
    # "6" is the id of the new "Test" role.
    set_user_roles([1, 6])

    api_user_roles = [role["name"] for role in get_roles()]
    ui_user_roles = get_ui_roles()

    expected_roles = ["Admin", "Test"]
    logging.debug(f"Expected roles: {expected_roles}")
    logging.debug(f"Got API user roles: {api_user_roles}")
    logging.debug(f"Got UI user roles: {ui_user_roles}")
    assert api_user_roles == ui_user_roles
    assert expected_roles == ui_user_roles


if __name__ == "__main__":
    main()
