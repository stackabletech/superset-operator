"""Seed Superset with content before a product upgrade and verify it afterwards.

Usage: upgrade-test.py seed|verify

"seed" creates (idempotently, so kuttl assert retries are safe):
  * a database connection pointing at the metadata PostgreSQL
  * a physical dataset on the ab_user table
  * a table chart on that dataset, attached to a dashboard
  * a saved query
  * a custom role and a user holding it

"verify" runs after the upgrade and asserts that all of the above survived
the metadata database migrations and that a real SQL query still works.
"""

import logging
import sys

import requests

BASE_URL = "http://superset-node:8088"

DATABASE_NAME = "upgrade-test-database"
DATASET_TABLE = "ab_user"
CHART_NAME = "upgrade-test-chart"
DASHBOARD_TITLE = "upgrade-test-dashboard"
SAVED_QUERY_LABEL = "upgrade-test-saved-query"
SAVED_QUERY_SQL = "SELECT 1"
ROLE_NAME = "upgrade-test-role"
USER_NAME = "upgrade-test-user"
USER_PASSWORD = "upgrade-test-password"

logging.basicConfig(
    level="INFO", format="%(asctime)s %(levelname)s: %(message)s", stream=sys.stdout
)


def login(username, password):
    session = requests.Session()
    response = session.post(
        f"{BASE_URL}/api/v1/security/login",
        json={
            "username": username,
            "password": password,
            "provider": "db",
            "refresh": True,
        },
    )
    assert response.status_code == 200, f"Login of [{username}] failed: {response.text}"
    session.headers["Authorization"] = f"Bearer {response.json()['access_token']}"

    response = session.get(f"{BASE_URL}/api/v1/security/csrf_token/")
    assert response.status_code == 200, f"Fetching CSRF token failed: {response.text}"
    session.headers["X-CSRFToken"] = response.json()["result"]
    session.headers["Referer"] = BASE_URL

    return session


def find_by(session, endpoint, attribute, value):
    """Return the first item of a list endpoint whose attribute matches, else None."""
    response = session.get(f"{BASE_URL}/api/v1/{endpoint}/?q=(page_size:100)")
    assert response.status_code == 200, f"Listing [{endpoint}] failed: {response.text}"
    return next(
        (item for item in response.json()["result"] if item.get(attribute) == value),
        None,
    )


def create(session, endpoint, payload):
    response = session.post(f"{BASE_URL}/api/v1/{endpoint}/", json=payload)
    assert response.status_code == 201, f"Creating [{endpoint}] failed: {response.text}"
    return response.json()["id"]


def ensure(session, endpoint, attribute, value, payload):
    """Create an object unless an object with the same attribute value exists."""
    existing = find_by(session, endpoint, attribute, value)
    if existing:
        logging.info("[%s] with %s=%s already exists", endpoint, attribute, value)
        return existing["id"]
    object_id = create(session, endpoint, payload)
    logging.info("Created [%s] with %s=%s", endpoint, attribute, value)
    return object_id


def seed():
    session = login("admin", "admin")

    database_id = ensure(
        session,
        "database",
        "database_name",
        DATABASE_NAME,
        {
            "database_name": DATABASE_NAME,
            "sqlalchemy_uri": "postgresql://superset:superset@superset-postgresql:5432/superset",
            "expose_in_sqllab": True,
        },
    )

    dataset_id = ensure(
        session,
        "dataset",
        "table_name",
        DATASET_TABLE,
        {"database": database_id, "schema": "public", "table_name": DATASET_TABLE},
    )

    dashboard_id = ensure(
        session,
        "dashboard",
        "dashboard_title",
        DASHBOARD_TITLE,
        {"dashboard_title": DASHBOARD_TITLE, "published": True},
    )

    ensure(
        session,
        "chart",
        "slice_name",
        CHART_NAME,
        {
            "slice_name": CHART_NAME,
            "datasource_id": dataset_id,
            "datasource_type": "table",
            "viz_type": "table",
            "params": "{}",
            "dashboards": [dashboard_id],
        },
    )

    ensure(
        session,
        "saved_query",
        "label",
        SAVED_QUERY_LABEL,
        {"label": SAVED_QUERY_LABEL, "sql": SAVED_QUERY_SQL, "db_id": database_id},
    )

    role_id = ensure(session, "security/roles", "name", ROLE_NAME, {"name": ROLE_NAME})
    gamma_role = find_by(session, "security/roles", "name", "Gamma")
    assert gamma_role, "Built-in Gamma role not found."

    ensure(
        session,
        "security/users",
        "username",
        USER_NAME,
        {
            "username": USER_NAME,
            "password": USER_PASSWORD,
            "first_name": "Upgrade",
            "last_name": "Test",
            "email": "upgrade-test@superset.com",
            "active": True,
            "roles": [gamma_role["id"], role_id],
        },
    )


def verify():
    session = login("admin", "admin")

    database = find_by(session, "database", "database_name", DATABASE_NAME)
    assert database, f"Database [{DATABASE_NAME}] not found after upgrade."

    dataset = find_by(session, "dataset", "table_name", DATASET_TABLE)
    assert dataset, f"Dataset [{DATASET_TABLE}] not found after upgrade."

    # Run an actual SQL query against the dataset to prove that the upgraded
    # installation can still query data, not just serve its metadata.
    response = session.post(
        f"{BASE_URL}/api/v1/chart/data",
        json={
            "datasource": {"id": dataset["id"], "type": "table"},
            "queries": [{"columns": ["username"], "row_limit": 10}],
            "result_format": "json",
            "result_type": "full",
        },
    )
    assert response.status_code == 200, f"Chart data query failed: {response.text}"
    data = response.json()["result"][0]["data"]
    assert data, "Chart data query returned no rows."
    logging.info("Chart data query returned %d rows", len(data))

    chart = find_by(session, "chart", "slice_name", CHART_NAME)
    assert chart, f"Chart [{CHART_NAME}] not found after upgrade."
    response = session.get(f"{BASE_URL}/api/v1/chart/{chart['id']}")
    assert response.status_code == 200, f"Fetching chart failed: {response.text}"
    dashboard_titles = [
        dashboard["dashboard_title"]
        for dashboard in response.json()["result"].get("dashboards", [])
    ]
    assert DASHBOARD_TITLE in dashboard_titles, (
        f"Chart [{CHART_NAME}] is no longer attached "
        f"to dashboard [{DASHBOARD_TITLE}]: {dashboard_titles}"
    )

    dashboard = find_by(session, "dashboard", "dashboard_title", DASHBOARD_TITLE)
    assert dashboard, f"Dashboard [{DASHBOARD_TITLE}] not found after upgrade."

    saved_query = find_by(session, "saved_query", "label", SAVED_QUERY_LABEL)
    assert saved_query, f"Saved query [{SAVED_QUERY_LABEL}] not found after upgrade."
    response = session.get(f"{BASE_URL}/api/v1/saved_query/{saved_query['id']}")
    assert response.status_code == 200, f"Fetching saved query failed: {response.text}"
    assert response.json()["result"]["sql"] == SAVED_QUERY_SQL, (
        "Saved query SQL changed after upgrade."
    )

    user = find_by(session, "security/users", "username", USER_NAME)
    assert user, f"User [{USER_NAME}] not found after upgrade."
    role_names = [role["name"] for role in user.get("roles", [])]
    assert ROLE_NAME in role_names, (
        f"User [{USER_NAME}] lost role [{ROLE_NAME}] after upgrade: {role_names}"
    )

    # The seeded user must still be able to log in with the FAB version
    # shipped in the new Superset version.
    user_session = login(USER_NAME, USER_PASSWORD)
    response = user_session.get(f"{BASE_URL}/api/v1/me/")
    assert response.status_code == 200, f"Fetching own user failed: {response.text}"

    logging.info("All seeded objects survived the upgrade.")


if __name__ == "__main__":
    if sys.argv[1:] == ["seed"]:
        seed()
    elif sys.argv[1:] == ["verify"]:
        verify()
    else:
        sys.exit(f"Usage: {sys.argv[0]} seed|verify (got {sys.argv[1:]})")
