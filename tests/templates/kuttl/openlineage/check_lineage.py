#!/usr/bin/env python
"""Trigger a SQL Lab query and assert that OpenLineage events reached the test receiver.

Runs inside the `python` testing-tools pod. It:
  1. logs in to Superset and gets a JWT access token,
  2. registers the Postgres metadata database as a SQL Lab data source (idempotent),
  3. runs a synchronous SELECT against `public.ab_user`,
  4. polls the test receiver's `/events` endpoint until it has captured a terminal
     `COMPLETE` OpenLineage event for that query (the SQL text is embedded in the event's
     SQL facet, so we match on it to prove the event came from *our* query).

Emission is driven by the `superset_openlineage` module wired into `superset_config.py`
(QUERY_LOGGER + EVENT_LOGGER): a SQL Lab `execute_sql` produces a START and a COMPLETE
RunEvent, POSTed by the OpenLineage HTTP client to `$OPENLINEAGE_URL/api/v1/lineage`.
"""

import argparse
import sys
import time

import requests

SUPERSET_URL = "http://superset-node:8088"
DATABASE_NAME = "postgresql-openlineage"
SQLALCHEMY_URI = "postgresql+psycopg2://superset:superset@superset-postgresql:5432/superset"
# A table that always exists in the Superset metadata database. The SQL text is echoed back
# in the emitted event's SQL facet, so we can match on it at the receiver.
QUERY_SQL = "SELECT username FROM public.ab_user LIMIT 1"
QUERY_MARKER = "ab_user"


def new_session(base_url: str) -> requests.Session:
    """Log in and return a session ready for state-changing API calls.

    Superset protects its write endpoints (database registration, SQL Lab execute) with
    Flask-WTF CSRF, which needs three things sent together: the JWT bearer token, the
    `X-CSRFToken` header, and the session cookie the CSRF-token endpoint sets. A shared
    `Session` keeps that cookie; `Referer` is required by the CSRF check too.
    """
    session = requests.Session()

    resp = session.post(
        f"{base_url}/api/v1/security/login",
        json={"username": "admin", "password": "admin", "provider": "db", "refresh": "true"},
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    session.headers.update({"Authorization": f"Bearer {token}", "Referer": base_url})

    csrf = session.get(f"{base_url}/api/v1/security/csrf_token/", timeout=10)
    csrf.raise_for_status()
    session.headers.update({"X-CSRFToken": csrf.json()["result"]})

    return session


def get_database_id(session: requests.Session, base_url: str) -> int | None:
    """Return the id of our registered database, or None if it is not registered yet."""
    resp = session.get(f"{base_url}/api/v1/database/", timeout=10)
    resp.raise_for_status()
    for db in resp.json().get("result", []):
        if db.get("database_name") == DATABASE_NAME:
            return db["id"]
    return None


def ensure_database(session: requests.Session, base_url: str) -> int:
    """Register the metadata database for SQL Lab (idempotent) and return its id."""
    existing = get_database_id(session, base_url)
    if existing is not None:
        return existing
    resp = session.post(
        f"{base_url}/api/v1/database/",
        json={
            "database_name": DATABASE_NAME,
            "sqlalchemy_uri": SQLALCHEMY_URI,
            "expose_in_sqllab": True,
        },
        timeout=30,
    )
    if resp.status_code < 300:
        return resp.json()["id"]
    # A concurrent/previous run may have created it between our check and our POST.
    existing = get_database_id(session, base_url)
    if existing is not None:
        return existing
    raise RuntimeError(f"Could not register database: {resp.status_code} {resp.text}")


def run_query(session: requests.Session, base_url: str, database_id: int) -> None:
    resp = session.post(
        f"{base_url}/api/v1/sqllab/execute/",
        json={"database_id": database_id, "runAsync": False, "sql": QUERY_SQL},
        timeout=60,
    )
    print(f"Query response: {resp.status_code} {resp.text[:500]}")
    resp.raise_for_status()


def receiver_has_lineage(receiver_url: str) -> bool:
    resp = requests.get(f"{receiver_url}/events", timeout=10)
    if resp.status_code != 200:
        return False
    body = resp.text
    return QUERY_MARKER in body and "COMPLETE" in body


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Superset OpenLineage lineage check")
    parser.add_argument("--superset-url", default=SUPERSET_URL)
    parser.add_argument(
        "--receiver-url",
        required=True,
        help="Base URL of the OpenLineage test receiver, e.g. http://openlineage-receiver:5000",
    )
    opts = parser.parse_args()

    deadline = time.time() + 300
    while time.time() < deadline:
        try:
            session = new_session(opts.superset_url)
            database_id = ensure_database(session, opts.superset_url)
            run_query(session, opts.superset_url, database_id)

            if receiver_has_lineage(opts.receiver_url):
                print("OpenLineage events for the query were received.")
                sys.exit(0)
        except Exception as e:  # noqa: BLE001
            print(f"Retrying after error: {e}")

        time.sleep(10)

    # Timed out - dump what the receiver captured to aid debugging.
    try:
        dump = requests.get(f"{opts.receiver_url}/events", timeout=10).text
        print(f"Receiver events at timeout:\n{dump}")
    except Exception as e:  # noqa: BLE001
        print(f"Could not read receiver events: {e}")
    print("Timed out waiting for OpenLineage events at the receiver.")
    sys.exit(1)
