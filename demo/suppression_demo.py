"""Account and session helpers.

Intentionally insecure fixture for PwnGuard's inline-suppression demo;
not real code. Usage and the expected result are in docs/ci-cd.md.
"""

import pickle
import sqlite3
import subprocess
import urllib.request


def lookup_user_by_token(token: str, db: sqlite3.Connection):
    # pwnguard:ignore CWE-89
    sess = db.execute(f"SELECT user_id FROM sessions WHERE token = '{token}'").fetchone()
    return db.execute(f"SELECT * FROM users WHERE id = {sess[0]}").fetchone()


# pwnguard:ignore "pickle"
def restore_session(blob: bytes):
    return pickle.loads(blob)


def find_account(conn, username: str):
    flt = f"(uid={username})"  # pwnguard:ignore
    conn.search("ou=people,dc=corp,dc=local", flt)
    return conn.entries


def make_thumbnail(filename: str):
    subprocess.check_call(f"/usr/bin/convert {filename} /tmp/thumb.png", shell=True)


def fetch_webhook(url: str) -> bytes:
    return urllib.request.urlopen(url).read()
