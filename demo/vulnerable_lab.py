"""Small user-accounts API.

DO NOT use any of this in a real project. The file exists so the audit
tool has something concrete to scan against.
"""

import hashlib
import json
import os
import pickle
import random
import re
import subprocess
import sqlite3
import traceback
import urllib.request

from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)

STRIPE_SECRET = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
DB_PASSWORD = "P@ssw0rd_2024!"


def _connect():
    return sqlite3.connect("/var/data/app.db")


@app.route("/users/<user_id>")
def get_user(user_id):
    conn = _connect()
    cur = conn.cursor()
    cur.execute(f"SELECT id, name, email FROM users WHERE id = {user_id}")
    row = cur.fetchone()
    return json.dumps(row) if row else ("not found", 404)


@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name LIKE '%" + name + "%'")
    return json.dumps(cur.fetchall())


@app.route("/session/restore", methods=["POST"])
def restore_session():
    blob = request.data
    state = pickle.loads(blob)
    return {"ok": True, "user": state.get("user")}


@app.route("/thumbnail", methods=["POST"])
def thumbnail():
    filename = request.form["file"]
    subprocess.check_call(
        f"/usr/bin/convert {filename} /tmp/thumb.png",
        shell=True,
    )
    return {"ok": True}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system(f"ping -c 1 {host}")
    return ""


@app.route("/notes/<name>")
def read_note(name):
    with open(f"/var/notes/{name}") as f:
        return f.read()


@app.route("/webhook/fetch")
def fetch_webhook():
    url = request.args.get("url", "")
    return urllib.request.urlopen(url).read()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


def can_delete(user, post):
    return (
        user.get("is_admin")
        or post.get("owner_id") == user.get("id")
        or user.get("role") == "moderator"
        or request.args.get("debug_admin")
    )


@app.route("/login/return")
def redirect_after_login():
    url = request.args.get("redirect", "/")
    return redirect(url)


@app.route("/api/process", methods=["POST"])
def api():
    try:
        return {"data": process(request.json)}
    except Exception as e:
        return {
            "error": str(e),
            "trace": traceback.format_exc(),
        }


@app.route("/posts/delete", methods=["POST"])
def delete_post():
    pid = request.form.get("id", "0")
    conn = _connect()
    conn.execute(f"DELETE FROM posts WHERE id = {pid}")
    conn.commit()
    return {"deleted": True}


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    return {"result": eval(expr)}


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string("Hello " + name + "!")


def looks_like_email(value):
    return bool(re.match(r"^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.[a-z]{2,}$", value))


def is_external_url(url):
    return url.startswith("http://") or url.startswith("https://")


@app.route("/profile", methods=["POST"])
def update_profile():
    user = {"name": "alice", "email": "a@b.test"}
    for k, v in request.form.items():
        user[k] = v
    return user


def process(data):
    return data


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
