from flask import Flask, request, redirect, make_response
import subprocess
import os
import sqlite3
import tempfile
import yaml  # PyYAML, unsafe usage below

app = Flask(__name__)

DB_PATH = "users.db"

# --- Helper to set up a tiny, insecure DB (for demo only) ---
def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
        conn.commit()
        conn.close()

# 1. SQL INJECTION
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Intentionally vulnerable to SQL injection via 'username' and 'password' fields.
    Example payload (for testing in tools / scanners):
      username=' OR 1=1 --
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ❌ VULNERABLE: direct string interpolation into SQL
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(query)  # SQL injection vulnerability
        row = cur.fetchone()
        conn.close()

        if row:
            return f"Welcome, {row[1]}!"
        else:
            return "Invalid credentials", 401

    return """
    <form method="POST">
      <input name="username" placeholder="username" />
      <input name="password" type="password" placeholder="password" />
      <button type="submit">Login</button>
    </form>
    """

# 2. COMMAND INJECTION
@app.route("/run-cmd")
def run_cmd():
    """
    Command execution via 'cmd' query parameter.
    Example: /run-cmd?cmd=ls
    """
    cmd = request.args.get("cmd", "echo no-command-provided")

    # ❌ VULNERABLE: shell=True with user-controlled input
    result = subprocess.check_output(cmd, shell=True, text=True)
    return f"<pre>{result}</pre>"

# 3. PATH TRAVERSAL
@app.route("/read-file")
def read_file():
    """
    Reads a file from 'filename' query param without validation.
    Example: /read-file?filename=app.py
    """
    filename = request.args.get("filename", "")

    # ❌ VULNERABLE: no validation, allows ../../etc/passwd style traversal
    try:
        with open(filename, "r") as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        return f"Error: {e}", 500

# 4. OPEN REDIRECT
@app.route("/redirect")
def open_redirect():
    """
    Open redirect via 'next' parameter.
    Example: /redirect?next=https://evil.com
    """
    target = request.args.get("next", "/")

    # ❌ VULNERABLE: unvalidated redirect
    return redirect(target)

# 5. UNSAFE YAML DESERIALIZATION
@app.route("/yaml-load", methods=["POST"])
def yaml_load():
    """
    Insecure deserialization with yaml.load.
    Send raw YAML in the body.
    """
    data = request.data

    # ❌ VULNERABLE: unsafe yaml.load on untrusted data
    obj = yaml.load(data, Loader=yaml.FullLoader)
    return f"Loaded object: {obj}"

# 6. XSS VIA UNSAFE REFLECTION
@app.route("/greet")
def greet():
    """
    Reflected XSS via 'name' param.
    Example: /greet?name=<script>alert(1)</script>
    """
    name = request.args.get("name", "World")

    # ❌ VULNERABLE: directly embedding user input in HTML
    html = f"<h1>Hello, {name}!</h1>"
    response = make_response(html)
    response.headers["Content-Type"] = "text/html"
    return response

if __name__ == "__main__":
    init_db()
    # ❌ debug=True on purpose (info leakage, etc.)
    app.run(host="0.0.0.0", port=5000, debug=True)
