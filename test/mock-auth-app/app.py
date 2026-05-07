from html import escape
import secrets
from urllib.parse import quote

from flask import Flask, jsonify, make_response, redirect, request
import time


app = Flask(__name__)
SSO_COOKIE_NAME = "mock_sso_session"
INITIAL_WRONG_SSO_COOKIE_VALUE = "wrong.sso.session.mock.value"
PENDING_SSO_TICKETS = {}
USERS = {
    "user": {
        "password": "pass",
        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODAwMDAwMDB9.sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "cookie_token": "cookie.jwt.mock.value.user",
        "second_cookie_token": "second.cookie.jwt.mock.value.user",
        "sso_session": "sso.session.mock.value.user",
    },
    "user2": {
        "password": "pass2",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE4ODAwMDAwMDB9.user2_mock_signature",
        "cookie_token": "cookie.jwt.mock.value.user2",
        "second_cookie_token": "second.cookie.jwt.mock.value.user2",
        "sso_session": "sso.session.mock.value.user2",
    },
    "admin": {
        "password": "adminpass",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJleHAiOjE5ODAwMDAwMDB9.admin_mock_signature",
        "cookie_token": "cookie.jwt.mock.value.admin",
        "second_cookie_token": "second.cookie.jwt.mock.value.admin",
        "sso_session": "sso.session.mock.value.admin",
    },
}


def safe_return_to(raw_value):
    value = (raw_value or "").strip()
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/data"
    return value


def sso_user_from_cookie():
    session_cookie = (request.cookies.get(SSO_COOKIE_NAME) or "").strip()
    for username, user in USERS.items():
        if session_cookie == user["sso_session"]:
            return username
    return None


@app.get("/")
def index():
    return redirect("/start", code=302)


@app.get("/data")
def data():
    sso_ticket = (request.args.get("sso_ticket") or "").strip()
    if sso_ticket:
        session_value = PENDING_SSO_TICKETS.pop(sso_ticket, None)
        if session_value is not None:
            resp = make_response(redirect("/data", code=302))
            resp.set_cookie(
                SSO_COOKIE_NAME,
                session_value,
                httponly=True,
                samesite="Lax",
                path="/",
            )
            return resp

    username = sso_user_from_cookie()
    if username is None:
        return_to = request.full_path
        if return_to.endswith("?"):
            return_to = return_to[:-1]
        resp = make_response(redirect(f"/sso-login?return_to={quote(return_to)}", code=302))
        resp.set_cookie(
            SSO_COOKIE_NAME,
            INITIAL_WRONG_SSO_COOKIE_VALUE,
            httponly=True,
            samesite="Lax",
            path="/",
        )
        return resp
    return jsonify({"message": "This is some data.", "user": username})


@app.get("/jwt-protected")
def jwt_protected():
    auth = (request.headers.get("Authorization") or "").strip()
    accepted = {f"Bearer {u['jwt']}" for u in USERS.values()}
    if auth not in accepted:
        return make_response(jsonify({"error": "missing or invalid bearer token"}), 401)
    return jsonify({"message": "JWT auth accepted"})


@app.get("/start")
def start():
    time.sleep(1)
    return redirect("/login", code=302)


@app.get("/cookie-start")
def cookie_start():
    time.sleep(1)
    return redirect("/cookie-login", code=302)


@app.get("/second-cookie-start")
def second_cookie_start():
    time.sleep(1)
    return redirect("/second-cookie-login", code=302)


@app.get("/401")
def unauthorized():
    return make_response("Unauthorized", 401)


@app.get("/login")
def login_form():
    return """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Mock Login</title>
      </head>
      <body>
        <h1>Mock Login</h1>
        <p>Use <strong>user/pass</strong>, <strong>user2/pass2</strong>, or <strong>admin/adminpass</strong>.</p>
        <form method="post" action="/token">
          <label>Username <input id="user" name="username" type="text" /></label><br />
          <label>Password <input id="pass" name="password" type="password" /></label><br />
          <button id="login" type="submit">Login</button>
        </form>
      </body>
    </html>
    """


@app.get("/sso-login")
def sso_login_form():
    return_to = safe_return_to(request.args.get("return_to"))
    return_to_attr = escape(return_to, quote=True)
    return f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Mock SSO Login</title>
      </head>
      <body>
        <h1>Mock SSO Login</h1>
        <p>Use <strong>user/pass</strong>, <strong>user2/pass2</strong>, or <strong>admin/adminpass</strong>.</p>
        <form method="post" action="/sso-login">
          <input name="return_to" type="hidden" value="{return_to_attr}" />
          <label>Username <input id="user" name="username" type="text" /></label><br />
          <label>Password <input id="pass" name="password" type="password" /></label><br />
          <button id="login" type="submit">Login</button>
        </form>
      </body>
    </html>
    """


@app.post("/sso-login")
def sso_login():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    return_to = safe_return_to(request.form.get("return_to"))
    user = USERS.get(username)
    if user is None or password != user["password"]:
        return make_response("Invalid credentials", 401)

    ticket = secrets.token_urlsafe(24)
    PENDING_SSO_TICKETS[ticket] = user["sso_session"]
    separator = "&" if "?" in return_to else "?"
    return redirect(f"{return_to}{separator}sso_ticket={quote(ticket)}", code=302)


@app.get("/cookie-login")
def cookie_login_form():
    return """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Mock Cookie Login</title>
      </head>
      <body>
        <h1>Mock Cookie Login</h1>
        <p>Use <strong>user/pass</strong>, <strong>user2/pass2</strong>, or <strong>admin/adminpass</strong>.</p>
        <form method="post" action="/cookie-token">
          <label>Username <input id="user" name="username" type="text" /></label><br />
          <label>Password <input id="pass" name="password" type="password" /></label><br />
          <button id="login" type="submit">Login</button>
        </form>
      </body>
    </html>
    """


@app.get("/second-cookie-login")
def second_cookie_login_form():
    return """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Mock Second Cookie Login</title>
      </head>
      <body>
        <h1>Mock Second Cookie Login</h1>
        <p>Use <strong>user/pass</strong>, <strong>user2/pass2</strong>, or <strong>admin/adminpass</strong>.</p>
        <form method="post" action="/second-cookie-token">
          <label>Username <input id="user" name="username" type="text" /></label><br />
          <label>Password <input id="pass" name="password" type="password" /></label><br />
          <button id="login" type="submit">Login</button>
        </form>
      </body>
    </html>
    """


@app.post("/token")
def token():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    user = USERS.get(username)
    if user is None or password != user["password"]:
        return make_response("Invalid credentials", 401)

    token_value = user["jwt"]
    resp = make_response(
        jsonify({"access_token": token_value, "token_type": "bearer"}))
    resp.set_cookie("mock_session", "ok", httponly=True)
    return resp


@app.post("/cookie-token")
def cookie_token():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    user = USERS.get(username)
    if user is None or password != user["password"]:
        return make_response("Invalid credentials", 401)
    token_value = user["cookie_token"]
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(
        "mock_access_token",
        token_value,
        httponly=True,
        samesite="Lax",
        path="/",
    )
    return resp


@app.post("/second-cookie-token")
def second_cookie_token():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    user = USERS.get(username)
    if user is None or password != user["password"]:
        return make_response("Invalid credentials", 401)
    token_value = user["second_cookie_token"]
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(
        "mock_second_access_token",
        token_value,
        httponly=True,
        samesite="Lax",
        path="/",
    )
    return resp


@app.get("/cookie-protected")
def cookie_protected():
    token_cookie = (request.cookies.get("mock_access_token") or "").strip()
    accepted = {u["cookie_token"] for u in USERS.values()}
    if token_cookie not in accepted:
        return make_response(jsonify({"error": "missing or invalid token cookie"}), 401)
    return jsonify({"message": "Cookie auth accepted"})


@app.get("/dual-cookie-protected")
def dual_cookie_protected():
    first_cookie = (request.cookies.get("mock_access_token") or "").strip()
    second_cookie = (request.cookies.get("mock_second_access_token") or "").strip()

    for username, user in USERS.items():
        if (
            first_cookie == user["cookie_token"]
            and second_cookie == user["second_cookie_token"]
        ):
            return jsonify({"message": "Dual cookie auth accepted", "user": username})

    return make_response(jsonify({"error": "missing or invalid token cookies"}), 401)


@app.get("/whoami")
def whoami():
    auth = (request.headers.get("Authorization") or "").strip()
    token_cookie = (request.cookies.get("mock_access_token") or "").strip()

    for username, user in USERS.items():
        if auth == f"Bearer {user['jwt']}":
            return jsonify({"user": username, "auth_mode": "bearer"})
        if token_cookie == user["cookie_token"]:
            return jsonify({"user": username, "auth_mode": "cookie"})

    return make_response(jsonify({"error": "unauthenticated"}), 401)


@app.get("/admin-only")
def admin_only():
    auth = (request.headers.get("Authorization") or "").strip()
    token_cookie = (request.cookies.get("mock_access_token") or "").strip()

    admin = USERS["admin"]
    if auth == f"Bearer {admin['jwt']}" or token_cookie == admin["cookie_token"]:
        return jsonify({"message": "Admin access granted"})

    # Distinguish unauthenticated from authenticated-but-not-admin.
    for user in USERS.values():
        if auth == f"Bearer {user['jwt']}" or token_cookie == user["cookie_token"]:
            return make_response(jsonify({"error": "forbidden"}), 403)

    return make_response(jsonify({"error": "unauthenticated"}), 401)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7577, debug=True)
