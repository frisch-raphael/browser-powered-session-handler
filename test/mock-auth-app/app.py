from flask import Flask, jsonify, make_response, redirect, request
import time


app = Flask(__name__)
USERS = {
    "user": {
        "password": "pass",
        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODAwMDAwMDB9.sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "cookie_token": "cookie.jwt.mock.value.user",
    },
    "user2": {
        "password": "pass2",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE4ODAwMDAwMDB9.user2_mock_signature",
        "cookie_token": "cookie.jwt.mock.value.user2",
    },
    "admin": {
        "password": "adminpass",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJleHAiOjE5ODAwMDAwMDB9.admin_mock_signature",
        "cookie_token": "cookie.jwt.mock.value.admin",
    },
}


@app.get("/")
def index():
    return redirect("/start", code=302)


@app.get("/data")
def data():
    return jsonify({"message": "This is some data."})


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


@app.get("/cookie-protected")
def cookie_protected():
    token_cookie = (request.cookies.get("mock_access_token") or "").strip()
    accepted = {u["cookie_token"] for u in USERS.values()}
    if token_cookie not in accepted:
        return make_response(jsonify({"error": "missing or invalid token cookie"}), 401)
    return jsonify({"message": "Cookie auth accepted"})


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
