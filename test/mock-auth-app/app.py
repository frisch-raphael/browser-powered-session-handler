from flask import Flask, jsonify, make_response, redirect, request
import time


app = Flask(__name__)


@app.get("/")
def index():
    return redirect("/start", code=302)


@app.get("/start")
def start():
    time.sleep(1)
    return redirect("/login", code=302)


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
        <p>Use username <strong>user</strong> and password <strong>pass</strong>.</p>
        <form method="post" action="/token">
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
    if username != "user" or password != "pass":
        return make_response("Invalid credentials", 401)

    token_value = f"mock-token-{int(time.time())}"
    resp = make_response(
        jsonify({"access_token": token_value, "token_type": "bearer"}))
    resp.set_cookie("mock_session", "ok", httponly=True)
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7577, debug=True)
