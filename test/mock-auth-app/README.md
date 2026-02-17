# Mock Auth App

Small local app to test a redirect-based login flow.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

App starts on `http://127.0.0.1:7577/start`, which redirects to `/login`.

## Suggested token service settings

- Authentication URL: `http://127.0.0.1:7577/start`
- Token URL substring: `/token`
- JSON path: `access_token`

Example steps:

```json
[
  {"type": "wait_url", "selector": "", "value": "**/login"},
  {"type": "wait_selector", "selector": "input#user", "value": ""},
  {"type": "input", "selector": "input#user", "value": "user"},
  {"type": "secure_input", "selector": "input#pass", "value": "pass"},
  {"type": "click", "selector": "button#login", "value": ""},
  {"type": "wait_time", "selector": "", "value": "500"},
  {"type": "wait_load_state", "selector": "", "value": "networkidle"}
]
```

Credentials for JSON mode:

- `user / pass`
- `user2 / pass2`
- `admin / adminpass`

## Cookie-based auth mode

Use this flow if you want to test `parsing.mode = cookie`.

- Authentication URL: `http://127.0.0.1:7577/cookie-start`
- Token URL substring: `/cookie-token`
- Parsing mode: `cookie`
- Cookie name: `mock_access_token`

Example steps:

```json
[
  {"type": "wait_url", "selector": "", "value": "**/cookie-login"},
  {"type": "wait_selector", "selector": "input#user", "value": ""},
  {"type": "input", "selector": "input#user", "value": "user"},
  {"type": "secure_input", "selector": "input#pass", "value": "pass"},
  {"type": "click", "selector": "button#cookie-login", "value": ""},
  {"type": "wait_load_state", "selector": "", "value": "networkidle"}
]
```

Credentials for cookie mode:

- `user / pass`
- `user2 / pass2`
- `admin / adminpass`

Protected test endpoint:

- `GET http://127.0.0.1:7577/cookie-protected`

## JWT-protected endpoint

For bearer-token mode testing:

- `GET http://127.0.0.1:7577/jwt-protected`

Behavior:

- Returns `200` only when `Authorization: Bearer <mock jwt>` is present and valid.
- Returns `401` when the bearer JWT is missing or invalid.

Both users have different JWTs (returned by `/token`) and both are accepted by `/jwt-protected`.

## WhoAmI endpoint

- `GET http://127.0.0.1:7577/whoami`

Behavior:

- Returns `200` with `{"user": "...", "auth_mode": "bearer|cookie"}` when authenticated.
- Accepts either:
  - `Authorization: Bearer <user jwt>`
  - `mock_access_token` cookie from cookie mode
- Returns `401` with `{"error":"unauthenticated"}` when no valid auth is present.

## Admin-only endpoint

- `GET http://127.0.0.1:7577/admin-only`

Behavior:

- Returns `200` only for the `admin` user (bearer or cookie auth).
- Returns `403` for authenticated non-admin users.
- Returns `401` when no valid auth is present.
