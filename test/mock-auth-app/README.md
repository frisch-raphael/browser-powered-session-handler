# Mock Auth App

Small local app to test a redirect-based login flow.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

App starts on `http://127.0.0.1:5050/start`, which redirects to `/login`.

## Suggested token service settings

- Authentication URL: `http://127.0.0.1:5050/start`
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
