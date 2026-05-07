import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "api"
MOCK_DIR = ROOT / "test" / "mock-auth-app"
API_PORT = int(os.environ.get("BPSH_TEST_API_PORT", "7585"))
API_BASE = f"http://127.0.0.1:{API_PORT}"
MOCK_BASE = "http://127.0.0.1:7577"


@dataclass
class CookieTag:
    name: str
    api_config: dict
    token_request: dict
    output_cookie_name: str


def post_json(url, payload, timeout=30):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "text/plain"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8").strip()
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"POST {url} failed with HTTP {exc.code}: {error_body}") from exc


def get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8")


def is_up(url):
    try:
        get(url, timeout=2)
        return True
    except Exception:
        return False


def wait_until_up(url, deadline_seconds=20):
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if is_up(url):
            return
        time.sleep(0.25)
    raise RuntimeError(f"Service did not start: {url}")


def start_services():
    procs = []

    if not is_up(f"{MOCK_BASE}/data"):
        mock_python = MOCK_DIR / ".venv" / "Scripts" / "python.exe"
        python = str(mock_python if mock_python.exists() else sys.executable)
        procs.append(subprocess.Popen([python, "app.py"], cwd=MOCK_DIR))
        wait_until_up(f"{MOCK_BASE}/data")

    if not is_up(f"{API_BASE}/health"):
        api_python = API_DIR / "venv" / "Scripts" / "python.exe"
        python = str(api_python if api_python.exists() else sys.executable)
        procs.append(
            subprocess.Popen(
                [python, "-m", "uvicorn", "token_service:app", "--host", "127.0.0.1", "--port", str(API_PORT)],
                cwd=API_DIR,
            )
        )
        wait_until_up(f"{API_BASE}/health")

    return procs


def stop_services(procs):
    for proc in procs:
        proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def load_cookie_tag(path):
    saved = json.loads(path.read_text(encoding="utf-8"))
    api_config = {
        "token_url_substring": saved.get("authenticationServerUrlSubstring", ""),
        "refresh_frequency_seconds": saved["refreshFrequencySeconds"],
        "refresh_skew_seconds": saved["refreshSkewSeconds"],
        "nav_timeout_ms": saved["navTimeoutMs"],
        "wait_token_timeout_ms": saved["waitTokenTimeoutMs"],
        "parsing": {
            "mode": saved["tokenParsingMode"],
            "path": saved["tokenJsonPath"],
            "cookie_name": saved["tokenCookieName"],
        },
    }
    token_request = {
        "authentication_url": saved["authenticationUrl"],
        "headless": True,
        "proxy": "",
        "steps": saved["steps"],
        "mtls_enabled": saved["mtlsEnabled"],
        "mtls_hostname": saved["mtlsHostname"],
        "mtls_pin": saved["mtlsPin"],
        "mtls_cert_cn": saved.get("mtls_cert_cn", ""),
        "force": False,
    }
    return CookieTag(
        name=path.stem,
        api_config=api_config,
        token_request=token_request,
        output_cookie_name=saved["tokenCookieName"],
    )


def create_tag(tag):
    # Mirrors the user action of copying a tag while this configuration is selected.
    post_json(f"{API_BASE}/config", tag.api_config)
    return tag


def evaluate_tag(tag):
    # Public contract under test: evaluating a copied tag returns that tag's token value.
    token_request = dict(tag.token_request)
    token_request["token_config"] = tag.api_config
    return post_json(f"{API_BASE}/token", token_request)


def main():
    procs = start_services()
    try:
        first_tag = create_tag(load_cookie_tag(MOCK_DIR / "saved_steps_cookie.json"))
        second_tag = create_tag(load_cookie_tag(MOCK_DIR / "saved_steps_cookie_2.json"))

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(evaluate_tag, first_tag)
            second_future = executor.submit(evaluate_tag, second_tag)
            first_value = first_future.result()
            second_value = second_future.result()

        cookie_header = (
            f"{first_tag.output_cookie_name}={first_value}; "
            f"{second_tag.output_cookie_name}={second_value}"
        )
        status, body = get(
            f"{MOCK_BASE}/dual-cookie-protected",
            headers={"Cookie": cookie_header, "Accept": "application/json"},
        )
        if status != 200:
            raise AssertionError(f"Expected dual-cookie endpoint to accept both tags, got {status}: {body}")
        print(body)
    finally:
        stop_services(procs)


if __name__ == "__main__":
    main()
