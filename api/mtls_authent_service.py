import os
import sys
import time

from pywinauto import Desktop


def log(msg):
    print(msg)


def find_firefoxes():
    return Desktop(backend="uia").windows(class_name="MozillaWindowClass")


def get_pin_firefox(timeout_sec=10):
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        firefoxes = find_firefoxes()
        for firefox in firefoxes:
            firefox_spec = Desktop(backend="uia").window(handle=firefox.handle)
            try:
                candidate = firefox_spec.child_window(title_re=".*PKCS.*")
                if candidate.exists(timeout=0.2):
                    log("Found Firefox window with PKCS prompt")
                    return firefox
            except Exception:
                continue
        time.sleep(0.25)
    raise RuntimeError(
        "No Firefox window contains the requested child control.")


def run_mtls_auth(pin_code=None, cert_cn=None, hostname=None, timeout_sec=10):
    if os.name != "nt":
        raise RuntimeError("mTLS helper only supports Windows")
    if hostname:
        log("mTLS hostname: %s" % hostname)

    firefox = get_pin_firefox(timeout_sec=timeout_sec)
    firefox_spec = Desktop(backend="uia").window(handle=firefox.handle)

    firefox.click_input()
    if pin_code:
        edits = firefox_spec.descendants(control_type="Edit")
        if not edits:
            raise RuntimeError("PIN input field not found")
        edits[0].type_keys(pin_code, with_spaces=True, set_foreground=True)
        edits[0].type_keys("{ENTER}")

    cert_picker = firefox_spec.child_window(auto_id="nicknames")
    if not cert_picker.exists():
        raise RuntimeError("Certificate picker not found")
    cert_dialog = cert_picker.parent().parent()
    cert_picker.click_input()
    # time.sleep(0.25)
    chosen = None
    items = firefox_spec.descendants(control_type="ListItem")
    if cert_cn:
        for item in items:
            if cert_cn.lower() in item.window_text().lower():
                chosen = item
                break
    if chosen is None:
        if not items:
            raise RuntimeError("No certificates found in picker")
        chosen = items[0]
    chosen.click_input()

    buttons = cert_dialog.parent().descendants(control_type="Button")
    if not buttons:
        raise RuntimeError("Certificate confirmation button not found")
    buttons[0].click_input()


def main():
    pin_code = "1234"
    cert_cn = "rfrisch"
    run_mtls_auth(pin_code, cert_cn)


if __name__ == "__main__":
    try:
        time.sleep(2)
        main()
    except Exception as exc:
        log("ERROR: %s" % exc)
        sys.exit(1)
