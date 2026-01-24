import csv
import os
import re
import subprocess
import sys
import time

from pywinauto import Desktop

PIN_CODE = "1234"
CERT_CN = "rfrisch"


def log(msg):
    print(msg)


def get_firefox_pids():
    try:
        output = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq firefox.exe", "/FO", "CSV"],
            text=True,
        )
    except Exception as exc:
        raise RuntimeError("Failed to run tasklist: %s" % exc)

    rows = list(csv.reader(output.strip().splitlines()))
    pids = []
    for row in rows[1:]:
        if len(row) >= 2 and row[0].lower() == "firefox.exe":
            try:
                pids.append(int(row[1]))
            except ValueError:
                continue
    return pids


def count_firefox_windows():
    windows = []
    for win in Desktop().windows(class_name="MozillaWindowClass"):
        try:
            if win.is_visible():
                windows.append(win)
        except Exception:
            continue
    return windows


def find_firefoxes():
    firefoxes = Desktop(backend="uia").windows(
        class_name="MozillaWindowClass")
    return firefoxes


def get_pin_firefox_spec():
    firefox = get_pin_firefox()
    firefox_spec = Desktop(backend="uia").window(handle=firefox.handle)
    return firefox_spec


def get_pin_firefox(timeout_sec=10):
    found = False
    firefoxes = find_firefoxes()
    for firefox in firefoxes:
        firefox_spec = Desktop(backend="uia").window(handle=firefox.handle)
        try:
            # Fast-ish probe: search descendants for the thing you care about
            print("x")
            candidate = firefox_spec.child_window(
                title_re=".*PKCS*")
            if candidate.exists(timeout=0.2):
                print("Found Firefox window with PKCS prompt")
                found = True
                return firefox
        except Exception:
            # Some windows might be mid-transition or deny access briefly
            continue

    if not found:
        raise RuntimeError(
            "No Firefox window contains the requested child control.")


def main():
    if os.name != "nt":
        raise RuntimeError("This helper only supports Windows")

    # find_firefoxes()
    firefox = get_pin_firefox()
    firefox_spec = Desktop(backend="uia").window(handle=firefox.handle)
    # windows = count_firefox_windows()
    # if len(windows) != 1:
    #     raise RuntimeError(
    #         "Expected exactly one Firefox window, found %d" % len(windows))

    # pids = get_firefox_pids()
    # log("Found firefox.exe processes: %d" % len(pids))

    # pin_dialog = find_pin_firefox()
    # if pin_dialog is None:
    #     raise RuntimeError("PIN prompt not found")

    # log("PIN prompt found")
    # firefox_spec.child_window(
    #     title="MozillaCompositorWindowClass").print_control_identifiers()
    firefox.click_input()
    firefox_spec.descendants(control_type="Edit")[0].type_keys(
        PIN_CODE, with_spaces=True, set_foreground=True)
    firefox_spec.descendants(control_type="Edit")[0].type_keys("{ENTER}")
    time.sleep(0.25)
    firefox_spec.print_control_identifiers()

    cert_picker = firefox_spec.child_window(auto_id="nicknames")
    cert_dialog = cert_picker.parent().parent()
    cert_picker.click_input()
    # firefox_spec.child_window(
    #     title_re=f".*{CERT_CN}.*", found_index=1).click_input()
    firefox_spec.child_window(
        title_re=f".*{CERT_CN}.*", found_index=0).click_input()
    cert_dialog.parent().descendants(control_type="Button")[0].click_input()
    # if cert_dialog is None:
    #     raise RuntimeError("Certificate selection dialog not found")

    # if not pick_certificate(cert_dialog, CERT_CN_SUBSTRING):
    #     raise RuntimeError(
    #         "Certificate with CN containing '%s' not found" % CERT_CN_SUBSTRING)

    # if not click_first_button(cert_dialog, [r"OK", r"OK.*", r"Select", r"Open"]):
    #     log("Certificate dialog button not found, trying Enter key")
    #     cert_dialog.type_keys("{ENTER}")

    # log("Certificate selected")


if __name__ == "__main__":
    try:
        # stop any existing firefox processes
        # start firefox process
        # sleep 2 seconds to allow firefox to start
        time.sleep(2)
        main()
    except Exception as exc:
        # killing gracefully firefox processes

        log("ERROR: %s" % exc)
        sys.exit(1)
