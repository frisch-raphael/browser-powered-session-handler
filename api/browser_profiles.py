import os
import shutil
from typing import List, Optional


def resolve_firefox_executable(api_dir: str) -> Optional[str]:
    browsers_root = os.environ.get(
        "PLAYWRIGHT_BROWSERS_PATH") or os.path.join(api_dir, "browsers")
    candidates: List[str] = []
    if browsers_root and os.path.isdir(browsers_root):
        for name in os.listdir(browsers_root):
            if not name.startswith("firefox-"):
                continue
            base = os.path.join(browsers_root, name, "firefox")
            exe = os.path.join(base, "firefox.exe")
            if os.path.exists(exe):
                candidates.append(exe)
                continue
            exe = os.path.join(base, "firefox")
            if os.path.exists(exe):
                candidates.append(exe)
    if candidates:
        try:
            return max(candidates, key=os.path.getmtime)
        except Exception:
            return sorted(candidates)[-1]

    bundled = os.path.join(api_dir, "firefox", "firefox.exe")
    return bundled if os.path.exists(bundled) else None


def _ignore_firefox_runtime_files(dir_name: str, names: List[str]) -> set:
    ignored = {
        "lock",
        "parent.lock",
        ".parentlock",
        "crashreporter",
        "minidumps",
        "startupCache",
    }
    return {name for name in names if name in ignored}


def profile_dir_for_cache_key(api_dir: str, cache_key: str) -> str:
    profile_root = os.path.join(api_dir, "firefox-profiles")
    profile_dir = os.path.join(profile_root, cache_key)
    if os.path.isdir(profile_dir):
        return profile_dir

    os.makedirs(profile_root, exist_ok=True)
    template_dir = os.path.join(api_dir, "firefox-profile")
    if os.path.isdir(template_dir):
        shutil.copytree(
            template_dir,
            profile_dir,
            ignore=_ignore_firefox_runtime_files,
        )
    else:
        os.makedirs(profile_dir, exist_ok=True)
    return profile_dir
