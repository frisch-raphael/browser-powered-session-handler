import base64
import json
import re
from typing import Any, List, Optional


def decode_jwt_exp(jwt_token: str) -> Optional[int]:
    """
    Decode JWT payload without verifying signature to extract exp.
    """
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # base64url padding
        payload = json.loads(base64.urlsafe_b64decode(
            payload_b64.encode("utf-8")))
        exp = payload.get("exp")
        return exp if isinstance(exp, int) else None
    except Exception:
        return None


def parse_json_path(path: str) -> List[Any]:
    tokens: List[Any] = []
    for match in re.finditer(r"([^\.\[\]]+)|\[(\d+)\]", path):
        key, idx = match.groups()
        if key is not None:
            tokens.append(key)
        elif idx is not None:
            tokens.append(int(idx))
    return tokens


def extract_json_path(data: Any, path: str) -> Optional[Any]:
    tokens = parse_json_path(path)
    current = data
    try:
        for token in tokens:
            if isinstance(token, int):
                if not isinstance(current, list) or token >= len(current):
                    return None
                current = current[token]
            else:
                if not isinstance(current, dict) or token not in current:
                    return None
                current = current[token]
        return current
    except Exception:
        return None


def normalize_token_value(token: str) -> str:
    token = token.strip()
    if token.lower().startswith("bearer "):
        return token[7:].strip()
    return token
