import re

from fastapi import HTTPException

from token_models import TokenConfig, TokenRequest


def validate_token_config(cfg: TokenConfig) -> None:
    if cfg.parsing.mode not in ("json_path", "cookie"):
        raise HTTPException(
            status_code=400, detail="token.parsing.mode must be json_path or cookie")
    if cfg.parsing.mode == "json_path" and not cfg.token_url_substring:
        raise HTTPException(
            status_code=400, detail="token.token_url_substring is required for json_path mode")
    if cfg.parsing.mode == "json_path" and not cfg.parsing.path:
        raise HTTPException(
            status_code=400, detail="token.parsing.path is required for json_path mode")
    if cfg.parsing.mode == "cookie" and not cfg.parsing.cookie_name:
        raise HTTPException(
            status_code=400, detail="token.parsing.cookie_name is required for cookie mode")


def parse_wait_time_ms(raw_value: str) -> int:
    value = (raw_value or "").strip().lower()
    if not value:
        raise ValueError("wait_time value is required")
    if value.endswith("ms"):
        number = value[:-2].strip()
        return int(number)
    if value.endswith("s"):
        number = value[:-1].strip()
        return int(float(number) * 1000)
    return int(value)


def validate_token_request(req: TokenRequest) -> None:
    if not req.authentication_url:
        raise HTTPException(
            status_code=400, detail="authentication_url is required")
    proxy = (req.proxy or "").strip()
    if proxy and not re.match(r"^https?://.+", proxy):
        raise HTTPException(
            status_code=400,
            detail="proxy must start with http:// or https://",
        )
    if req.steps is None:
        raise HTTPException(
            status_code=400, detail="steps is required")
    for i, step in enumerate(req.steps):
        if step.type not in (
            "click",
            "input",
            "secure_input",
            "wait_load_state",
            "wait_url",
            "wait_time",
            "wait_selector",
        ):
            raise HTTPException(
                status_code=400, detail=f"Invalid step type at index {i}")
        if step.type in ("click", "input", "secure_input", "wait_selector") and not step.selector:
            raise HTTPException(
                status_code=400, detail=f"Missing selector at index {i}")
        if step.type in ("input", "secure_input") and (step.value is None or not str(step.value).strip()):
            raise HTTPException(
                status_code=400, detail=f"Missing input value at index {i}")
        if step.type == "wait_url" and (step.value is None or not str(step.value).strip()):
            raise HTTPException(
                status_code=400, detail=f"Missing wait_url value at index {i}")
        if step.type == "wait_time":
            try:
                wait_ms = parse_wait_time_ms(step.value or "")
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=400, detail=f"Invalid wait_time value at index {i}") from None
            if wait_ms < 1:
                raise HTTPException(
                    status_code=400, detail=f"Invalid wait_time value at index {i}")
        if step.type == "wait_load_state":
            state = (step.value or "load").strip().lower()
            if state not in ("load", "domcontentloaded", "networkidle"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid load state at index {i} (load, domcontentloaded, networkidle)",
                )
