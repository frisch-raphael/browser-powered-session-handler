from typing import List, Optional

from pydantic import BaseModel, Field


DEFAULT_NAV_TIMEOUT_MS = 8000
DEFAULT_WAIT_TOKEN_TIMEOUT_MS = 3000
DEFAULT_REFRESH_SKEW_SECONDS = 1


class AuthStep(BaseModel):
    type: str
    selector: str
    value: Optional[str] = None
    pin: Optional[str] = None
    cert_cn: Optional[str] = None


class TokenParsingConfig(BaseModel):
    mode: str
    path: Optional[str] = None
    cookie_name: Optional[str] = None


class TokenConfig(BaseModel):
    token_url_substring: str = ""
    refresh_frequency_seconds: Optional[int] = Field(None, ge=5, le=86400)
    refresh_skew_seconds: int = Field(
        DEFAULT_REFRESH_SKEW_SECONDS, ge=0, le=86400)
    nav_timeout_ms: int = Field(
        DEFAULT_NAV_TIMEOUT_MS, ge=1000, le=180000)
    wait_token_timeout_ms: int = Field(
        DEFAULT_WAIT_TOKEN_TIMEOUT_MS, ge=500, le=60000)
    parsing: TokenParsingConfig


class TokenRequest(BaseModel):
    authentication_url: str
    headless: bool
    proxy: Optional[str] = None
    steps: List[AuthStep]
    token_config: Optional[TokenConfig] = None
    force: bool = False
    mtls_enabled: bool = False
    mtls_hostname: Optional[str] = None
    mtls_pin: Optional[str] = None
    mtls_cert_cn: Optional[str] = None
