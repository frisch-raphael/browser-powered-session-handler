"""Local mTLS issuer and independent bearer-token resource for integration tests."""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


def encode_segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_segment(value):
    return json.loads(base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True))


class TokenError(ValueError):
    pass


class TokenIssuer:
    """Test-only HS256 tokens; signing state is discarded on process restart."""

    def __init__(self, ttl_seconds=30, clock=time.time):
        if ttl_seconds < 1:
            raise ValueError("Token lifetime must be positive")
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self.secret = secrets.token_bytes(32)

    def mint(self, identity):
        now = int(self.clock())
        claims = {
            "iss": "bpsh-mtls-fixture", "aud": "bpsh-protected-fixture",
            "sub": identity["sha256"], "cn": identity["common_name"],
            "iat": now, "exp": now + self.ttl_seconds, "jti": secrets.token_hex(16),
        }
        message = encode_segment({"alg": "HS256", "typ": "JWT"}) + "." + encode_segment(claims)
        signature = hmac.new(self.secret, message.encode("ascii"), hashlib.sha256).digest()
        return message + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"), claims

    def verify(self, token):
        try:
            if not isinstance(token, str) or len(token) > 16384:
                raise ValueError("Invalid length")
            header, payload, signature = token.split(".")
            supplied = base64.b64decode(
                signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True)
            expected = hmac.new(
                self.secret, (header + "." + payload).encode("ascii"), hashlib.sha256).digest()
            if not hmac.compare_digest(supplied, expected):
                raise ValueError("Invalid signature")
            if decode_segment(header) != {"alg": "HS256", "typ": "JWT"}:
                raise ValueError("Invalid header")
            claims = decode_segment(payload)
            if (not isinstance(claims, dict)
                    or claims.get("iss") != "bpsh-mtls-fixture"
                    or claims.get("aud") != "bpsh-protected-fixture"
                    or not isinstance(claims.get("sub"), str) or not claims["sub"]
                    or type(claims.get("exp")) is not int):
                raise ValueError("Invalid claims")
        except (ValueError, TypeError, UnicodeError, binascii.Error, RecursionError):
            raise TokenError("invalid_token") from None
        if int(self.clock()) >= claims["exp"]:
            raise TokenError("token_expired")
        return claims


class JsonHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status, payload, authenticate=False):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if authenticate:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Request lines can contain secrets in query parameters.
        pass


class IssuerHandler(JsonHandler):
    def do_GET(self):
        if urlsplit(self.path).path not in ("/", "/token"):
            self.reply(404, {"error": "not_found"})
            return
        cert = self.connection.getpeercert()
        der = self.connection.getpeercert(binary_form=True)
        if not cert or not der:
            self.reply(403, {"error": "client_certificate_required"})
            return
        names = [value for rdn in cert.get("subject", ())
                 for name, value in rdn if name == "commonName"]
        identity = {
            "sha256": hashlib.sha256(der).hexdigest(),
            "common_name": names[0] if names else "",
            "serial_number": cert.get("serialNumber", ""),
        }
        token, claims = self.server.issuer.mint(identity)
        self.reply(200, {
            "access_token": token, "token_type": "Bearer",
            "expires_in": self.server.issuer.ttl_seconds,
            "expires_at": claims["exp"], "identity": identity,
        })


class ProtectedHandler(JsonHandler):
    def do_GET(self):
        if urlsplit(self.path).path != "/protected":
            self.reply(404, {"error": "not_found"})
            return
        scheme, separator, token = self.headers.get("Authorization", "").partition(" ")
        if not separator or scheme.lower() != "bearer" or not token:
            self.reply(401, {"error": "missing_token"}, authenticate=True)
            return
        try:
            claims = self.server.issuer.verify(token)
        except TokenError as exc:
            self.reply(401, {"error": str(exc)}, authenticate=True)
            return
        self.reply(200, {
            "subject": claims["sub"], "common_name": claims["cn"],
            "token_id": claims["jti"], "expires_at": claims["exp"],
        })


def create_servers(certfile, keyfile, cafile, host="127.0.0.1", port=7576,
                   protected_port=7578, issuer=None):
    issuer = issuer if issuer is not None else TokenIssuer()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    context.load_verify_locations(cafile=str(cafile))
    login = ThreadingHTTPServer((host, port), IssuerHandler)
    try:
        login.socket = context.wrap_socket(login.socket, server_side=True)
        login.issuer = issuer
        resource = ThreadingHTTPServer((host, protected_port), ProtectedHandler)
        resource.issuer = issuer
    except BaseException:
        login.server_close()
        raise
    return login, resource


def main():
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", type=Path, default=root / "server.crt")
    parser.add_argument("--key", type=Path, default=root / "server.key")
    parser.add_argument("--ca", type=Path, default=root / "ca.crt")
    parser.add_argument("--port", type=int, default=7576)
    parser.add_argument("--protected-port", type=int, default=7578)
    parser.add_argument("--token-ttl-seconds", type=int, default=30)
    args = parser.parse_args()
    if args.token_ttl_seconds < 1:
        parser.error("--token-ttl-seconds must be positive")
    servers = create_servers(
        args.cert, args.key, args.ca, port=args.port, protected_port=args.protected_port,
        issuer=TokenIssuer(args.token_ttl_seconds))
    workers = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for worker in workers:
        worker.start()
    print(f"mTLS issuer: https://localhost:{servers[0].server_port}/token", flush=True)
    print(f"Protected resource: http://127.0.0.1:{servers[1].server_port}/protected", flush=True)
    print("Local fixture only. Tokens expire and become invalid on restart.", flush=True)
    try:
        while all(worker.is_alive() for worker in workers):
            workers[0].join(timeout=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for worker in workers:
            worker.join()


if __name__ == "__main__":
    main()
