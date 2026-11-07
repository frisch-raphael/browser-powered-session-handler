"""Fixture checks use temporary PEM certificates, not a PKCS#11 device."""

import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest


SPEC = importlib.util.spec_from_file_location("mtls_fixture", Path(__file__).with_name("mtls-app.py"))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI is required for test certificates")
class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="bpsh-mtls-fixture-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)

        def openssl(*args):
            subprocess.run([shutil.which("openssl"), *args], cwd=cls.root,
                           check=True, capture_output=True, timeout=30)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=BPSH Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", "ca.key", "-out", "ca.crt")
        for name in ("server", "client-a", "client-b"):
            # Distinct certificates deliberately share a CN to test identity attribution.
            common_name = "localhost" if name == "server" else "Same Display Name"
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", "/CN=" + common_name, "-keyout", name + ".key",
                    "-out", name + ".csr")
            extensions = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            extensions += "extendedKeyUsage=" + ("serverAuth" if name == "server" else "clientAuth") + "\n"
            if name == "server":
                extensions += "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
            (cls.root / (name + ".ext")).write_text(extensions, encoding="ascii")
            openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.crt",
                    "-CAkey", "ca.key", "-CAcreateserial", "-days", "2",
                    "-extfile", name + ".ext", "-out", name + ".crt")

    def setUp(self):
        self.now = 2000000000
        self.issuer = FIXTURE.TokenIssuer(ttl_seconds=30, clock=lambda: self.now)
        self.login, self.resource = FIXTURE.create_servers(
            self.root / "server.crt", self.root / "server.key", self.root / "ca.crt",
            port=0, protected_port=0, issuer=self.issuer)
        self.workers = []
        for server in (self.login, self.resource):
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            self.workers.append(worker)
        self.addCleanup(self.close_servers)

    def close_servers(self):
        for server in (self.login, self.resource):
            server.shutdown()
            server.server_close()
        for worker in self.workers:
            worker.join(timeout=5)

    def issue(self, name="client-a", path="/token"):
        context = ssl.create_default_context(cafile=str(self.root / "ca.crt"))
        if name:
            context.load_cert_chain(str(self.root / (name + ".crt")),
                                    str(self.root / (name + ".key")))
        connection = http.client.HTTPSConnection(
            "localhost", self.login.server_port, context=context, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            connection.close()

    def protected(self, token=None, path="/protected"):
        connection = http.client.HTTPConnection("127.0.0.1", self.resource.server_port, timeout=5)
        try:
            headers = {} if token is None else {"Authorization": "Bearer " + token}
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            connection.close()

    def test_issued_token_works_without_client_certificate_on_resource(self):
        status, headers, issued = self.issue()
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        pem = (self.root / "client-a.crt").read_text()
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        self.assertEqual(issued["identity"]["sha256"], fingerprint)
        status, _, protected = self.protected(issued["access_token"])
        self.assertEqual(status, 200)
        self.assertEqual(protected["subject"], fingerprint)

    def test_same_cn_certificates_have_distinct_token_identities(self):
        first = self.issue("client-a")[2]
        second = self.issue("client-b")[2]
        self.assertEqual(first["identity"]["common_name"], second["identity"]["common_name"])
        self.assertNotEqual(first["identity"]["sha256"], second["identity"]["sha256"])
        self.assertNotEqual(self.protected(first["access_token"])[2]["subject"],
                            self.protected(second["access_token"])[2]["subject"])

    def test_expiry_boundary_and_fresh_login(self):
        first = self.issue()[2]
        self.now += 29
        self.assertEqual(self.protected(first["access_token"])[0], 200)
        self.now += 1
        status, _, body = self.protected(first["access_token"])
        self.assertEqual((status, body), (401, {"error": "token_expired"}))
        refreshed = self.issue()[2]
        self.assertNotEqual(first["access_token"], refreshed["access_token"])
        self.assertEqual(self.protected(refreshed["access_token"])[0], 200)

    def test_missing_and_malformed_tokens_are_rejected(self):
        status, headers, body = self.protected()
        self.assertEqual((status, body), (401, {"error": "missing_token"}))
        self.assertEqual(headers["WWW-Authenticate"], "Bearer")
        for value in ("not-a-jwt", "a.b.c", "a.b.!", "a" * 16385):
            with self.subTest(value=value[:20]):
                status, _, body = self.protected(value)
                self.assertEqual((status, body), (401, {"error": "invalid_token"}))

    def test_tampered_claims_are_rejected(self):
        token = self.issue()[2]["access_token"]
        header, payload, signature = token.split(".")
        claims = FIXTURE.decode_segment(payload)
        claims["sub"] = "another-user"
        tampered = ".".join((header, FIXTURE.encode_segment(claims), signature))
        self.assertEqual(self.protected(tampered)[0], 401)

    def test_other_issuer_signing_key_is_rejected(self):
        other = FIXTURE.TokenIssuer(clock=lambda: self.now)
        token, _ = other.mint({"sha256": "test", "common_name": "test"})
        self.assertEqual(self.protected(token)[0], 401)

    def test_missing_and_wrong_purpose_client_certificates_are_rejected(self):
        for name in (None, "server"):
            # The server-auth-only certificate is trusted but invalid for client auth.
            with self.subTest(certificate=name):
                with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                    self.issue(name)

    def test_root_remains_compatible_and_no_static_files_are_served(self):
        self.assertIn("access_token", self.issue(path="/")[2])
        self.assertEqual(self.issue(path="/server.key")[0], 404)
        self.assertEqual(self.protected(path="/unknown")[0], 404)


if __name__ == "__main__":
    unittest.main()
