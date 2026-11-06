"""Create a fresh, private SoftHSM store for Java integration tests; never reuse/reset a store."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import uuid


def run(arguments, *, root, environment):
    """Run a developer fixture tool without printing PIN-bearing arguments or captured output."""
    result = subprocess.run([str(a) for a in arguments], cwd=root, env=environment, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"Fixture tool {Path(arguments[0]).name} failed (exit {result.returncode}); output/arguments omitted.")


def prepare(output, module, utility, pkcs_tool, openssl):
    """Initialize only a newly created store with two on-token keys and same-CN certificates."""
    output = output.resolve()
    if output.exists():
        raise ValueError("Refusing to reuse an existing output directory. Choose a fresh private fixture path.")
    for path in (module, utility, pkcs_tool, openssl):
        if not Path(path).is_file():
            raise ValueError("A required SoftHSM/OpenSC/OpenSSL developer tool is missing; provide its explicit path.")
    if "softhsm" not in module.name.lower():
        raise ValueError("This disposable fixture supports only SoftHSM middleware, never a physical token module.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    if os.name == "nt":
        user = os.environ.get("USERDOMAIN", "") + "\\" + os.environ["USERNAME"]
        result = subprocess.run(["icacls", str(output), "/inheritance:r", "/grant:r", user + ":(OI)(CI)F"], capture_output=True)
        if result.returncode:
            raise RuntimeError("Cannot restrict the owned fixture directory to the current user; no token was initialized.")
    identity = str(uuid.uuid4())
    (output / ".fixture-owned.json").write_text(json.dumps({"formatVersion": 1, "fixtureId": identity, "purpose": "isolated-bpsh-tests"}), encoding="utf8")
    (output / "tokens").mkdir(mode=0o700)
    configuration = output / "softhsm2.conf"
    configuration.write_text("directories.tokendir = " + (output / "tokens").as_posix() + "\nobjectstore.backend = file\nlog.level = ERROR\n", encoding="utf8")
    environment = dict(os.environ, SOFTHSM2_CONF=str(configuration))
    pin = "".join(str(secrets.randbelow(10)) for _ in range(8))
    so_pin = secrets.token_hex(16)
    label = "BPSH-" + identity[:12]
    run([utility, "--init-token", "--free", "--label", label, "--so-pin", so_pin, "--pin", pin], root=output, environment=environment)
    run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=BPSH disposable fixture CA", "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", "ca.key", "-out", "ca.crt"], root=output, environment=environment)
    run([openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr"], root=output, environment=environment)
    (output / "server.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="ascii")
    (output / "wrong-host.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:wrong.example\n", encoding="ascii")
    for extension, name, serial in (("server.ext", "server.crt", "1"), ("wrong-host.ext", "wrong-host.crt", "2")):
        run([openssl, "x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", serial, "-days", "2", "-extfile", extension, "-out", name], root=output, environment=environment)
    (output / "client.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n", encoding="ascii")
    fingerprints = {}
    for number, name in (("01", "employee"), ("02", "admin")):
        common = [pkcs_tool, "--module", module, "--token-label", label, "--login", "--pin", pin]
        run(common + ["--keypairgen", "--key-type", "rsa:2048", "--id", number, "--label", name], root=output, environment=environment)
        run(common + ["--read-object", "--type", "pubkey", "--id", number, "--output-file", name + "-public.der"], root=output, environment=environment)
        run([openssl, "pkey", "-pubin", "-inform", "DER", "-in", name + "-public.der", "-out", name + "-public.pem"], root=output, environment=environment)
        run([openssl, "x509", "-new", "-force_pubkey", name + "-public.pem", "-subj", "/CN=Same Display Name", "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", str(10 + int(number)), "-days", "2", "-extfile", "client.ext", "-out", name + ".crt"], root=output, environment=environment)
        run([openssl, "x509", "-in", name + ".crt", "-outform", "DER", "-out", name + ".der"], root=output, environment=environment)
        run(common + ["--write-object", name + ".der", "--type", "cert", "--id", number, "--label", name], root=output, environment=environment)
        fingerprints[name] = hashlib.sha256((output / (name + ".der")).read_bytes()).hexdigest()
    manifest = {"formatVersion": 1, "fixtureId": identity, "root": str(output), "module": str(module.resolve()), "pin": pin, "fingerprints": fingerprints}
    (output / "fixture.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print("Prepared disposable SoftHSM fixture:", output / "fixture.json")
    print("Two non-exported private keys have same-CN certificates and distinct fingerprints. No existing token store was reused.")


def main():
    """Resolve developer tool paths and require an explicit fresh output directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module", type=Path, default=Path("C:/SoftHSM2/lib/softhsm2-x64.dll"))
    parser.add_argument("--utility", type=Path, default=Path("C:/SoftHSM2/bin/softhsm2-util.exe"))
    parser.add_argument("--pkcs-tool", type=Path, default=Path("C:/Program Files/OpenSC Project/OpenSC/tools/pkcs11-tool.exe"))
    parser.add_argument("--openssl", type=Path, default=Path(shutil.which("openssl") or "missing-openssl"))
    args = parser.parse_args()
    prepare(args.output, args.module, args.utility, args.pkcs_tool, args.openssl)


if __name__ == "__main__":
    main()
