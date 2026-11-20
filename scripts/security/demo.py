#!/usr/bin/env python3
"""Controlled demonstrations: never insert test credentials into application history."""
import argparse
import hashlib
from pathlib import Path
import shutil
import tempfile

from scan import ROOT, command, scan


def fixture(repo):
    repo.mkdir()
    for args in (["init", "--initial-branch=main"], ["config", "user.name", "ACME synthetic test"],
                 ["config", "user.email", "synthetic@example.invalid"]):
        p = command(["git", "-C", str(repo), *args])
        if p.returncode:
            raise RuntimeError("Cannot initialize synthetic repository")
    (repo / "README.md").write_text("Isolated synthetic security test. No real credentials.\n")
    commit(repo, "Initial synthetic fixture")


def commit(repo, message):
    for args in (["add", "."], ["-c", "commit.gpgsign=false", "commit", "-m", message]):
        if command(["git", "-C", str(repo), *args]).returncode:
            raise RuntimeError("Cannot commit synthetic fixture")


def fake_secret(repo):
    # Generated only in disposable repositories; no account accepts this value.
    value = hashlib.sha256(b"ACME isolated fictional token; not an actual credential").hexdigest()
    (repo / "demo.env").write_text("APP_SECRET=" + value + "\n")
    return value


def demonstrate(scenario, output):
    with tempfile.TemporaryDirectory(prefix="acme-security-demo-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        fixture(repo)
        config = root / "security"
        shutil.copytree(ROOT / "security", config)
        if scenario == "secret-fixture":
            fake_secret(repo)
        elif scenario == "operational-failure":
            (config / "gitleaks.toml").write_text("invalid_toml = [\n")
        else:
            raise ValueError("Unknown controlled demonstration")
        return scan(repo, output, config)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["secret-fixture", "operational-failure"])
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/security/demo")
    args = parser.parse_args()
    raise SystemExit(demonstrate(args.scenario, args.output.resolve()))
