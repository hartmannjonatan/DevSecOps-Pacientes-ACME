#!/usr/bin/env python3
"""Run real Gitleaks scans and apply the project's fail-closed policy."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]


class OperationalError(Exception):
    pass


def command(args, *, timeout=300, **kwargs):
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OperationalError(f"Cannot execute {args[0]}: {type(exc).__name__}") from exc


def git(repo, *args):
    result = command(["git", "-C", str(repo), *args])
    if result.returncode:
        raise OperationalError(f"Git {args[0]} failed (exit {result.returncode})")
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exceptions_from(path, today):
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1 or not isinstance(data.get("exceptions"), list):
        raise OperationalError("Invalid exceptions document")
    seen = set()
    for entry in data["exceptions"]:
        required = ("fingerprint", "classification", "reason", "remaining_risk",
                    "compensating_controls", "review_condition", "expires_on", "owner")
        if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str)
                                              or not entry[k].strip() for k in required):
            raise OperationalError("Exception lacks its identification or justification")
        if entry.get("scope") != "history" or entry["fingerprint"] in seen:
            raise OperationalError("Exceptions must be unique and restricted to historical findings")
        if len(entry["fingerprint"].split(":", 1)[0]) != 40:
            raise OperationalError("Historical exception must identify an exact commit")
        if dt.date.fromisoformat(entry["expires_on"]) < today:
            raise OperationalError("Expired exception: review required")
        seen.add(entry["fingerprint"])
    return {entry["fingerprint"]: entry for entry in data["exceptions"]}


def validate_report(path, exit_code):
    if exit_code not in (0, 42):
        raise OperationalError(f"Gitleaks execution failed (exit {exit_code})")
    try:
        rows = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise OperationalError("Missing or invalid Gitleaks JSON report") from exc
    if not isinstance(rows, list):
        raise OperationalError("Gitleaks report must be a JSON array")
    for row in rows:
        if not isinstance(row, dict) or any(not isinstance(row.get(k), str) or not row[k]
                                           for k in ("RuleID", "File", "Fingerprint")):
            raise OperationalError("Malformed Gitleaks finding")
        if type(row.get("StartLine")) is not int or row["StartLine"] < 1:
            raise OperationalError("Finding without a valid source location")
    if bool(rows) != (exit_code == 42):
        raise OperationalError("Scanner exit code and report disagree")
    return rows


def safe_findings(rows, scope, exceptions):
    result = []
    for row in rows:
        # Never publish Match, Secret, author/email, or commit messages.
        item = {key: row.get(key, "") for key in
                ("RuleID", "File", "StartLine", "EndLine", "Commit", "Fingerprint")}
        item["scope"] = scope
        exception = exceptions.get(row["Fingerprint"]) if scope == "history" else None
        item["decision"] = "accepted_exception" if exception else "block"
        if exception:
            item["exception"] = exception
        result.append(item)
    return result


def snapshot(repo, target):
    target.mkdir()
    entries = git(repo, "ls-files", "--stage", "-z").split(b"\0")
    if any(entry.startswith(b"160000 ") for entry in entries):
        raise OperationalError("Nested submodules require an explicit additional scan")
    names = set(git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0"))
    count = 0
    for name in sorted(names - {b""}):
        rel = Path(os.fsdecode(name))
        source = repo / rel
        if rel.is_absolute() or ".." in rel.parts or source.is_symlink():
            raise OperationalError("Unsafe path or symlink in the scan target")
        if not source.exists():  # Deleted working-tree files remain covered by history.
            continue
        if not source.is_file():
            raise OperationalError("Unsupported non-regular file in scan target")
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        count += 1
    if not count:
        raise OperationalError("Empty current-file scan target")
    return count


def scan(repo, output, config_dir, *, docker="docker"):
    output.mkdir(parents=True, exist_ok=True)
    result = {
        "schema_version": 1, "run_id": str(uuid.uuid4()), "category": "secret_detection",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "operational_error", "findings": [], "scans": {},
    }
    code = 2
    try:
        tools = json.loads((config_dir / "tools.json").read_text())
        image = tools["gitleaks_image"]
        version = tools["gitleaks_version"]
        if "@sha256:" not in image:
            raise OperationalError("Scanner image must be pinned by digest")
        exceptions = exceptions_from(config_dir / "secret-exceptions.json", dt.date.today())
        result["scanner"] = {"name": "gitleaks", "version": version, "image": image}
        result["configuration_sha256"] = {name: digest(config_dir / name) for name in
                                          ("gitleaks.toml", "tools.json", "secret-exceptions.json")}
        if git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
            raise OperationalError("Shallow history is not valid: fetch the complete history")
        result["commit"] = git(repo, "rev-parse", "HEAD").decode().strip()
        result["working_tree_dirty"] = bool(git(repo, "status", "--porcelain"))
        result["history_commits"] = int(git(repo, "rev-list", "--all", "--count"))
        if not result["history_commits"]:
            raise OperationalError("No reachable commits to scan")
        probe = command([docker, "run", "--rm", "--network", "none", image, "version"])
        if probe.returncode or probe.stdout.decode().strip().removeprefix("v") != version:
            raise OperationalError("Docker/Gitleaks unavailable or unexpected scanner version")
        with tempfile.TemporaryDirectory(prefix="acme-secret-scan-") as tmp:
            work = Path(tmp)
            inputs = work / "input"
            inputs.mkdir()
            # Gitleaks always loads <source>/.gitleaksignore, even with an explicit
            # ignore path. Scan a controlled parent directory instead; keep every
            # project file in the nested snapshot without importing its suppressions.
            (inputs / "current").mkdir()
            result["current_files"] = snapshot(repo, inputs / "current/files")
            clone = command(["git", "clone", "--mirror", "--no-local", str(repo), str(inputs / "history.git")])
            if clone.returncode:
                raise OperationalError("Could not copy complete repository history")
            shutil.copyfile(config_dir / "gitleaks.toml", inputs / "gitleaks.toml")
            (inputs / "empty-ignore").write_text("")
            for scope in ("files", "history"):
                reports = work / scope
                reports.mkdir()
                args = [docker, "run", "--rm", "--network", "none", "--read-only",
                        "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                        "--user", f"{os.getuid()}:{os.getgid()}",
                        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                        "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory",
                        "-e", "GIT_CONFIG_VALUE_0=/input/history.git",
                        "-v", f"{inputs}:/input:ro", "-v", f"{reports}:/output:rw", image]
                args += (["dir", "/input/current"] if scope == "files" else
                         ["git", "/input/history.git", "--log-opts=--all --full-history"])
                args += ["--config=/input/gitleaks.toml", "--gitleaks-ignore-path=/input/empty-ignore",
                         "--ignore-gitleaks-allow", "--redact=100", "--no-banner", "--no-color",
                         "--log-level=error", "--report-format=json", "--report-path=/output/report.json",
                         "--exit-code=42", "--timeout=180"]
                process = command(args)
                rows = validate_report(reports / "report.json", process.returncode)
                for row in rows:
                    row["File"] = row["File"].removeprefix("/input/current/files/")
                result["scans"][scope] = {"valid": True, "scanner_exit_code": process.returncode,
                                          "findings": len(rows)}
                result["findings"].extend(safe_findings(rows, scope, exceptions))
        result["blocking_findings"] = sum(f["decision"] == "block" for f in result["findings"])
        result["accepted_findings"] = len(result["findings"]) - result["blocking_findings"]
        result["status"] = "policy_violation" if result["blocking_findings"] else "pass"
        code = 1 if result["blocking_findings"] else 0
    except (OperationalError, OSError, ValueError, KeyError, TypeError) as exc:
        # Only our known operational messages are exposed; external stderr can contain secrets.
        result["error"] = str(exc) if isinstance(exc, OperationalError) else type(exc).__name__
    (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"Secret Detection: {result['status']} (exit {code}); report: {output / 'result.json'}")
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/security/secrets")
    options = parser.parse_args()
    raise SystemExit(scan(options.repository.resolve(), options.output.resolve(), ROOT / "security"))
