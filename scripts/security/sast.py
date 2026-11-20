#!/usr/bin/env python3
"""Real, offline Semgrep CE analysis of a controlled PHP/JS(X) source snapshot."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from scan import ROOT, OperationalError, command, digest, git
from sast_rules import prepare_rules

EXTENSIONS = {".php", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
EXCLUDED = ("vendor/", "node_modules/", "var/", "public/build/", "artifacts/")


def snapshot(repo, destination):
    names = sorted(set(git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0")) - {""})
    inventory = []
    for name in names:
        path = Path(name)
        if path.suffix not in EXTENSIONS or name.startswith(EXCLUDED):
            continue
        source = repo / path
        if source.is_symlink() or any(p.is_symlink() for p in source.parents if p != repo):
            raise OperationalError("Source symlinks are not supported")
        if not source.exists():  # tracked deletion in the working tree
            continue
        if not source.is_file() or source.stat().st_size > 1_000_000:
            raise OperationalError("Source is not a regular file or exceeds the scan limit")
        dest = destination / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        inventory.append({"path": name, "sha256": digest(source), "bytes": source.stat().st_size,
                          "language": "php" if path.suffix == ".php" else "javascript/typescript"})
    if not inventory:
        raise OperationalError("Empty SAST target")
    return inventory


def validate_report(report, exit_code, inventory, version, rules):
    if exit_code not in (0, 1) or not isinstance(report, dict):
        raise OperationalError(f"Semgrep execution failed (exit {exit_code})")
    if report.get("version") != version or report.get("errors") != []:
        raise OperationalError("Semgrep version mismatch or incomplete analysis (parse/timeout/configuration error)")
    if report.get("engine_requested") != "OSS" or report.get("skipped_rules") != []:
        raise OperationalError("Unexpected analysis engine or skipped rules")
    rows = report.get("results")
    scanned = report.get("paths", {}).get("scanned")
    expected = {entry["path"] for entry in inventory}
    if not isinstance(rows, list) or not isinstance(scanned, list) or set(scanned) != expected:
        raise OperationalError("Missing report or incomplete source coverage")
    if bool(rows) != (exit_code == 1):
        raise OperationalError("Semgrep exit code and findings disagree")
    for row in rows:
        if (not isinstance(row, dict) or row.get("check_id") not in rules
                or row.get("path") not in expected
                or type(row.get("start", {}).get("line")) is not int
                or row["start"]["line"] < 1 or not isinstance(row.get("extra"), dict)):
            raise OperationalError("Malformed or unknown SAST finding")
        rule = rules[row["check_id"]]
        if row["extra"].get("severity") != rule["severity"]:
            raise OperationalError("Finding severity differs from the pinned rule")
    return rows


def decide(rows, rules, policy):
    if (policy.get("schema_version") != 1 or policy.get("exceptions") != []
            or policy.get("unknown_metadata") != "block" or policy.get("other_findings") != "review"
            or policy.get("blocking_severities") != ["ERROR", "WARNING"]
            or policy.get("blocking_confidences") != ["HIGH", "MEDIUM"]):
        raise OperationalError("Unsupported SAST policy: review implementation and tests before changing it")
    findings = []
    for row in rows:
        rule = rules[row["check_id"]]
        severity = rule["severity"]
        meta = rule.get("metadata", {})
        confidence = meta.get("confidence", "UNKNOWN")
        unknown = severity not in {"ERROR", "WARNING", "INFO"} or confidence not in {"HIGH", "MEDIUM", "LOW"}
        blocking = unknown or (severity in policy["blocking_severities"] and confidence in policy["blocking_confidences"])
        findings.append({"rule_id": row["check_id"], "path": row["path"], "line": row["start"]["line"],
                         "severity": severity, "confidence": confidence, "cwe": meta.get("cwe", []),
                         "message": rule["message"], "decision": "block" if blocking else "review"})
    return findings


def scan(repo, output, config=ROOT / "security", *, docker="docker", scenario="normal", cache=None):
    output.mkdir(parents=True, exist_ok=True)
    result = {"schema_version": 1, "category": "sast", "run_id": str(uuid.uuid4()), "scenario": scenario,
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "analysis_valid": False,
              "status": "operational_error", "findings": []}
    code = 2
    for name in ("semgrep.json", "scanner.log", "inventory.json"):
        (output / name).unlink(missing_ok=True)
    try:
        tools = json.loads((config / "tools.json").read_text())
        image = tools["semgrep_image"]
        if "@sha256:" not in image:
            raise OperationalError("Semgrep image must be pinned by digest")
        policy = json.loads((config / "sast-policy.json").read_text())
        decide([], {}, policy)
        provenance = json.loads((config / "semgrep/provenance.json").read_text())
        result.update(commit=git(repo, "rev-parse", "HEAD").decode().strip(),
                      working_tree_dirty=bool(git(repo, "status", "--porcelain")),
                      integration_commit=git(ROOT, "rev-parse", "HEAD").decode().strip(),
                      integration_working_tree_dirty=bool(git(ROOT, "status", "--porcelain")),
                      scanner_image=image, scanner_version=tools["semgrep_version"],
                      policy_sha256=digest(config / "sast-policy.json"),
                      provenance_sha256=digest(config / "semgrep/provenance.json"),
                      rules_sha256=provenance["rules_sha256"], upstream_commit=provenance["commit"])
        base = [docker, "run", "--rm", "--network", "none", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp", "-e", "SEMGREP_SEND_METRICS=off",
                "-e", "SEMGREP_ENABLE_VERSION_CHECK=0", image]
        version = command([*base, "semgrep", "--version"], timeout=60)
        if version.returncode or version.stdout.decode().strip() != tools["semgrep_version"]:
            raise OperationalError("Semgrep version probe failed")
        rule_file = prepare_rules(config, cache or ROOT / "artifacts/security/semgrep-cache", base)
        rules_list = json.loads(rule_file.read_text())["rules"]
        rules = {r["id"]: r for r in rules_list}
        if len(rules) != provenance["rule_count"] or len(rules) != len(rules_list):
            raise OperationalError("Rules missing or duplicated")
        result["rule_count"] = len(rules)
        with tempfile.TemporaryDirectory(prefix="acme-sast-source-") as tmp:
            target = Path(tmp)
            inventory = snapshot(repo, target)
            (output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
            result["source_count"] = len(inventory)
            result["inventory_sha256"] = digest(output / "inventory.json")
            # No repository ignore files, .git, credentials or installed dependencies are mounted.
            p = command([*base[:-1], "-v", f"{target}:/src:ro", "-v", f"{rule_file}:/rules.json:ro", "-w", "/src", image,
                         "semgrep", "scan", "--config", "/rules.json", "--oss-only", "--metrics=off",
                         "--disable-version-check", "--disable-nosem", "--no-git-ignore", "--no-rewrite-rule-ids",
                         "--strict", "--error", "--json", "--jobs=2", "--timeout=10", "--timeout-threshold=1",
                         "--max-target-bytes=1000000", *[entry["path"] for entry in inventory]], timeout=240)
            (output / "semgrep.json").write_bytes(p.stdout)
            (output / "scanner.log").write_bytes(p.stderr)
            result["scanner_exit_code"] = p.returncode
            rows = validate_report(json.loads(p.stdout), p.returncode, inventory, tools["semgrep_version"], rules)
        result["findings"] = decide(rows, rules, policy)
        result["blocking_findings"] = sum(f["decision"] == "block" for f in result["findings"])
        result["review_findings"] = sum(f["decision"] == "review" for f in result["findings"])
        code = int(result["blocking_findings"] > 0)
        result.update(analysis_valid=True, status="policy_violation" if code else "pass")
    except (OperationalError, OSError, ValueError, KeyError, TypeError) as exc:
        result["error"] = str(exc)
    result["exit_code"] = code
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"SAST: {result['status']} (exit {code}); report: {output / 'result.json'}")
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/security/sast")
    args = parser.parse_args()
    raise SystemExit(scan(args.repository.resolve(), args.output.resolve()))
