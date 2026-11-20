#!/usr/bin/env python3
"""Offline Checkov Dockerfile analysis with explicit coverage and contextual policy."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from scan import ROOT, OperationalError, command, digest, git

REQUIRED_CHECKS = {"CKV_DOCKER_2", "CKV_DOCKER_3", "CKV_DOCKER_7",
                   "CKV_ACME_DOCKER_1", "CKV_ACME_DOCKER_2", "CKV_ACME_DOCKER_3"}


def validate_report(report, exit_code, version):
    if exit_code not in (0, 1) or not isinstance(report, dict) or report.get("check_type") != "dockerfile":
        raise OperationalError(f"Invalid Checkov execution/report (exit {exit_code})")
    summary = report.get("summary", {})
    results = report.get("results", {})
    if summary.get("checkov_version") != version or summary.get("resource_count") != 1:
        raise OperationalError("Unexpected scanner version or target coverage")
    for group, count, status in [("passed_checks", "passed", "PASSED"), ("failed_checks", "failed", "FAILED"),
                                 ("skipped_checks", "skipped", "SKIPPED")]:
        rows = results.get(group)
        if not isinstance(rows, list) or type(summary.get(count)) is not int or len(rows) != summary[count]:
            raise OperationalError("Checkov summary and records disagree")
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("check_id"), str)
                    or row.get("check_result", {}).get("result") != status
                    or row.get("file_path") != "/src/Dockerfile"
                    or not isinstance(row.get("check_name"), str)):
                raise OperationalError("Malformed finding or unexpected source file")
    if results.get("parsing_errors") != [] or summary.get("parsing_errors") != 0 or results["skipped_checks"]:
        raise OperationalError("Parsing errors or suppressed checks: analysis is incomplete")
    executed = {row["check_id"] for group in ("passed_checks", "failed_checks") for row in results[group]}
    if not REQUIRED_CHECKS <= executed:
        raise OperationalError("Required Dockerfile checks were not executed")
    if bool(results["failed_checks"]) != (exit_code == 1):
        raise OperationalError("Checkov exit code and findings disagree")
    return results["failed_checks"], sorted(executed)


def decide(rows, policy):
    if (policy.get("schema_version") != 1 or policy.get("exceptions") != []
            or policy.get("unknown_check") != "block" or not isinstance(policy.get("checks"), dict)
            or not REQUIRED_CHECKS <= policy["checks"].keys()):
        raise OperationalError("Unsupported or incomplete IaC policy")
    for entry in policy["checks"].values():
        if entry.get("decision") not in {"block", "review"} or not entry.get("reason"):
            raise OperationalError("IaC decision lacks its classification or justification")
    if any(policy["checks"][rule]["decision"] != "block" for rule in REQUIRED_CHECKS):
        raise OperationalError("Core IaC controls must remain blocking")
    findings = []
    for row in rows:
        classification = policy["checks"].get(row["check_id"], {"decision": "block", "reason": "Unknown rule: review required"})
        findings.append({"rule_id": row["check_id"], "message": row["check_name"], "path": "Dockerfile",
                         "lines": row.get("file_line_range"), "decision": classification["decision"],
                         "reason": classification["reason"]})
    return findings


def scan(repo, output, config=ROOT / "security", *, docker="docker", scenario="normal"):
    output.mkdir(parents=True, exist_ok=True)
    result = {"schema_version": 1, "category": "iac", "scenario": scenario, "run_id": str(uuid.uuid4()),
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "analysis_valid": False,
              "status": "operational_error", "findings": []}
    code = 2
    for name in ("checkov.json", "scanner.log", "inventory.json", "build-context.json", "context.log"):
        (output / name).unlink(missing_ok=True)
    try:
        tools = json.loads((config / "tools.json").read_text())
        image = tools["checkov_image"]
        if "@sha256:" not in image:
            raise OperationalError("Checkov image must be pinned by digest")
        policy = json.loads((config / "iac-policy.json").read_text())
        decide([], policy)
        checks = {p.name: digest(p) for p in sorted((config / "checkov").glob("*.py"))}
        if not checks:
            raise OperationalError("Missing local checks")
        result.update(commit=git(repo, "rev-parse", "HEAD").decode().strip(),
                      working_tree_dirty=bool(git(repo, "status", "--porcelain")),
                      integration_commit=git(ROOT, "rev-parse", "HEAD").decode().strip(),
                      integration_working_tree_dirty=bool(git(ROOT, "status", "--porcelain")),
                      scanner_image=image, scanner_version=tools["checkov_version"],
                      policy_sha256=digest(config / "iac-policy.json"), local_checks=checks,
                      local_checks_sha256=hashlib.sha256(json.dumps(checks, sort_keys=True).encode()).hexdigest(),
                      context_validator_sha256=digest(ROOT / "scripts/security/iac_context.py"))
        base = [docker, "run", "--rm", "--network", "none", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp", "-e", "LOG_LEVEL=ERROR",
                "-e", "PYTHONDONTWRITEBYTECODE=1"]
        version = command([*base, image, "--version"], timeout=60)
        if version.returncode or version.stdout.decode().strip() != tools["checkov_version"]:
            raise OperationalError("Checkov version probe failed")
        with tempfile.TemporaryDirectory(prefix="acme-iac-") as tmp:
            target = Path(tmp)
            inventory = []
            for name, purpose in [("Dockerfile", "checkov_analysis"), ("compose.yaml", "build_target_validation_only")]:
                source = repo / name
                if source.is_symlink() or not source.is_file() or source.stat().st_size > 1_000_000:
                    raise OperationalError("IaC target missing, symlink or oversized")
                shutil.copyfile(source, target / name)
                inventory.append({"path": name, "purpose": purpose, "sha256": digest(source)})
            (output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
            result["inventory_sha256"] = digest(output / "inventory.json")
            mounts = ["-v", f"{target}:/src:ro", "-w", "/src"]
            # No repo .checkov config, environment files, baselines or Docker socket are mounted.
            p = command([*base, *mounts, "-v", f"{config / 'checkov'}:/checks:ro", image,
                         "--file", "/src/Dockerfile", "--framework", "dockerfile", "--external-checks-dir", "/checks",
                         "--skip-download", "--output", "json"], timeout=240)
            (output / "checkov.json").write_bytes(p.stdout)
            (output / "scanner.log").write_bytes(p.stderr)
            result["scanner_exit_code"] = p.returncode
            rows, executed = validate_report(json.loads(p.stdout), p.returncode, tools["checkov_version"])
            context = command([*base, *mounts, "--entrypoint", "python", "-v",
                               f"{ROOT / 'scripts/security/iac_context.py'}:/context.py:ro", image, "/context.py"], timeout=60)
            (output / "context.log").write_bytes(context.stderr)
            if context.returncode:
                raise OperationalError("Dockerfile syntax or Compose build target validation failed (see context.log)")
            build = json.loads(context.stdout)
            if not isinstance(build, dict) or build.get("target") != "app":
                raise OperationalError("Invalid build context report")
            (output / "build-context.json").write_bytes(context.stdout)
        result["executed_checks"] = executed
        result["summary"] = json.loads(p.stdout)["summary"]
        result["findings"] = decide(rows, policy)
        result["blocking_findings"] = sum(f["decision"] == "block" for f in result["findings"])
        result["review_findings"] = sum(f["decision"] == "review" for f in result["findings"])
        code = int(result["blocking_findings"] > 0)
        result.update(analysis_valid=True, status="policy_violation" if code else "pass")
    except (OperationalError, OSError, ValueError, KeyError, TypeError) as exc:
        result["error"] = str(exc)
    result["exit_code"] = code
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"IaC: {result['status']} (exit {code}); report: {output / 'result.json'}")
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/security/iac")
    args = parser.parse_args()
    raise SystemExit(scan(args.repository.resolve(), args.output.resolve()))
