#!/usr/bin/env python3
"""Audit both lockfiles with pinned native tools; do not install or execute packages."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from scan import ROOT, OperationalError, command, digest, git

LEVELS = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}


def require(condition, message):
    if not condition:
        raise OperationalError(message)


def inventory(ecosystem, manifest, lock):
    items = []
    if ecosystem == "composer":
        require(isinstance(lock.get("packages"), list) and isinstance(lock.get("packages-dev"), list),
                "Composer lock has no complete package inventory")
        for key, scope in (("packages", "runtime"), ("packages-dev", "development")):
            for package in lock[key]:
                name, version = package["name"], package["version"]
                items.append({"name": name, "version": version, "scope": scope,
                              "direct": name in manifest.get("require", {}) or name in manifest.get("require-dev", {}),
                              "path": name, "source": "composer.lock"})
    else:
        require(lock.get("lockfileVersion") == 3 and isinstance(lock.get("packages"), dict),
                "Expected npm lockfile v3 with package entries")
        for path, package in lock["packages"].items():
            if not path:
                continue
            require(not package.get("link"), "Linked npm package needs explicit inventory support")
            name = package.get("name", path.rsplit("node_modules/", 1)[-1])
            local = package.get("resolved", "").startswith("file:")
            items.append({"name": name, "version": package["version"],
                          "scope": "development" if package.get("dev", False) else "runtime",
                          "direct": name in manifest.get("dependencies", {}) or name in manifest.get("devDependencies", {}),
                          "path": path, "source": "local-file" if local else "npm-registry"})
    require(bool(items), "Empty dependency inventory is not a valid analysis")
    require(all(isinstance(p["version"], str) and p["version"] for p in items), "Package without a resolved version")
    require(len({p["path"] for p in items}) == len(items), "Duplicate inventory paths")
    return items


def collection(value, label):
    require(isinstance(value, (dict, list)), f"Invalid {label} collection")
    return list(value.values()) if isinstance(value, dict) else value


def parse_composer(report, code, packages):
    require(code in (0, 1), f"Composer audit failed (exit {code})")
    require(isinstance(report, dict) and "advisories" in report and "abandoned" in report,
            "Invalid Composer audit report")
    require(not report.get("error"), "Composer returned an operational error")
    # Never silently accept a new/nonempty policy category we do not understand.
    require(not any(value for key, value in report.items() if key not in ("advisories", "abandoned")),
            "Composer returned additional policy findings requiring explicit handling")
    by_name = {p["name"]: p for p in packages}
    findings = []
    advisories = report["advisories"]
    require(isinstance(advisories, dict) or advisories == [], "Invalid Composer advisory map")
    for name, rows in (advisories.items() if isinstance(advisories, dict) else []):
        require(name in by_name, "Composer finding is absent from the audited inventory")
        rows = collection(rows, "Composer advisory")
        require(bool(rows), "Empty advisory list for affected package")
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get("advisoryId"), str)
                    and row.get("packageName") == name and isinstance(row.get("title"), str),
                    "Malformed Composer advisory")
            severity = row.get("severity") or "unknown"
            if severity == "medium":
                severity = "moderate"
            require(severity in LEVELS or severity == "unknown", "Unsupported advisory severity")
            findings.append({"kind": "vulnerability", "package": name, "severity": severity,
                             "instances": [by_name[name]], "advisories": [{
                                 "id": row["advisoryId"], "title": row["title"],
                                 "url": row.get("link"), "cve": row.get("cve"),
                                 "affected_versions": row.get("affectedVersions"),
                             }]})
    abandoned = report["abandoned"]
    require(isinstance(abandoned, dict) or abandoned == [], "Invalid abandoned package map")
    for name, replacement in (abandoned.items() if isinstance(abandoned, dict) else []):
        require(name in by_name, "Abandoned package absent from inventory")
        findings.append({"kind": "abandoned", "package": name, "severity": "info",
                         "instances": [by_name[name]], "advisories": [], "replacement": replacement})
    # --abandoned=report does not change the native exit status.
    require((code == 1) == any(f["kind"] == "vulnerability" for f in findings),
            "Composer exit status disagrees with vulnerability findings")
    return findings


def parse_npm(report, code, packages):
    require(code in (0, 1), f"npm audit failed (exit {code})")
    require(isinstance(report, dict) and not report.get("error") and report.get("auditReportVersion") == 2,
            "Missing/invalid npm audit response or registry error")
    vulnerabilities = report.get("vulnerabilities")
    require(isinstance(vulnerabilities, dict), "npm report lacks its vulnerability map")
    metadata = report.get("metadata")
    require(isinstance(metadata, dict), "npm report lacks metadata")
    counts = metadata.get("vulnerabilities")
    dependencies = metadata.get("dependencies")
    require(isinstance(dependencies, dict) and type(dependencies.get("total")) is int
            and dependencies["total"] == len(packages), "npm audited package count differs from the lock inventory")
    require(isinstance(counts, dict) and type(counts.get("total")) is int and counts["total"] == len(vulnerabilities),
            "npm report lacks consistent vulnerability counts")
    by_path = {p["path"]: p for p in packages}

    def advisories(name, visiting):
        require(name not in visiting, "Cycle in npm advisory references")
        entry = vulnerabilities.get(name)
        require(isinstance(entry, dict) and isinstance(entry.get("via"), list) and entry["via"],
                "Malformed npm advisory references")
        rows = []
        for via in entry["via"]:
            if isinstance(via, str):
                rows.extend(advisories(via, visiting | {name}))
            else:
                require(isinstance(via, dict) and isinstance(via.get("url"), str)
                        and via.get("source") and isinstance(via.get("title"), str), "Malformed npm advisory")
                rows.append({"id": via["url"].rstrip("/").rsplit("/", 1)[-1], "source": via["source"],
                             "title": via["title"], "url": via["url"], "affected_versions": via.get("range")})
        return list({row["id"]: row for row in rows}.values())

    findings = []
    observed_counts = {level: 0 for level in LEVELS}
    for name, entry in vulnerabilities.items():
        require(isinstance(entry, dict) and entry.get("name") == name and entry.get("severity") in LEVELS,
                "Malformed npm vulnerability")
        nodes = entry.get("nodes")
        require(isinstance(nodes, list) and nodes and all(node in by_path for node in nodes),
                "npm finding does not identify resolved packages in the lockfile")
        require(all(by_path[node]["name"] == name for node in nodes), "npm finding/package mismatch")
        observed_counts[entry["severity"]] += 1
        findings.append({"kind": "vulnerability", "package": name, "severity": entry["severity"],
                         "instances": [by_path[node] for node in nodes], "advisories": advisories(name, set()),
                         "via_packages": [v for v in entry["via"] if isinstance(v, str)],
                         "fix_available": entry.get("fixAvailable")})
    require(all(counts.get(level) == value for level, value in observed_counts.items()),
            "npm severity counts are inconsistent")
    require((code == 1) == any(f["severity"] != "info" for f in findings),
            "npm exit status disagrees with audit-level=low")
    return findings


def decide(findings, policy, ecosystem):
    require(policy.get("schema_version") == 1 and policy.get("unknown_severity") == "block"
            and policy.get("abandoned_packages") == "review", "Invalid SCA policy")
    thresholds = policy.get("blocking_threshold", {})
    require(set(thresholds) == {"runtime", "development"}
            and all(v in LEVELS for v in thresholds.values()), "Invalid SCA thresholds")
    exceptions = policy.get("exceptions")
    require(isinstance(exceptions, list), "Invalid SCA exception list")
    seen = set()
    for entry in exceptions:
        fields = ("ecosystem", "package", "version", "advisory_id", "classification", "reason",
                  "remaining_risk", "compensating_controls", "review_condition", "owner", "expires_on")
        require(isinstance(entry, dict) and all(isinstance(entry.get(k), str) and entry[k].strip() for k in fields),
                "Incomplete SCA exception")
        identity = tuple(entry[k] for k in ("ecosystem", "package", "version", "advisory_id"))
        require(entry["ecosystem"] in ("composer", "npm") and identity not in seen, "Duplicate/invalid SCA exception")
        require(dt.date.fromisoformat(entry["expires_on"]) >= dt.date.today(), "Expired SCA exception")
        seen.add(identity)
    for finding in findings:
        if finding["kind"] == "abandoned":
            finding["decision"] = "review"
            continue
        accepted = all((ecosystem, finding["package"], p["version"], a["id"]) in seen
                       for p in finding["instances"] for a in finding["advisories"])
        if accepted:
            finding["decision"] = "accepted_exception"
        elif finding["severity"] == "unknown" or any(
                LEVELS[finding["severity"]] >= LEVELS[thresholds[p["scope"]]] for p in finding["instances"]):
            finding["decision"] = "block"
        else:
            finding["decision"] = "review"
    return 1 if any(f["decision"] == "block" for f in findings) else 0


def run_sca(ecosystem, repo, output, *, offline=False):
    output.mkdir(parents=True, exist_ok=True)
    result = {"schema_version": 1, "run_id": str(uuid.uuid4()), "category": "sca", "ecosystem": ecosystem,
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "status": "operational_error",
              "scenario": "registry-unavailable" if offline else "normal", "findings": [], "analysis_valid": False}
    code = 2
    # Do not reuse evidence from a previous run if the current attempt fails early.
    for name in ("audit.json", "inventory.json", "validation.log"):
        (output / name).unlink(missing_ok=True)
    try:
        tools = json.loads((ROOT / "security/tools.json").read_text())
        policy = json.loads((ROOT / "security/sca-policy.json").read_text())
        decide([], policy, ecosystem)  # Validate policy even when the scanner finds nothing.
        names = ("composer.json", "composer.lock") if ecosystem == "composer" else ("package.json", "package-lock.json")
        manifest, lock = (json.loads((repo / name).read_text()) for name in names)
        if ecosystem == "composer":
            config = manifest.get("config", {})
            require(not any(k in config for k in ("audit", "policy")) and "repositories" not in manifest,
                    "Composer audit overrides/custom sources require explicit policy support")
        packages = inventory(ecosystem, manifest, lock)
        result["commit"] = git(repo, "rev-parse", "HEAD").decode().strip()
        result["working_tree_dirty"] = bool(git(repo, "status", "--porcelain"))
        result["input_sha256"] = {name: digest(repo / name) for name in names}
        result["policy_sha256"] = digest(ROOT / "security/sca-policy.json")
        result["tools_sha256"] = digest(ROOT / "security/tools.json")
        result["inventory_count"] = len(packages)
        result["coverage"] = {"direct_and_transitive": True, "development_included": True,
                              "local_packages": [p for p in packages if p["source"] == "local-file"]}
        (output / "inventory.json").write_text(json.dumps(packages, indent=2) + "\n")
        image = tools["composer_image" if ecosystem == "composer" else "node_image"]
        require("@sha256:" in image and image in (ROOT / "Dockerfile").read_text(),
                "SCA tool image must be pinned and match the application Dockerfile")
        result["scanner"] = {"image": image, "name": ecosystem,
                             "version": tools["composer_version" if ecosystem == "composer" else "npm_version"]}
        result["advisory_source"] = "https://packagist.org" if ecosystem == "composer" else "https://registry.npmjs.org"
        with tempfile.TemporaryDirectory(prefix="acme-sca-") as tmp:
            work = Path(tmp)
            for name in names:
                shutil.copyfile(repo / name, work / name)
            base = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "-e", "COMPOSER_HOME=/tmp/composer",
                    "-e", "COMPOSER_CACHE_DIR=/tmp/composer-cache", "-e", "npm_config_cache=/tmp/npm",
                    "-e", "npm_config_update_notifier=false", "-e", "npm_config_fetch_retries=0",
                    "-e", "npm_config_fetch_timeout=8000", "-v", f"{work}:/app", "-w", "/app"]
            def invoke(args, network=False):
                return command(base + (["--network=none"] if network and offline else []) + [image] + args, timeout=180)
            if ecosystem == "composer":
                probe = invoke(["composer", "--version", "--no-ansi"])
                require(probe.returncode == 0 and probe.stdout.decode().startswith("Composer version " + tools["composer_version"] + " "),
                        "Unexpected/unavailable Composer version")
                validation = invoke(["composer", "validate", "--strict", "--check-lock", "--no-check-publish", "--no-plugins", "--no-scripts"])
                audit_command = ["composer", "audit", "--locked", "--format=json", "--no-interaction",
                                 "--no-plugins", "--no-scripts", "--abandoned=report"]
            else:
                probe = invoke(["npm", "--version"])
                node_probe = invoke(["node", "--version"])
                require(probe.returncode == 0 and probe.stdout.decode().strip() == tools["npm_version"]
                        and node_probe.returncode == 0 and node_probe.stdout.decode().strip() == "v" + tools["node_version"],
                        "Unexpected/unavailable npm or Node version")
                result["scanner"]["node_version"] = tools["node_version"]
                validation = invoke(["npm", "ci", "--dry-run", "--ignore-scripts", "--install-links=true", "--include=dev",
                                     "--include=optional", "--include=peer", "--no-audit", "--fund=false"])
                audit_command = ["npm", "audit", "--package-lock-only", "--include=dev", "--include=optional",
                                 "--include=peer", "--ignore-scripts", "--json", "--audit-level=low",
                                 "--registry=https://registry.npmjs.org"]
            (output / "validation.log").write_bytes(validation.stdout + validation.stderr)
            require(validation.returncode == 0, "Manifest/lock validation failed; see validation.log")
            require(all(digest(work / name) == result["input_sha256"][name] for name in names),
                    "Validation unexpectedly modified a manifest/lockfile")
            result["manifest_lock_consistent"] = True
            result["command"] = audit_command
            process = invoke(audit_command, network=True)
            result["scanner_exit_code"] = process.returncode
            try:
                report = json.loads(process.stdout)
            except ValueError as exc:
                raise OperationalError(f"{ecosystem} produced no valid JSON report (exit {process.returncode})") from exc
            # Reports from the fixed public advisory sources; no auth or application data is mounted.
            (output / "audit.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
            findings = (parse_composer if ecosystem == "composer" else parse_npm)(report, process.returncode, packages)
            code = decide(findings, policy, ecosystem)
            result.update(findings=findings, analysis_valid=True, status="policy_violation" if code else "pass",
                          blocking_findings=sum(f["decision"] == "block" for f in findings),
                          review_findings=sum(f["decision"] == "review" for f in findings))
    except (OperationalError, OSError, ValueError, KeyError, TypeError) as exc:
        result["error"] = str(exc) if isinstance(exc, OperationalError) else type(exc).__name__
    (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"SCA {ecosystem}: {result['status']} (exit {code}); report: {output / 'result.json'}")
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", choices=["composer", "npm", "all"], default="all")
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/security/sca")
    parser.add_argument("--offline-demo", action="store_true", help="Intentionally disconnect the real audit from its registry")
    args = parser.parse_args()
    targets = ("composer", "npm") if args.ecosystem == "all" else (args.ecosystem,)
    codes = [run_sca(target, args.repository.resolve(), args.output.resolve() / target, offline=args.offline_demo) for target in targets]
    raise SystemExit(max(codes))
