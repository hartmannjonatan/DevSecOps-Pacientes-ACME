#!/usr/bin/env python3
"""Analyze unsafe/corrected copies of the real Dockerfile; never build or run them."""
import argparse
import difflib
import json
from pathlib import Path
import tempfile

from demo import fixture
from iac import ROOT, scan


def sources():
    corrected = (ROOT / "Dockerfile").read_text()
    if "USER www-data\n" not in corrected or corrected.count("HEALTHCHECK ") != 1:
        raise ValueError("Dockerfile changed: review the controlled demonstration")
    vulnerable = corrected.replace("USER www-data\n", "USER root\n")
    vulnerable = "\n".join("HEALTHCHECK NONE" if line.startswith("HEALTHCHECK ") else line
                           for line in vulnerable.splitlines()) + "\n"
    return vulnerable, corrected


def demonstrate(scenario, output):
    output.mkdir(parents=True, exist_ok=True)
    before, after = sources()
    with tempfile.TemporaryDirectory(prefix="acme-iac-demo-") as tmp:
        repo = Path(tmp) / "repo"
        fixture(repo)
        content = after if scenario == "iac-corrected" else before
        if scenario == "iac-operational-failure":
            content = "THIS_IS_NOT_A_DOCKERFILE\n"
        (repo / "Dockerfile").write_text(content)
        (repo / "compose.yaml").write_text((ROOT / "compose.yaml").read_text())
        (output / "source.json").write_text(json.dumps({"Dockerfile": content}, indent=2) + "\n")
        (output / "correction.diff").write_text("".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                                          fromfile="before/Dockerfile", tofile="after/Dockerfile")))
        return scan(repo, output, scenario=scenario)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["iac-fixture", "iac-corrected", "iac-operational-failure"])
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/security/iac-demo")
    args = parser.parse_args()
    raise SystemExit(demonstrate(args.scenario, args.output.resolve()))
