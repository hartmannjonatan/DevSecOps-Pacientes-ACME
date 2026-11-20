"""Read public build configuration inside the pinned Checkov image; never load .env."""
import json
from pathlib import Path
import re

from dockerfile_parse import DockerfileParser
import yaml


def inspect(root):
    root = Path(root)
    compose = yaml.safe_load((root / "compose.yaml").read_text())
    build = compose["services"]["app"]["build"]
    if (not isinstance(build, dict) or build.get("context") != "."
            or build.get("dockerfile", "Dockerfile") != "Dockerfile" or build.get("target") != "app"
            or "dockerfile_inline" in build):
        raise ValueError("Unexpected Compose build target: review the IaC scope")
    instructions = DockerfileParser(str(root)).structure
    allowed = {"ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM", "HEALTHCHECK",
               "LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL", "STOPSIGNAL", "USER", "VOLUME", "WORKDIR", "COMMENT"}
    if any(item["instruction"] not in allowed for item in instructions):
        raise ValueError("Unrecognized Dockerfile instruction")
    stages = [item for item in instructions if item["instruction"] == "FROM"]
    if not stages:
        raise ValueError("Dockerfile has no FROM stage")
    if not re.search(r"\sAS\s+app\s*$", stages[-1]["value"], re.I):
        raise ValueError("Compose target app must be the final Dockerfile stage for this policy")
    return {"compose_service": "app", "context": ".", "dockerfile": "Dockerfile", "target": "app",
            "stages": [{"from": item["value"], "line": item["startline"] + 1} for item in stages],
            "instruction_count": sum(item["instruction"] != "COMMENT" for item in instructions)}


if __name__ == "__main__":
    print(json.dumps(inspect("/src"), indent=2))
