"""Project policy: the final app stage must explicitly select a non-root user."""
import re
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck


class RuntimeUser(BaseDockerfileCheck):
    def __init__(self):
        super().__init__(name="ACME: final app stage explicitly uses a non-root user", id="CKV_ACME_DOCKER_1",
                         categories=(CheckCategories.IAM,), supported_instructions=("*",))

    def scan_resource_conf(self, conf):
        stages = conf.get("FROM", [])
        if not stages or not re.search(r"\sAS\s+app\s*$", stages[-1]["value"], re.I):
            return CheckResult.FAILED, stages or None
        users = [item for item in conf.get("USER", []) if item["startline"] > stages[-1]["startline"]]
        if not users:
            return CheckResult.FAILED, [stages[-1]]
        user = users[-1]["value"].strip().split(":")[0]
        valid = re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*|[0-9]+", user)
        nonroot = valid and user.lower() != "root" and not (user.isdigit() and int(user) == 0)
        return (CheckResult.PASSED if nonroot else CheckResult.FAILED), [users[-1]]


check = RuntimeUser()
