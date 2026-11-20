"""Project policy: a build-stage healthcheck or HEALTHCHECK NONE is insufficient."""
import re
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck


class RuntimeHealthcheck(BaseDockerfileCheck):
    def __init__(self):
        super().__init__(name="ACME: final app stage explicitly declares an active healthcheck", id="CKV_ACME_DOCKER_2",
                         categories=(CheckCategories.APPLICATION_SECURITY,), supported_instructions=("*",))

    def scan_resource_conf(self, conf):
        stages = conf.get("FROM", [])
        if not stages or not re.search(r"\sAS\s+app\s*$", stages[-1]["value"], re.I):
            return CheckResult.FAILED, stages or None
        checks = [item for item in conf.get("HEALTHCHECK", []) if item["startline"] > stages[-1]["startline"]]
        if not checks:
            return CheckResult.FAILED, [stages[-1]]
        active = re.match(r"^(?:--\S+\s+)*CMD\s+\S", checks[-1]["value"], re.I)
        return (CheckResult.PASSED if active else CheckResult.FAILED), [checks[-1]]


check = RuntimeHealthcheck()
