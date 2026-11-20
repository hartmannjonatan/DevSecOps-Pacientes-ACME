"""Project policy: pin external FROM and COPY --from images, preserving stage aliases."""
import re
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck


class PinnedImages(BaseDockerfileCheck):
    def __init__(self):
        super().__init__(name="ACME: external FROM and COPY images are pinned by SHA256", id="CKV_ACME_DOCKER_3",
                         categories=(CheckCategories.SUPPLY_CHAIN,), supported_instructions=("*",))

    def scan_resource_conf(self, conf):
        aliases = set()
        stage_count = 0
        inspected = []
        instructions = sorted(conf.get("FROM", []) + conf.get("COPY", []), key=lambda item: item["startline"])
        for item in instructions:
            value = item["value"]
            if item["instruction"] == "FROM":
                parts = value.split()
                if parts and parts[0].startswith("--platform="):
                    parts = parts[1:]
                if not parts:
                    return CheckResult.FAILED, [item]
                image = parts[0]
                internal = image.lower() in aliases or image.lower() == "scratch"
            else:
                match = re.search(r"(?:^|\s)--from=(\S+)", value)
                if not match:
                    continue
                image = match[1]
                internal = image.lower() in aliases or (image.isdigit() and int(image) < stage_count - 1)
            inspected.append(item)
            if not internal and not re.fullmatch(r"[^\s$]+@sha256:[a-f0-9]{64}", image):
                return CheckResult.FAILED, [item]
            if item["instruction"] == "FROM":
                stage_count += 1
                if len(parts) == 3 and parts[1].upper() == "AS":
                    aliases.add(parts[2].lower())
        return (CheckResult.PASSED if stage_count else CheckResult.FAILED), inspected or None


check = PinnedImages()
