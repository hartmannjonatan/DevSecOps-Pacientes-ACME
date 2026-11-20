"""Fetch immutable upstream rules for internal analysis; do not redistribute them."""
import hashlib
import io
import json
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from scan import OperationalError, command, digest


def prepare_rules(config, cache, docker_args):
    provenance = json.loads((config / "semgrep/provenance.json").read_text())
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / "rules.json"
    if target.exists():
        if digest(target) != provenance["rules_sha256"]:
            raise OperationalError("Cached rules changed; remove cache and fetch the pinned revision again")
        return target
    revision = provenance["commit"]
    url = f"https://codeload.github.com/semgrep/semgrep-rules/tar.gz/{revision}"
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            archive = response.read(40_000_001)
    except OSError as exc:
        raise OperationalError("Cannot download pinned upstream rules") from exc
    if hashlib.sha256(archive).hexdigest() != provenance["archive_sha256"]:
        raise OperationalError("Rules archive checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="acme-sast-rules-") as tmp:
        root = Path(tmp)
        paths = []
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for source in provenance["sources"]:
                relative = Path(source["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise OperationalError("Invalid upstream rule path")
                member = tar.getmember(f"semgrep-rules-{revision}/{relative.as_posix()}")
                if not member.isfile() or member.size > 1_000_000:
                    raise OperationalError("Invalid upstream rule member")
                content = tar.extractfile(member).read()
                if hashlib.sha256(content).hexdigest() != source["sha256"]:
                    raise OperationalError("Upstream rule checksum mismatch")
                dest = root / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
                paths.append(relative.as_posix())
        (root / "paths.json").write_text(json.dumps(paths))
        # The YAML parser comes from the pinned Semgrep image, not the host.
        conversion = """import json,pathlib
from ruamel.yaml import YAML
yaml=YAML(typ='safe'); yaml.version=(1,1)
root=pathlib.Path('/rules'); rules=[]
for relative in json.loads((root/'paths.json').read_text()):
    for rule in yaml.load((root/relative).read_text())['rules']:
        rule['id']=str(pathlib.PurePosixPath(relative).with_suffix('')).replace('/','.')+'.'+rule['id']
        rules.append(rule)
print(json.dumps({'rules':rules},indent=2))
"""
        p = command([*docker_args[:-1], "-v", f"{root}:/rules:ro", docker_args[-1],
                     "python3", "-c", conversion])
        if p.returncode or hashlib.sha256(p.stdout).hexdigest() != provenance["rules_sha256"]:
            raise OperationalError("Rules conversion failed or produced unexpected content")
        target.write_bytes(p.stdout)
    return target
