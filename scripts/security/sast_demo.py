#!/usr/bin/env python3
"""Isolated SAST examples: source is scanned, never executed or served."""
import argparse
import difflib
import json
from pathlib import Path
import tempfile

from demo import fixture
from sast import ROOT, scan

BEFORE = {
    "example.php": '''<?php
// Intentionally vulnerable synthetic example. Never executed.
function search($db) {
    $name = $_GET['name'];
    return $db->query("SELECT nome FROM paciente WHERE nome = '" . $name . "'");
}
''',
    "Example.jsx": '''import React from 'react';
// Intentionally vulnerable synthetic example. Never rendered.
export function Example({name}) {
    return <div dangerouslySetInnerHTML={{__html: name}} />;
}
''',
}
AFTER = {
    "example.php": '''<?php
// Corrected synthetic example. Prepared SQL keeps input separate from commands.
function search($db) {
    $name = $_GET['name'];
    $query = $db->prepare("SELECT nome FROM paciente WHERE nome = :name");
    $query->execute(['name' => $name]);
    return $query->fetchAll();
}
''',
    "Example.jsx": '''import React from 'react';
// Corrected synthetic example. React renders the value as escaped text.
export function Example({name}) {
    return <div>{name}</div>;
}
''',
}


def demonstrate(scenario, output):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="acme-sast-demo-") as tmp:
        repo = Path(tmp) / "repo"
        fixture(repo)
        sources = AFTER if scenario == "sast-corrected" else BEFORE
        for name, source in sources.items():
            (repo / name).write_text(source)
        if scenario == "sast-operational-failure":
            (repo / "example.php").write_text("<?php function broken( {\n")
        (output / "correction.diff").write_text("".join(
            "".join(difflib.unified_diff(BEFORE[name].splitlines(True), AFTER[name].splitlines(True),
                                        fromfile="before/" + name, tofile="after/" + name)) for name in BEFORE))
        (output / "source.json").write_text(json.dumps({p.name: p.read_text() for p in repo.iterdir()
                                                       if p.suffix in {".php", ".jsx"}}, indent=2) + "\n")
        return scan(repo, output, scenario=scenario)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["sast-fixture", "sast-corrected", "sast-operational-failure"])
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/security/sast-demo")
    args = parser.parse_args()
    raise SystemExit(demonstrate(args.scenario, args.output.resolve()))
