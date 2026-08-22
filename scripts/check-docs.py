#!/usr/bin/env python3
"""Validate local Markdown links and checked-in JSON documentation fixtures."""

from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
errors = []

for path in sorted(ROOT.rglob("*.json")):
    if ".git" in path.parts:
        continue
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{path.relative_to(ROOT)}: invalid JSON: {exc}")

link_re = re.compile(r"!?(?:\[[^]]*\])\(([^)]+)\)")
for source in sorted(ROOT.rglob("*.md")):
    if ".git" in source.parts:
        continue
    text = source.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        errors.append(f"{source.relative_to(ROOT)}: Markdown file must end with a newline")
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.endswith((" ", "\t")):
            errors.append(f"{source.relative_to(ROOT)}:{line_number}: trailing whitespace")
    for raw in link_re.findall(text):
        target = raw.strip().split()[0].strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        resolved = (source.parent / target).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(f"{source.relative_to(ROOT)}: link escapes repository: {raw}")
            continue
        if not resolved.exists():
            errors.append(f"{source.relative_to(ROOT)}: missing link target: {raw}")

if errors:
    print("Documentation checks failed:", file=sys.stderr)
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)

print("Documentation links and JSON fixtures are valid.")
