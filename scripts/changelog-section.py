#!/usr/bin/env python3
"""Print the CHANGELOG.md section of one version, for release notes.

Usage: scripts/changelog-section.py 1.0.0
Exit code 1 when the version has no section.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def section(version: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    # A heading looks like "## 1.0.0 — 2026-11-21" or "## 1.0.0".
    pattern = re.compile(r"^##\s+" + re.escape(version) + r"\b.*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return ""
    start = match.start()
    following = re.compile(r"^##\s+", re.MULTILINE).search(text, match.end())
    end = following.start() if following else len(text)
    return text[start:end].strip() + "\n"


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    body = section(argv[1])
    if not body:
        print(f"no CHANGELOG section for {argv[1]}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
