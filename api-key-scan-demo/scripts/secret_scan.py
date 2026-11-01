#!/usr/bin/env python3
"""secret_scan.py - a small, dependency-free secret scanner for CI pipelines.

Exit codes:
    0  no findings
    1  one or more potential secrets found (pipeline should stop)
    2  usage or configuration error
"""

import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_EXCLUDE_DIRS = {".git", "node_modules", "tests", "__pycache__"}
MAX_FILE_BYTES = 1_000_000
ALLOW_MARKER = "secretscan:allow"

# Only applied to rules with "ignore_placeholders": true (the generic rule).
PLACEHOLDER_MARKERS = (
    "example", "your", "changeme", "change_me", "placeholder",
    "dummy", "sample", "xxxx", "<", ">", "${", "{{", "process.env",
)

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "secret-rules.json"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    severity: str
    description: str
    redacted: str


def shannon_entropy(value):
    """Bits of entropy per character. Random keys score high, 'aaaa...' scores 0."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value):
    low = value.lower()
    return any(marker in low for marker in PLACEHOLDER_MARKERS)


def redact(value):
    """Never print a full secret into CI logs (logs are often readable by many people)."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 6, 12) + value[-2:]


def load_rules(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    rules = []
    for raw in data["rules"]:
        rules.append({
            "id": raw["id"],
            "description": raw["description"],
            "severity": raw["severity"],
            "regex": re.compile(raw["regex"]),
            "secret_group": raw.get("secret_group", 0),
            "min_entropy": raw.get("min_entropy", 0.0),
            "ignore_placeholders": raw.get("ignore_placeholders", False),
        })
    return rules


def scan_text(rules, text, path="<memory>"):
    """Scan text line by line. Rules are tried in file order, so specific rules
    win over the generic one: if two rules hit the same value on the same line,
    only the first (most specific) is reported."""
    findings = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        seen_values = set()
        for rule in rules:
            for match in rule["regex"].finditer(line):
                secret = match.group(rule["secret_group"])
                if secret in seen_values:
                    continue
                if rule["ignore_placeholders"] and is_placeholder(secret):
                    continue
                if shannon_entropy(secret) < rule["min_entropy"]:
                    continue
                seen_values.add(secret)
                findings.append(Finding(
                    path=path,
                    line=line_no,
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    description=rule["description"],
                    redacted=redact(secret),
                ))
    return findings


def iter_files(paths, exclude_dirs):
    for root in paths:
        root = Path(root)
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in exclude_dirs)
            for name in sorted(filenames):
                yield Path(dirpath) / name


def read_text_file(path):
    """Return file text, or None for binary / oversized / unreadable files."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8000]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_paths(rules, paths, exclude_dirs):
    findings = []
    files_scanned = 0
    for file_path in iter_files(paths, exclude_dirs):
        text = read_text_file(file_path)
        if text is None:
            continue
        files_scanned += 1
        shown = os.path.relpath(file_path).replace(os.sep, "/")
        findings.extend(scan_text(rules, text, shown))
    return files_scanned, findings


def write_step_summary(files_scanned, findings):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = ["## Secret scan", ""]
    if findings:
        lines.append(f"**FAILED** - {len(findings)} potential secret(s) in {files_scanned} files. Deployment blocked.")
        lines += ["", "| File | Line | Rule | Value (redacted) |", "|---|---|---|---|"]
        for f in findings:
            lines.append(f"| `{f.path}` | {f.line} | `{f.rule_id}` | `{f.redacted}` |")
    else:
        lines.append(f"**PASSED** - no secrets found in {files_scanned} files.")
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan files for hardcoded secrets.")
    parser.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    parser.add_argument("--rules", default=str(DEFAULT_RULES), help="path to rules JSON")
    parser.add_argument("--exclude-dir", action="append", default=[],
                        help="extra directory name to skip (repeatable)")
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except (OSError, KeyError, ValueError, re.error) as exc:
        print(f"error: could not load rules from {args.rules}: {exc}", file=sys.stderr)
        return 2

    exclude = DEFAULT_EXCLUDE_DIRS | set(args.exclude_dir)
    files_scanned, findings = scan_paths(rules, args.paths, exclude)
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"

    if findings:
        print(f"SECRET SCAN FAILED: {len(findings)} potential secret(s) in {files_scanned} files scanned\n")
        for f in findings:
            print(f"  {f.path}:{f.line}  [{f.severity.upper()}] {f.rule_id}  ->  {f.redacted}")
            print(f"      {f.description}")
            if in_actions:
                # GitHub turns this line into an annotation on the file in the PR / run page.
                print(f"::error file={f.path},line={f.line},title=Hardcoded secret detected::"
                      f"{f.rule_id}: {f.redacted}")
        print("\nDeployment must not continue. Remove the secret, ROTATE it (assume it is burned), then push again.")
    else:
        print(f"SECRET SCAN PASSED: no secrets found in {files_scanned} files scanned")

    write_step_summary(files_scanned, findings)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
