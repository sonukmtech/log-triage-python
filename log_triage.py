"""
log_triage.py - Security log triage tool
Parses Linux auth logs, detects suspicious patterns, and generates a
Markdown incident report aligned to NIST SP 800-61 phases.
Author: Sonu Kumar | MIT License
NOTE: regexes use re.search() per line (no sticky-flag state bugs).
"""

import argparse
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SIGNATURES = {
    "brute_force": {
        "pattern": r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)",
        "group_by": 2,          # count by source IP
        "technique": "T1110 - Brute Force",
        "threshold": 5,
        "severity": "HIGH",
    },
    "privilege_escalation": {
        "pattern": r"session opened for user root",
        "group_by": None,
        "technique": "T1548 - Abuse Elevation Control Mechanism",
        "threshold": 1,
        "severity": "MEDIUM",
    },
    "sensitive_file_access": {
        "pattern": r"COMMAND=(.*?/etc/shadow)",
        "group_by": 1,
        "technique": "T1003 - OS Credential Dumping",
        "threshold": 1,
        "severity": "HIGH",
    },
    "unauthorized_user_creation": {
        "pattern": r"COMMAND=(.*?/usr/sbin/useradd)\s+(\S+)",
        "group_by": 2,
        "technique": "T1136 - Create Account",
        "threshold": 1,
        "severity": "HIGH",
    },
}


def parse_log(path):
    """Yield (timestamp, message) tuples from an auth log."""
    ts_re = re.compile(r"^(\w{3}\s+\d+\s+[\d:]+)\s")
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            m = ts_re.match(line)
            yield (m.group(1) if m else "unknown"), line.strip()


def detect(log_path):
    counts = defaultdict(lambda: defaultdict(int))
    evidence = defaultdict(list)

    for ts, line in parse_log(log_path):
        for name, sig in SIGNATURES.items():
            m = re.search(sig["pattern"], line)
            if not m:
                continue
            gi = sig["group_by"]
            key = m.group(gi) if gi else "n/a"
            counts[name][key] += 1
            evidence[(name, key)].append((ts, line))

    sev_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = []
    for name, keys in counts.items():
        sig = SIGNATURES[name]
        for key, n in keys.items():
            if n >= sig["threshold"]:
                findings.append({
                    "rule": name,
                    "technique": sig["technique"],
                    "severity": sig["severity"],
                    "subject": key,
                    "count": n,
                    "evidence": evidence[(name, key)][:5],
                })
    return sorted(findings, key=lambda f: sev_rank[f["severity"]])


def generate_report(findings, source, out_dir="reports"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    lines = [
        "# Incident Triage Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC",
        f"**Source:** `{source}`",
        f"**Findings:** {len(findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Technique | Subject | Events |",
        "|----------|-----------|---------|--------|",
    ]
    for f in findings:
        lines.append(f"| {f['severity']} | {f['technique']} | `{f['subject']}` | {f['count']} |")

    lines += ["", "## Evidence (Detection Phase — NIST SP 800-61 §3.2)", ""]
    for f in findings:
        lines.append(f"### {f['rule']} — `{f['subject']}` ({f['count']} events)")
        lines.append("```text")
        lines += [f"{ts}  {ln}" for ts, ln in f["evidence"]]
        lines += ["```", ""]

    out = Path(out_dir) / "incident_report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Report written to {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Triage suspicious activity in a Linux auth log.")
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=Path("sample_logs/auth.log"),
        help="path to the auth log to analyze (default: sample_logs/auth.log)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports"),
        help="directory for the generated incident report (default: reports)",
    )
    args = parser.parse_args()

    if not args.log_file.is_file():
        parser.error(f"log file does not exist or is not a file: {args.log_file}")

    results = detect(args.log_file)
    print(f"[!] {len(results)} finding(s) detected")
    generate_report(results, args.log_file, args.output_dir)