#!/usr/bin/env python3
import argparse
import csv
import html
import json
import re
import sys
from pathlib import Path


HEADERS = [
    "Domain",
    "Scan Type",
    "Risk Summary",
    "Observations",
    "Detailed Report",
    "Proposal",
    "Temporary Removal",
]


RECOMMENDATIONS = {
    "10003": "upgrade the vulnerable JavaScript library or raise a vendor/support ticket if it is part of a managed platform bundle",
    "10038": "add a restrictive Content-Security-Policy header, starting in report-only mode if needed and then enforcing it",
    "10020": "add X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors to prevent clickjacking",
    "10021": "set X-Content-Type-Options: nosniff on HTML and other served content",
    "10035": "enable HTTP Strict Transport Security with an appropriate max-age after confirming HTTPS is correctly deployed",
    "10098": "restrict Access-Control-Allow-Origin to trusted origins or remove permissive CORS headers from unauthenticated resources",
    "90003": "add Subresource Integrity attributes for third-party scripts/styles or self-host trusted assets",
    "10010": "set HttpOnly on session and application cookies",
    "10011": "set Secure on cookies served over HTTPS",
    "10054": "set SameSite=Lax or Strict for cookies unless cross-site behavior is explicitly required",
    "10017": "review third-party JavaScript sources and keep only trusted, necessary script origins",
    "10096": "verify exposed timestamps are non-sensitive and remove them if they disclose implementation details",
    "10027": "remove comments that reveal implementation details, TODOs, paths, secrets, or debugging hints",
    "10015": "review Cache-Control directives; prevent caching for sensitive pages and allow caching only for static public assets",
    "10050": "verify cached responses do not contain user-specific or sensitive data",
    "10112": "review session identifiers/cookies and ensure secure session-management settings are applied",
    "40012": "investigate SQL injection evidence immediately and fix parameterized query handling",
    "40014": "investigate cross-site scripting evidence immediately and fix output encoding/input handling",
    "40016": "investigate command injection evidence immediately and remove unsafe command execution paths",
    "40018": "investigate file inclusion evidence immediately and restrict file/path handling",
    "40019": "investigate path traversal evidence immediately and restrict file/path handling",
    "7": "disable or remove external entity processing in XML parsers",
    "6": "fix path traversal handling and restrict filesystem access",
}


IGNORE_FOR_PROPOSAL = {
    "10109",  # Modern Web Application
}


REMOVAL_ALERT_PATTERNS = [
    re.compile(r"\b(remote code execution|command injection|server side template injection)\b", re.I),
    re.compile(r"\b(sql injection|path traversal|local file inclusion|remote file inclusion|xxe|external entity)\b", re.I),
    re.compile(r"\b(default credentials|private key|secret|password)\b", re.I),
    re.compile(r"\b(web shell|backdoor|malware)\b", re.I),
]


REMOVE_ALERT_PATTERNS = [
    re.compile(r"\b(remote code execution|command injection|server side template injection)\b", re.I),
    re.compile(r"\b(sql injection|path traversal|local file inclusion|remote file inclusion|xxe|external entity)\b", re.I),
    re.compile(r"\b(default credentials|private key|secret|password)\b", re.I),
    re.compile(r"\b(web shell|backdoor|malware)\b", re.I),
]


def clean_text(value):
    value = html.unescape(value or "")
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def risk_name(alert):
    riskdesc = alert.get("riskdesc") or ""
    if "(" in riskdesc:
        return riskdesc.split("(", 1)[0].strip()
    code = str(alert.get("riskcode", ""))
    return {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}.get(code, "Unknown")


def risk_rank(name):
    return {"High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Unknown": -1}.get(name, -1)


def instance_count(alert):
    instances = alert.get("instances") or []
    return len(instances)


def is_systemic(alert):
    return instance_count(alert) >= 3


def alert_label(alert):
    count = instance_count(alert)
    scope = "systemic" if count >= 3 else f"{count} instance" + ("" if count == 1 else "s")
    return f"{alert.get('alert', 'Unknown alert')} ({risk_name(alert)}, {scope})"


def needs_temporary_removal(alerts):
    for alert in alerts:
        haystack = " ".join(
            [
                alert.get("alert", ""),
                clean_text(alert.get("otherinfo", "")),
                " ".join(clean_text(instance.get("evidence", "")) for instance in alert.get("instances", [])),
            ]
        )
        if risk_name(alert) == "High" and any(pattern.search(haystack) for pattern in REMOVE_ALERT_PATTERNS):
            return "REMOVE: temporarily remove or restrict access until the confirmed high-impact exposure is fixed."

    return "KEEP: no temporary removal recommended based on this ZAP report; keep online while fixing the listed issues urgently."


def proposal_prefix(alerts):
    return "REMOVE" if needs_temporary_removal(alerts).startswith("REMOVE:") else "KEEP"


def build_observations(alerts):
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Unknown": 0}
    for alert in alerts:
        counts[risk_name(alert)] = counts.get(risk_name(alert), 0) + 1

    ordered = sorted(alerts, key=lambda a: (-risk_rank(risk_name(a)), a.get("alert", "")))
    significant = [a for a in ordered if risk_name(a) in {"High", "Medium", "Low"}]
    if not significant:
        significant = ordered[:5]

    top_items = [alert_label(a) for a in significant[:8]]
    summary = f"{counts.get('High', 0)} High, {counts.get('Medium', 0)} Medium, {counts.get('Low', 0)} Low, {counts.get('Informational', 0)} Informational alerts"
    if top_items:
        return summary + ". Key findings: " + "; ".join(top_items) + "."
    return summary + ". No actionable ZAP alerts reported."


def build_risk_summary(alerts):
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Unknown": 0}
    for alert in alerts:
        counts[risk_name(alert)] = counts.get(risk_name(alert), 0) + 1
    return f"High: {counts.get('High', 0)}; Medium: {counts.get('Medium', 0)}; Low: {counts.get('Low', 0)}; Informational: {counts.get('Informational', 0)}"


def build_proposal(alerts):
    ordered = sorted(alerts, key=lambda a: (-risk_rank(risk_name(a)), a.get("alert", "")))
    recs = []
    seen = set()
    for alert in ordered:
        pluginid = str(alert.get("pluginid", ""))
        name = alert.get("alert", "")
        if pluginid in IGNORE_FOR_PROPOSAL:
            continue
        rec = RECOMMENDATIONS.get(pluginid)
        if not rec:
            solution = clean_text(alert.get("solution", ""))
            rec = solution[:180] if solution else f"review and remediate {name}"
        if rec not in seen and risk_name(alert) in {"High", "Medium", "Low"}:
            recs.append(rec)
            seen.add(rec)
        if len(recs) >= 8:
            break

    prefix = proposal_prefix(alerts)
    if not recs:
        return f"{prefix}: No immediate remediation required from this ZAP report; manually verify application logic, authentication, authorization, and exposed admin/upload paths."

    priority = "Prioritize High findings first, then Medium and Low hardening items: "
    return f"{prefix}: " + priority + "; ".join(recs) + ". Also manually verify authentication, authorization, upload/code execution paths, admin panels, and server ownership."


def write_text(fields):
    labels = [
        "Domain",
        "Scan Type",
        "Risk Summary",
        "Observations",
        "Detailed Report",
        "Proposal",
        "Temporary Removal",
    ]
    for label, value in zip(labels, fields):
        print(f"{label}: {value}")


def load_alerts(report):
    with open(report, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    alerts = []
    for site in data.get("site", []):
        alerts.extend(site.get("alerts", []))
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Generate deterministic spreadsheet fields from a ZAP JSON report.")
    parser.add_argument("report", help="Path to ZAP traditional JSON report")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--scan-type", default="Passive")
    parser.add_argument("--report-link", default="")
    parser.add_argument("--format", choices=["text", "csv"], default="text")
    parser.add_argument("--no-header", action="store_true")
    args = parser.parse_args()

    report_path = Path(args.report)
    alerts = load_alerts(report_path)
    detail = args.report_link or str(report_path)
    row = [
        args.domain,
        args.scan_type,
        build_risk_summary(alerts),
        build_observations(alerts).replace("\n", " "),
        detail,
        build_proposal(alerts).replace("\n", " "),
        needs_temporary_removal(alerts).replace("\n", " "),
    ]

    if args.format == "csv":
        writer = csv.writer(sys.stdout)
        if not args.no_header:
            writer.writerow(HEADERS)
        writer.writerow(row)
    else:
        write_text(row)


if __name__ == "__main__":
    main()
