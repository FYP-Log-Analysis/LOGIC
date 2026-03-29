"""
Export functionality for Windows forensic reports
Supports CSV and formatted text report exports
"""

import csv
from io import StringIO
from typing import Any


def export_sigma_matches_csv(matches: list[dict[str, Any]]) -> str:
    """Export Sigma matches to CSV format."""
    if not matches:
        return "timestamp,severity,rule_id,rule_title,computer,event_id,channel\n"
    
    output = StringIO()
    fieldnames = [
        "timestamp", "severity", "rule_id", "rule_title",
        "computer", "event_id", "channel", "client_ip",
        "mitre_techniques", "mitre_tactics"
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    
    for match in matches:
        row = {
            "timestamp": match.get("timestamp", ""),
            "severity": match.get("severity", ""),
            "rule_id": match.get("rule_id", ""),
            "rule_title": match.get("rule_title", ""),
            "computer": match.get("computer", ""),
            "event_id": match.get("event_id", ""),
            "channel": match.get("channel", ""),
            "client_ip": match.get("client_ip", ""),
            "mitre_techniques": ", ".join([t.get("technique_id", "") for t in match.get("mitre_techniques", [])]),
            "mitre_tactics": ", ".join(match.get("mitre_tactics", [])),
        }
        writer.writerow(row)
    
    return output.getvalue()


def export_behavioral_windows_csv(windows: list[dict[str, Any]]) -> str:
    """Export behavioral analysis windows to CSV format."""
    if not windows:
        return "window_start,event_count,anomaly_score,is_anomalous,unique_computers,unique_users,unique_source_ips\n"
    
    output = StringIO()
    fieldnames = [
        "window_start", "event_count", "anomaly_score", "is_anomalous",
        "unique_computers", "unique_users", "unique_source_ips",
        "security_events", "system_events", "powershell_events"
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    
    for window in windows:
        row = {
            "window_start": window.get("window_start", ""),
            "event_count": window.get("event_count", 0),
            "anomaly_score": f"{window.get('anomaly_score', 0):.4f}" if window.get('anomaly_score') else "",
            "is_anomalous": "Yes" if window.get("is_anomalous") else "No",
            "unique_computers": window.get("unique_computers", 0),
            "unique_users": window.get("unique_users", 0),
            "unique_source_ips": window.get("unique_source_ips", 0),
            "security_events": window.get("security_events", 0),
            "system_events": window.get("system_events", 0),
            "powershell_events": window.get("powershell_events", 0),
        }
        writer.writerow(row)
    
    return output.getvalue()


def export_iocs_csv(iocs: dict[str, Any]) -> str:
    """Export IOCs to CSV format."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Value"])
    
    for ip in iocs.get("ips", []):
        writer.writerow(["IP", ip])
    
    for domain in iocs.get("domains", []):
        writer.writerow(["Domain", domain])
    
    hashes = iocs.get("hashes", {})
    for md5 in hashes.get("md5", []):
        writer.writerow(["MD5", md5])
    for sha1 in hashes.get("sha1", []):
        writer.writerow(["SHA1", sha1])
    for sha256 in hashes.get("sha256", []):
        writer.writerow(["SHA256", sha256])
    
    for path in iocs.get("file_paths", []):
        writer.writerow(["File Path", path])
    
    for user in iocs.get("users", []):
        writer.writerow(["User", user])
    
    for process in iocs.get("processes", []):
        writer.writerow(["Process", process])
    
    return output.getvalue()


def generate_forensic_report(
    project_name: str,
    sigma_results: dict[str, Any],
    behavioral_results: dict[str, Any] | None,
    iocs: dict[str, Any],
) -> str:
    """Generate a comprehensive forensic report in text format."""
    
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("WINDOWS FORENSIC ANALYSIS REPORT")
    report_lines.append("=" * 80)
    report_lines.append(f"Project: {project_name}")
    report_lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    report_lines.append(f"Analysis Type: Windows Event Log (EVTX)")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # Executive Summary
    report_lines.append("EXECUTIVE SUMMARY")
    report_lines.append("-" * 80)
    total_matches = sigma_results.get("total_matches", 0)
    report_lines.append(f"  • Sigma Rule Matches: {total_matches}")
    report_lines.append(f"  • Unique Rules Triggered: {len(sigma_results.get('matched_rules', []))}")
    report_lines.append(f"  • Total IOCs Extracted: {iocs.get('total_iocs', 0)}")
    
    if behavioral_results:
        report_lines.append(f"  • Anomalous Time Windows: {behavioral_results.get('anomalous_windows', 0)}")
        report_lines.append(f"  • Total Time Windows Analyzed: {behavioral_results.get('total_windows', 0)}")
    
    report_lines.append("")
    
    # Severity Breakdown
    matches = sigma_results.get("matches", [])
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for match in matches:
        sev = str(match.get("severity", "low")).lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    report_lines.append("SEVERITY DISTRIBUTION")
    report_lines.append("-" * 80)
    report_lines.append(f"  CRITICAL: {severity_counts['critical']}")
    report_lines.append(f"  HIGH:     {severity_counts['high']}")
    report_lines.append(f"  MEDIUM:   {severity_counts['medium']}")
    report_lines.append(f"  LOW:      {severity_counts['low']}")
    report_lines.append("")
    
    # MITRE ATT&CK Techniques
    mitre_techniques = set()
    mitre_tactics = set()
    for match in matches:
        for technique in match.get("mitre_techniques", []):
            mitre_techniques.add(f"{technique.get('technique_id')} - {technique.get('name')}")
            mitre_tactics.add(technique.get("tactic", ""))
    
    if mitre_techniques:
        report_lines.append("MITRE ATT&CK TECHNIQUES DETECTED")
        report_lines.append("-" * 80)
        for technique in sorted(mitre_techniques):
            report_lines.append(f"  • {technique}")
        report_lines.append("")
        
        report_lines.append("MITRE ATT&CK TACTICS")
        report_lines.append("-" * 80)
        for tactic in sorted(mitre_tactics):
            if tactic:
                report_lines.append(f"  • {tactic}")
        report_lines.append("")
    
    # IOCs
    report_lines.append("INDICATORS OF COMPROMISE (IOCs)")
    report_lines.append("-" * 80)
    report_lines.append(f"IP Addresses ({len(iocs.get('ips', []))}):")
    for ip in iocs.get("ips", [])[:20]:
        report_lines.append(f"  • {ip}")
    if len(iocs.get("ips", [])) > 20:
        report_lines.append(f"  ... and {len(iocs.get('ips', [])) - 20} more")
    report_lines.append("")
    
    report_lines.append(f"Domains ({len(iocs.get('domains', []))}):")
    for domain in iocs.get("domains", [])[:20]:
        report_lines.append(f"  • {domain}")
    if len(iocs.get("domains", [])) > 20:
        report_lines.append(f"  ... and {len(iocs.get('domains', [])) - 20} more")
    report_lines.append("")
    
    hashes = iocs.get("hashes", {})
    total_hashes = len(hashes.get("md5", [])) + len(hashes.get("sha1", [])) + len(hashes.get("sha256", []))
    if total_hashes > 0:
        report_lines.append(f"File Hashes ({total_hashes}):")
        for hash_type in ["md5", "sha1", "sha256"]:
            for hash_val in hashes.get(hash_type, [])[:10]:
                report_lines.append(f"  • {hash_type.upper()}: {hash_val}")
        report_lines.append("")
    
    report_lines.append(f"Suspicious Processes ({len(iocs.get('processes', []))}):")
    for process in iocs.get("processes", [])[:15]:
        report_lines.append(f"  • {process}")
    if len(iocs.get("processes", [])) > 15:
        report_lines.append(f"  ... and {len(iocs.get('processes', [])) - 15} more")
    report_lines.append("")
    
    # Top Detections
    report_lines.append("TOP DETECTIONS")
    report_lines.append("-" * 80)
    critical_high = [m for m in matches if m.get("severity") in ["critical", "high"]]
    for match in critical_high[:10]:
        report_lines.append(f"  [{match.get('severity', 'UNKNOWN').upper()}] {match.get('rule_title', 'Unknown')}")
        report_lines.append(f"    Computer: {match.get('computer', 'N/A')}")
        report_lines.append(f"    Time: {match.get('timestamp', 'N/A')}")
        report_lines.append(f"    EventID: {match.get('event_id', 'N/A')}")
        report_lines.append("")
    
    report_lines.append("=" * 80)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 80)
    
    return "\n".join(report_lines)


def export_to_stix(sigma_results: dict[str, Any], iocs: dict[str, Any], project_name: str) -> dict[str, Any]:
    """Export to STIX 2.1 format for threat intelligence sharing."""
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "objects": []
    }
    
    # Create indicator objects for IOCs
    for ip in iocs.get("ips", [])[:50]:
        stix_bundle["objects"].append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--ip-{ip.replace('.', '-')}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Malicious IP: {ip}",
            "description": f"IP address detected in Windows event logs - {project_name}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
        })
    
    for domain in iocs.get("domains", [])[:50]:
        stix_bundle["objects"].append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--domain-{domain.replace('.', '-')}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Suspicious Domain: {domain}",
            "description": f"Domain detected in Windows event logs - {project_name}",
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
        })
    
    hashes = iocs.get("hashes", {})
    for sha256 in hashes.get("sha256", [])[:50]:
        stix_bundle["objects"].append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--hash-{sha256[:16]}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Malicious File Hash",
            "description": f"SHA256 hash detected in Windows event logs - {project_name}",
            "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
        })
    
    return stix_bundle
