"""
MITRE ATT&CK Technique Mapping for Windows Events and Sigma Rules
Maps event patterns to MITRE ATT&CK techniques for digital forensics analysis
"""

from typing import Any

# MITRE ATT&CK Technique Mappings
MITRE_MAPPINGS = {
    # Credential Access
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["mimikatz", "lsass", "credential", "dump", "password"],
        "event_ids": [4656, 4663, 4658],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "keywords": ["failed", "logon", "brute", "password"],
        "event_ids": [4625, 4771, 4776],
    },
    
    # Persistence
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "keywords": ["service", "create", "modify", "sc.exe"],
        "event_ids": [7045, 4697],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "keywords": ["registry", "run", "startup", "autostart"],
        "event_ids": [4657, 13],
    },
    
    # Privilege Escalation
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "keywords": ["exploit", "elevation", "privilege", "uac"],
        "event_ids": [4688, 4624],
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "keywords": ["token", "impersonate", "duplicate"],
        "event_ids": [4672, 4673],
    },
    
    # Defense Evasion
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "keywords": ["clear", "delete", "remove", "event", "log"],
        "event_ids": [1102, 104, 1100],
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "keywords": ["disable", "defender", "firewall", "antivirus"],
        "event_ids": [7036, 5025, 5034],
    },
    
    # Lateral Movement
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "keywords": ["rdp", "remote", "desktop", "3389"],
        "event_ids": [4624, 4778, 4779],
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "keywords": ["smb", "admin$", "c$", "ipc$", "share"],
        "event_ids": [5140, 5145, 4776],
    },
    
    # Execution
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "keywords": ["powershell", "ps1", "scriptblock"],
        "event_ids": [4103, 4104, 4688],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "keywords": ["cmd.exe", "command", "shell"],
        "event_ids": [4688, 1],
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "keywords": ["wmi", "wmiprvse", "wmic"],
        "event_ids": [4688, 1],
    },
    
    # Discovery
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "keywords": ["net user", "net group", "whoami", "query user"],
        "event_ids": [4688, 4798, 4799],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "keywords": ["systeminfo", "hostname", "ipconfig"],
        "event_ids": [4688],
    },
    
    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "keywords": ["copy", "xcopy", "robocopy", "file access"],
        "event_ids": [4663, 4656],
    },
    
    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "keywords": ["http", "https", "dns", "c2"],
        "event_ids": [3, 22],
    },
    
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": ["ransom", "encrypt", "crypto"],
        "event_ids": [4663, 4656],
    },
}


def extract_mitre_from_tags(tags: list[str]) -> list[dict[str, str]]:
    """Extract MITRE ATT&CK techniques from Sigma rule tags."""
    techniques = []
    for tag in tags:
        tag_lower = str(tag).lower()
        if tag_lower.startswith("attack.t"):
            technique_id = tag.upper().replace("ATTACK.", "")
            if technique_id in MITRE_MAPPINGS:
                mapping = MITRE_MAPPINGS[technique_id]
                techniques.append({
                    "technique_id": technique_id,
                    "name": mapping["name"],
                    "tactic": mapping["tactic"],
                })
    return techniques


def infer_mitre_from_event(event: dict[str, Any]) -> list[dict[str, str]]:
    """Infer MITRE ATT&CK techniques from Windows event content."""
    techniques = []
    event_id = event.get("event_id")
    
    # Create searchable content
    event_data = event.get("event_data", {})
    searchable_text = " ".join([
        str(event.get("channel", "")),
        str(event_data) if isinstance(event_data, str) else json.dumps(event_data),
    ]).lower()
    
    for technique_id, mapping in MITRE_MAPPINGS.items():
        # Check if event ID matches
        if event_id in mapping["event_ids"]:
            # Also check for keywords
            if any(keyword in searchable_text for keyword in mapping["keywords"]):
                techniques.append({
                    "technique_id": technique_id,
                    "name": mapping["name"],
                    "tactic": mapping["tactic"],
                })
    
    return techniques


def enrich_sigma_match_with_mitre(match: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    """Enrich a Sigma match with MITRE ATT&CK technique information."""
    # Extract from rule tags first
    techniques = extract_mitre_from_tags(rule.get("tags", []))
    
    # If no techniques from tags, try to infer from event
    if not techniques:
        event = match.get("entry", {})
        techniques = infer_mitre_from_event(event)
    
    # Add to match
    if techniques:
        match["mitre_techniques"] = techniques
        match["mitre_tactics"] = list(set(t["tactic"] for t in techniques))
    
    return match


def get_mitre_technique_info(technique_id: str) -> dict[str, str] | None:
    """Get information about a specific MITRE ATT&CK technique."""
    return MITRE_MAPPINGS.get(technique_id)


def get_all_techniques() -> list[dict[str, Any]]:
    """Get all MITRE ATT&CK techniques in the mapping."""
    return [
        {
            "technique_id": tid,
            "name": data["name"],
            "tactic": data["tactic"],
            "event_ids": data["event_ids"],
        }
        for tid, data in MITRE_MAPPINGS.items()
    ]


import json
