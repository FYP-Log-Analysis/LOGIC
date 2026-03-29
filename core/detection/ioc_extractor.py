"""
IOC (Indicators of Compromise) Extraction for Windows Events
Extracts IPs, domains, hashes, file paths, and user accounts from Windows event logs
"""

import re
from typing import Any
from collections import defaultdict

# Regex patterns for IOC extraction
IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
WINDOWS_PATH_PATTERN = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
USER_PATTERN = re.compile(r'(?:DOMAIN|NT AUTHORITY|WORKGROUP)\\[a-zA-Z0-9_\-\.]+', re.IGNORECASE)

# Known benign IPs to filter out
BENIGN_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::",
}

# Common benign domains to filter
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com",
    "localhost", "local", "localdomain",
}

# Critical file extensions for forensics
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".scr", ".pif",
}


class IOCExtractor:
    """Extract Indicators of Compromise from Windows events."""
    
    def __init__(self):
        self.iocs = {
            "ips": set(),
            "domains": set(),
            "hashes": {"md5": set(), "sha1": set(), "sha256": set()},
            "file_paths": set(),
            "users": set(),
            "processes": set(),
        }
        self.ioc_contexts = defaultdict(list)
    
    def _extract_from_text(self, text: str, event_context: dict[str, Any]) -> None:
        """Extract IOCs from text content."""
        if not text or not isinstance(text, str):
            return
        
        # Extract IPs
        for ip in IP_PATTERN.findall(text):
            if ip not in BENIGN_IPS:
                self.iocs["ips"].add(ip)
                self.ioc_contexts[f"ip:{ip}"].append(event_context)
        
        # Extract domains
        for domain in DOMAIN_PATTERN.findall(text):
            domain_lower = domain.lower()
            if domain_lower not in BENIGN_DOMAINS and not domain_lower.endswith('.local'):
                self.iocs["domains"].add(domain)
                self.ioc_contexts[f"domain:{domain}"].append(event_context)
        
        # Extract hashes
        for md5 in MD5_PATTERN.findall(text):
            self.iocs["hashes"]["md5"].add(md5.lower())
            self.ioc_contexts[f"hash:md5:{md5.lower()}"].append(event_context)
        
        for sha1 in SHA1_PATTERN.findall(text):
            self.iocs["hashes"]["sha1"].add(sha1.lower())
            self.ioc_contexts[f"hash:sha1:{sha1.lower()}"].append(event_context)
        
        for sha256 in SHA256_PATTERN.findall(text):
            self.iocs["hashes"]["sha256"].add(sha256.lower())
            self.ioc_contexts[f"hash:sha256:{sha256.lower()}"].append(event_context)
        
        # Extract Windows file paths
        for path in WINDOWS_PATH_PATTERN.findall(text):
            if any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                self.iocs["file_paths"].add(path)
                self.ioc_contexts[f"file:{path}"].append(event_context)
        
        # Extract users
        for user in USER_PATTERN.findall(text):
            self.iocs["users"].add(user)
            self.ioc_contexts[f"user:{user}"].append(event_context)
    
    def extract_from_event(self, event: dict[str, Any]) -> None:
        """Extract IOCs from a single Windows event."""
        event_context = {
            "event_id": event.get("event_id"),
            "computer": event.get("computer"),
            "timestamp": event.get("timestamp"),
            "channel": event.get("channel"),
        }
        
        # Extract from main fields
        if event.get("client_ip"):
            ip = str(event["client_ip"])
            if ip not in BENIGN_IPS:
                self.iocs["ips"].add(ip)
                self.ioc_contexts[f"ip:{ip}"].append(event_context)
        
        if event.get("auth_user"):
            user = str(event["auth_user"])
            self.iocs["users"].add(user)
            self.ioc_contexts[f"user:{user}"].append(event_context)
        
        # Extract from event_data
        event_data = event.get("event_data", {})
        if isinstance(event_data, dict):
            # Process creation events (4688, 1)
            if event.get("event_id") in [4688, 1]:
                if "NewProcessName" in event_data:
                    process_path = str(event_data["NewProcessName"])
                    self.iocs["processes"].add(process_path)
                    self.ioc_contexts[f"process:{process_path}"].append(event_context)
                    self._extract_from_text(process_path, event_context)
                
                if "CommandLine" in event_data:
                    self._extract_from_text(str(event_data["CommandLine"]), event_context)
            
            # Network connections (3, 22 - Sysmon)
            if event.get("event_id") in [3, 22]:
                if "DestinationIp" in event_data:
                    ip = str(event_data["DestinationIp"])
                    if ip not in BENIGN_IPS:
                        self.iocs["ips"].add(ip)
                        self.ioc_contexts[f"ip:{ip}"].append(event_context)
                
                if "QueryName" in event_data:
                    domain = str(event_data["QueryName"])
                    if domain.lower() not in BENIGN_DOMAINS:
                        self.iocs["domains"].add(domain)
                        self.ioc_contexts[f"domain:{domain}"].append(event_context)
            
            # File hash events (Sysmon)
            if "Hashes" in event_data:
                self._extract_from_text(str(event_data["Hashes"]), event_context)
            
            # Extract from all string fields
            for key, value in event_data.items():
                if isinstance(value, str):
                    self._extract_from_text(value, event_context)
        elif isinstance(event_data, str):
            self._extract_from_text(event_data, event_context)
    
    def extract_from_events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Extract IOCs from multiple Windows events."""
        for event in events:
            self.extract_from_event(event)
        
        return {
            "ips": sorted(list(self.iocs["ips"])),
            "domains": sorted(list(self.iocs["domains"])),
            "hashes": {
                "md5": sorted(list(self.iocs["hashes"]["md5"])),
                "sha1": sorted(list(self.iocs["hashes"]["sha1"])),
                "sha256": sorted(list(self.iocs["hashes"]["sha256"])),
            },
            "file_paths": sorted(list(self.iocs["file_paths"])),
            "users": sorted(list(self.iocs["users"])),
            "processes": sorted(list(self.iocs["processes"])),
            "total_iocs": (
                len(self.iocs["ips"]) +
                len(self.iocs["domains"]) +
                len(self.iocs["hashes"]["md5"]) +
                len(self.iocs["hashes"]["sha1"]) +
                len(self.iocs["hashes"]["sha256"]) +
                len(self.iocs["file_paths"]) +
                len(self.iocs["users"]) +
                len(self.iocs["processes"])
            ),
        }
    
    def get_ioc_context(self, ioc_type: str, ioc_value: str) -> list[dict[str, Any]]:
        """Get context (events) where an IOC was found."""
        key = f"{ioc_type}:{ioc_value}"
        return self.ioc_contexts.get(key, [])


def extract_iocs_from_sigma_matches(matches: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract IOCs from Sigma rule matches."""
    extractor = IOCExtractor()
    
    for match in matches:
        event = match.get("entry", {})
        if event:
            extractor.extract_from_event(event)
    
    return extractor.extract_from_events([])
