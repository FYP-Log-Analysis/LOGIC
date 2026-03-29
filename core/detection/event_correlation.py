"""
Event Correlation Engine for Windows Attack Chain Detection
Identifies related events that may constitute an attack campaign
"""

from typing import Any
from datetime import datetime, timezone, timedelta
from collections import defaultdict


def parse_timestamp(ts: str | None) -> datetime | None:
    """Parse ISO timestamp to datetime."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class EventCorrelator:
    """Correlate Windows events to detect attack chains."""
    
    def __init__(self, time_window_minutes: int = 60):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.correlations = []
    
    def _events_are_related(self, event1: dict[str, Any], event2: dict[str, Any]) -> tuple[bool, list[str]]:
        """Check if two events are potentially related."""
        reasons = []
        
        # Same computer
        if event1.get("computer") and event1.get("computer") == event2.get("computer"):
            reasons.append("same_computer")
        
        # Same user
        if event1.get("auth_user") and event1.get("auth_user") == event2.get("auth_user"):
            reasons.append("same_user")
        
        # Same source IP
        if event1.get("client_ip") and event1.get("client_ip") == event2.get("client_ip"):
            reasons.append("same_source_ip")
        
        # Process lineage (parent-child)
        event1_data = event1.get("event_data", {}) or {}
        event2_data = event2.get("event_data", {}) or {}
        
        if isinstance(event1_data, dict) and isinstance(event2_data, dict):
            # Check if process IDs link
            if event1_data.get("NewProcessId") and event1_data.get("NewProcessId") == event2_data.get("ProcessId"):
                reasons.append("process_parent_child")
            
            # Check if same process
            if event1_data.get("ProcessId") and event1_data.get("ProcessId") == event2_data.get("ProcessId"):
                reasons.append("same_process")
        
        return len(reasons) >= 2, reasons
    
    def _is_within_time_window(self, ts1: datetime, ts2: datetime) -> bool:
        """Check if two timestamps are within the correlation time window."""
        return abs(ts1 - ts2) <= self.time_window
    
    def correlate_matches(self, matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find correlated attack chains from Sigma matches."""
        if len(matches) < 2:
            return []
        
        # Sort by timestamp
        sorted_matches = sorted(
            [m for m in matches if parse_timestamp(m.get("timestamp"))],
            key=lambda m: parse_timestamp(m.get("timestamp"))
        )
        
        chains = []
        used_indices = set()
        
        for i, match1 in enumerate(sorted_matches):
            if i in used_indices:
                continue
            
            ts1 = parse_timestamp(match1.get("timestamp"))
            if not ts1:
                continue
            
            chain = {
                "chain_id": f"chain_{i}",
                "events": [match1],
                "start_time": match1.get("timestamp"),
                "end_time": match1.get("timestamp"),
                "computers": {match1.get("computer")},
                "users": set(),
                "correlation_reasons": [],
                "severity": match1.get("severity", "low"),
            }
            
            if match1.get("auth_user"):
                chain["users"].add(match1.get("auth_user"))
            
            # Find related events
            for j, match2 in enumerate(sorted_matches[i+1:], start=i+1):
                if j in used_indices:
                    continue
                
                ts2 = parse_timestamp(match2.get("timestamp"))
                if not ts2:
                    continue
                
                # Check if within time window
                if not self._is_within_time_window(ts1, ts2):
                    continue
                
                # Check if related
                is_related, reasons = self._events_are_related(match1, match2)
                if is_related:
                    chain["events"].append(match2)
                    chain["end_time"] = match2.get("timestamp")
                    chain["computers"].add(match2.get("computer"))
                    if match2.get("auth_user"):
                        chain["users"].add(match2.get("auth_user"))
                    chain["correlation_reasons"].extend(reasons)
                    used_indices.add(j)
                    
                    # Upgrade severity if necessary
                    sev2 = match2.get("severity", "low")
                    if self._severity_level(sev2) > self._severity_level(chain["severity"]):
                        chain["severity"] = sev2
            
            # Only include chains with 2+ events
            if len(chain["events"]) >= 2:
                chain["computers"] = list(chain["computers"])
                chain["users"] = list(chain["users"])
                chain["correlation_reasons"] = list(set(chain["correlation_reasons"]))
                chain["event_count"] = len(chain["events"])
                chain["duration_seconds"] = (
                    parse_timestamp(chain["end_time"]) - parse_timestamp(chain["start_time"])
                ).total_seconds() if chain["start_time"] and chain["end_time"] else 0
                chains.append(chain)
                used_indices.add(i)
        
        return sorted(chains, key=lambda c: self._severity_level(c["severity"]), reverse=True)
    
    def _severity_level(self, severity: str) -> int:
        """Convert severity to numeric level for comparison."""
        levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return levels.get(str(severity).lower(), 0)


def detect_attack_patterns(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect common attack patterns from correlated events."""
    patterns = []
    
    # Group by computer
    by_computer = defaultdict(list)
    for match in matches:
        computer = match.get("computer")
        if computer:
            by_computer[computer].append(match)
    
    # Check for lateral movement patterns
    for computer, events in by_computer.items():
        rdp_events = [e for e in events if e.get("event_id") in [4624, 4778, 4779]]
        smb_events = [e for e in events if e.get("event_id") in [5140, 5145]]
        
        if len(rdp_events) > 0 and len(smb_events) > 0:
            patterns.append({
                "pattern_type": "lateral_movement",
                "pattern_name": "RDP + SMB Lateral Movement",
                "computer": computer,
                "confidence": "high",
                "event_count": len(rdp_events) + len(smb_events),
                "mitre_technique": "T1021",
                "description": f"Detected {len(rdp_events)} RDP and {len(smb_events)} SMB events on {computer}",
            })
    
    # Check for credential dumping patterns
    for computer, events in by_computer.items():
        lsass_events = [e for e in events if "lsass" in str(e.get("rule_title", "")).lower()]
        credential_events = [e for e in events if "credential" in str(e.get("rule_title", "")).lower()]
        
        if len(lsass_events) > 0 or len(credential_events) > 0:
            patterns.append({
                "pattern_type": "credential_access",
                "pattern_name": "Credential Dumping Activity",
                "computer": computer,
                "confidence": "high",
                "event_count": len(lsass_events) + len(credential_events),
                "mitre_technique": "T1003",
                "description": f"Detected credential access attempts on {computer}",
            })
    
    # Check for PowerShell execution chains
    for computer, events in by_computer.items():
        ps_events = [e for e in events if e.get("event_id") in [4103, 4104] or "powershell" in str(e.get("rule_title", "")).lower()]
        
        if len(ps_events) >= 3:
            patterns.append({
                "pattern_type": "execution",
                "pattern_name": "PowerShell Execution Chain",
                "computer": computer,
                "confidence": "medium",
                "event_count": len(ps_events),
                "mitre_technique": "T1059.001",
                "description": f"Detected {len(ps_events)} PowerShell events in sequence on {computer}",
            })
    
    # Check for audit log tampering
    for computer, events in by_computer.items():
        clear_events = [e for e in events if e.get("event_id") in [1102, 104, 1100]]
        
        if len(clear_events) > 0:
            patterns.append({
                "pattern_type": "defense_evasion",
                "pattern_name": "Audit Log Clearing",
                "computer": computer,
                "confidence": "high",
                "event_count": len(clear_events),
                "mitre_technique": "T1070",
                "description": f"Detected {len(clear_events)} log clearing events on {computer}",
            })
    
    return patterns


def build_attack_timeline(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a unified attack timeline from correlated chains."""
    timeline = []
    
    for chain in chains:
        for event in chain.get("events", []):
            timeline.append({
                "timestamp": event.get("timestamp"),
                "chain_id": chain.get("chain_id"),
                "severity": event.get("severity"),
                "rule_title": event.get("rule_title"),
                "computer": event.get("computer"),
                "event_id": event.get("event_id"),
                "correlation_strength": len(chain.get("correlation_reasons", [])),
            })
    
    return sorted(timeline, key=lambda e: e.get("timestamp", ""))
