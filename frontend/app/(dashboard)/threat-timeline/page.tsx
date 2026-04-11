"use client";

import { useEffect, useMemo, useState } from "react";
import { getRuleMatches } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { SectionHeader, Btn, SearchInput, SelectInput, Spinner } from "@/components/ui-primitives";
import { EventDetailModal } from "@/components/event-detail-modal";
import { WindowsEventTable } from "@/components/windows-ui";
import type { ThreatEvent } from "@/components/threat-timeline";

interface RuleMatch {
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  client_ip?: string;
  method?: string;
  path?: string;
  status_code?: number | string;
  timestamp?: string;
}

type SortDirection = "asc" | "desc";
type SortKey = "timestamp" | "severity" | "type" | "title" | "source";

const severityColors: Record<ThreatEvent["severity"], string> = {
  critical: "#ff4444",
  warning: "#f0c040",
  info: "#4488ff",
};

const severityRank: Record<ThreatEvent["severity"], number> = {
  critical: 3,
  warning: 2,
  info: 1,
};

function toTimelineEvent(match: RuleMatch): ThreatEvent {
  const sev = (match.severity ?? "low").toLowerCase();
  const severity: ThreatEvent["severity"] =
    sev === "critical" || sev === "high"
      ? "critical"
      : sev === "medium"
        ? "warning"
        : "info";

  return {
    timestamp: match.timestamp || new Date().toISOString(),
    severity,
    type: "detection",
    title: match.rule_title || match.rule_id || "Rule match",
    details: `${match.client_ip || "unknown ip"} | ${match.method || "-"} ${match.path || "-"} | status ${match.status_code || "-"}`,
    source: "rule-detection",
    payload: match,
  };
}

export default function ThreatTimelinePage() {
  const [matches, setMatches] = useState<RuleMatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshTick, setRefreshTick] = useState(0);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selectedEvent, setSelectedEvent] = useState<ThreatEvent | null>(null);
  const { activeProject, timeRange } = useAuthStore();

  useEffect(() => {
    let cancelled = false;

    (async () => {
      if (!activeProject?.id) {
        if (!cancelled) {
          setMatches([]);
          setLoading(false);
        }
        return;
      }

      if (!cancelled) setLoading(true);

      try {
        const result = await getRuleMatches({
          projectId: activeProject.id,
          startTs: timeRange?.from,
          endTs: timeRange?.to,
        });
        if (!cancelled) setMatches(result.matches as RuleMatch[]);
      } catch {
        if (!cancelled) setMatches([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [activeProject?.id, timeRange?.from, timeRange?.to, refreshTick]);

  const timelineEvents = useMemo(() => {
    return matches.map(toTimelineEvent);
  }, [matches]);

  const eventTypes = useMemo(() => {
    return [...new Set(timelineEvents.map((event) => event.type))].sort();
  }, [timelineEvents]);

  const filteredEvents = useMemo(() => {
    return timelineEvents.filter((event) => {
      if (severityFilter && event.severity !== severityFilter) return false;
      if (typeFilter && event.type !== typeFilter) return false;
      if (search) {
        const query = search.toLowerCase();
        const haystack = [event.title, event.details, event.source, event.type]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });
  }, [timelineEvents, severityFilter, typeFilter, search]);

  const sortedEvents = useMemo(() => {
    const clone = [...filteredEvents];
    clone.sort((a, b) => {
      let compare = 0;

      if (sortKey === "timestamp") {
        compare = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      } else if (sortKey === "severity") {
        compare = severityRank[a.severity] - severityRank[b.severity];
      } else if (sortKey === "type") {
        compare = a.type.localeCompare(b.type);
      } else if (sortKey === "title") {
        compare = a.title.localeCompare(b.title);
      } else if (sortKey === "source") {
        compare = (a.source || "").localeCompare(b.source || "");
      }

      return sortDirection === "asc" ? compare : -compare;
    });
    return clone;
  }, [filteredEvents, sortKey, sortDirection]);

  const tableRows = useMemo(() => {
    return sortedEvents.slice(0, 500).map((event, index) => ({
      id: `${event.timestamp}_${event.type}_${index}`,
      event,
    }));
  }, [sortedEvents]);

  if (!activeProject?.id) {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#555" }}>
        Select a project from the sidebar to view this page.
      </div>
    );
  }

  if (activeProject.project_type === "windows") {
    return (
      <div style={{ textAlign: "center", padding: 60, color: "#ff6b6b" }}>
        <h2 style={{ margin: 0, color: "#ff6b6b" }}>Web Projects Only</h2>
        <p style={{ color: "#999", marginTop: 12 }}>
          Threat timeline is available for web projects.
        </p>
      </div>
    );
  }

  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: 60 }}>
        <Spinner size={28} />
      </div>
    );
  }

  return (
    <div>
      <SectionHeader
        title="Threat Timeline"
        subtitle="Chronological web threat events rendered in a table layout for fast triage"
      />

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <SearchInput value={search} onChange={setSearch} placeholder="Search title, details, source..." />
        <SelectInput
          value={severityFilter}
          onChange={setSeverityFilter}
          options={[
            { value: "", label: "All Severities" },
            { value: "critical", label: "CRITICAL" },
            { value: "warning", label: "WARNING" },
            { value: "info", label: "INFO" },
          ]}
        />
        <SelectInput
          value={typeFilter}
          onChange={setTypeFilter}
          options={[
            { value: "", label: "All Types" },
            ...eventTypes.map((type) => ({ value: type, label: type.toUpperCase() })),
          ]}
        />
        <div style={{ fontSize: 11, color: "#444", whiteSpace: "nowrap" }}>
          {filteredEvents.length.toLocaleString()} / {timelineEvents.length.toLocaleString()}
        </div>
        <Btn onClick={() => setRefreshTick((prev) => prev + 1)} style={{ marginLeft: "auto" }}>
          Refresh
        </Btn>
      </div>

      <WindowsEventTable
        density="compact"
        maxHeight={620}
        stickyHeader
        emptyMessage="No threat events found for the current filters"
        rowKey={(row) => String(row.id ?? "")}
        data={tableRows as Array<Record<string, unknown>>}
        onRowClick={(row) => {
          const event = row.event as ThreatEvent | undefined;
          if (event) setSelectedEvent(event);
        }}
        sortKey={sortKey}
        sortDirection={sortDirection}
        onSortChange={(key, direction) => {
          setSortKey(key as SortKey);
          setSortDirection(direction);
        }}
        columns={[
          {
            key: "timestamp",
            label: "Time",
            width: "190px",
            sortable: true,
            render: (row) => {
              const event = row.event as ThreatEvent;
              return <span style={{ color: "#777", whiteSpace: "nowrap", fontSize: 11 }}>{new Date(event.timestamp).toLocaleString()}</span>;
            },
          },
          {
            key: "severity",
            label: "Severity",
            width: "96px",
            sortable: true,
            render: (row) => {
              const event = row.event as ThreatEvent;
              return (
                <span style={{ color: severityColors[event.severity], fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>
                  {event.severity}
                </span>
              );
            },
          },
          {
            key: "type",
            label: "Type",
            width: "90px",
            sortable: true,
            render: (row) => {
              const event = row.event as ThreatEvent;
              return <span style={{ color: "#888", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>{event.type}</span>;
            },
          },
          {
            key: "title",
            label: "Title",
            width: "260px",
            sortable: true,
            render: (row) => {
              const event = row.event as ThreatEvent;
              return (
                <div
                  style={{ color: "#c0c0c0", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={event.title}
                >
                  {event.title}
                </div>
              );
            },
          },
          {
            key: "details",
            label: "Details",
            width: "340px",
            render: (row) => {
              const event = row.event as ThreatEvent;
              const value = event.details || "-";
              return (
                <div
                  style={{ color: "#666", maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={value}
                >
                  {value}
                </div>
              );
            },
          },
          {
            key: "source",
            label: "Source",
            width: "140px",
            sortable: true,
            render: (row) => {
              const event = row.event as ThreatEvent;
              return <span style={{ color: "#555", fontSize: 10, textTransform: "uppercase" }}>{event.source || "-"}</span>;
            },
          },
        ]}
      />

      {sortedEvents.length > 500 && (
        <div style={{ color: "#444", fontSize: 11, marginTop: 6, textAlign: "center" }}>
          Showing 500 of {sortedEvents.length.toLocaleString()} events. Refine filters to narrow results.
        </div>
      )}

      {selectedEvent && (
        <EventDetailModal
          title={selectedEvent.title}
          subtitle={`${selectedEvent.severity.toUpperCase()} | ${selectedEvent.type.toUpperCase()} | ${new Date(selectedEvent.timestamp).toLocaleString()}`}
          payload={selectedEvent.payload ?? selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}
