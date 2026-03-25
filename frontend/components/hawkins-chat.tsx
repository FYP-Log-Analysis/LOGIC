"use client";

import { useState, useRef, useEffect } from "react";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface HawkinsChatProps {
  title: string;
  description?: string;
  dataSummary?: string | Record<string, unknown>;
  componentKey: string;
  helpGuide?: string;
}

function buildContext(props: HawkinsChatProps): string {
  const lines = [
    `COMPONENT: ${props.title}`,
    `DESCRIPTION: ${props.description ?? ""}`,
  ];
  if (props.dataSummary) {
    try {
      const ds = props.dataSummary;
      lines.push(`DATA_SUMMARY:\n${typeof ds === "string" ? ds : JSON.stringify(ds, null, 2)}`);
    } catch {}
  }
  if (props.helpGuide) {
    lines.push(`HOW_TO_USE:\n${props.helpGuide}`);
  }
  return lines.join("\n\n");
}

export default function HawkinsChat(props: HawkinsChatProps) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, open]);

  const sendMessage = async () => {
    if (!input.trim() || streaming) return;
    const userMsg: Message = { role: "user", content: input.trim() };
    const newHistory = [...messages, userMsg];
    setMessages(newHistory);
    setInput("");
    setStreaming(true);

    const context = buildContext(props);
    let responseText = "";

    try {
      const res = await fetch("/api/proxy/api/analysis/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          context,
          messages: newHistory,
          component_key: props.componentKey,
        }),
      });

      if (!res.ok || !res.body) {
        const errData = await res.json().catch(() => ({ error: "Request failed" }));
        setMessages([...newHistory, { role: "assistant", content: `**Error:** ${errData.error ?? "Request failed"}` }]);
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      setMessages([...newHistory, { role: "assistant", content: "" }]);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        responseText += decoder.decode(value, { stream: true });
        setMessages([...newHistory, { role: "assistant", content: responseText }]);
      }
    } catch (err) {
      setMessages([...newHistory, { role: "assistant", content: `**Error:** ${String(err)}` }]);
    } finally {
      setStreaming(false);
    }
  };

  return (
    <>
      {/* Inject spin animation */}
      <style>{`
        @keyframes hawkins-spin { to { transform: rotate(360deg); } }
      `}</style>

      {/* Floating button */}
      <button
        onClick={() => setOpen((o) => !o)}
        title="Hawkins AI Analyst"
        style={{
          position: "fixed", bottom: 24, right: 24,
          width: 52, height: 52, borderRadius: "50%",
          background: "#4c1d95", border: "2px solid #7c3aed",
          color: "#e9d5ff", fontSize: 22, cursor: "pointer",
          display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: "0 4px 20px rgba(109,40,217,0.45)",
          zIndex: 99998, transition: "background 0.2s",
        }}
        onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "#6d28d9"; }}
        onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "#4c1d95"; }}
      >
        ✦
      </button>

      {/* Chat panel */}
      {open && (
        <div style={{
          position: "fixed", bottom: 88, right: 24,
          width: 400, maxHeight: 540,
          background: "#080808", border: "1px solid #2d1b69",
          borderRadius: 10,
          boxShadow: "0 8px 40px rgba(109,40,217,0.30), 0 2px 12px rgba(0,0,0,0.85)",
          display: "flex", flexDirection: "column",
          overflow: "hidden", zIndex: 99997,
          fontFamily: "'SF Mono','Fira Code','Consolas',monospace",
        }}>
          {/* Header */}
          <div style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "14px 16px 12px", borderBottom: "1px solid #2d1b69",
          }}>
            <span style={{
              background: "rgba(109,40,217,0.15)", border: "1px solid #4c1d95",
              color: "#a78bfa", fontSize: 10, letterSpacing: 2, padding: "3px 9px",
              borderRadius: 12,
            }}>HAWKINS</span>
            <span style={{ color: "#e0e0e0", fontSize: 13, fontWeight: 300, letterSpacing: 1 }}>
              {props.title}
            </span>
            <button
              onClick={() => setOpen(false)}
              style={{ marginLeft: "auto", background: "none", border: "none", color: "#555", cursor: "pointer", fontSize: 16 }}
            >×</button>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: "auto", padding: "12px 14px" }}>
            {messages.length === 0 && (
              <div style={{ color: "#333", fontSize: 11, textAlign: "center", paddingTop: 20 }}>
                Ask about this data, patterns, threats, or how to use this view…
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} style={{
                marginBottom: 10,
                padding: "8px 12px",
                borderRadius: "0 4px 4px 0",
                borderLeft: `3px solid ${m.role === "user" ? "#7c3aed" : "#2a2a2a"}`,
                background: m.role === "user" ? "rgba(109,40,217,0.09)" : "#0d0d0d",
                fontSize: 12,
                color: "#c0c0c0",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}>
                {m.content}
                {m.role === "assistant" && streaming && i === messages.length - 1 && (
                  <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", border: "2px solid #555", borderTop: "2px solid #808080", animation: "hawkins-spin 0.7s linear infinite", marginLeft: 6, verticalAlign: "middle" }} />
                )}
              </div>
            ))}
            <div ref={bottomRef} />
          </div>

          {/* Clear button */}
          {messages.length > 0 && (
            <div style={{ padding: "4px 14px 0" }}>
              <button
                onClick={() => setMessages([])}
                style={{ background: "none", border: "none", color: "#333", cursor: "pointer", fontSize: 10, letterSpacing: 1 }}
              >
                CLEAR CONVERSATION
              </button>
            </div>
          )}

          {/* Input */}
          <div style={{ padding: "10px 14px 14px", display: "flex", gap: 8 }}>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
              placeholder="Ask Hawkins…"
              rows={2}
              style={{
                flex: 1, background: "#0d0d0d", border: "1px solid #2d1b69",
                borderRadius: 4, color: "#c0c0c0", fontFamily: "inherit", fontSize: 12,
                padding: "7px 10px", resize: "none", outline: "none",
              }}
            />
            <button
              onClick={sendMessage}
              disabled={streaming || !input.trim()}
              style={{
                background: "#4c1d95", border: "1px solid #7c3aed", color: "#c4b5fd",
                borderRadius: 4, padding: "0 14px", cursor: streaming ? "not-allowed" : "pointer",
                fontSize: 11, fontFamily: "inherit", opacity: streaming ? 0.6 : 1,
              }}
            >
              ↑
            </button>
          </div>
        </div>
      )}
    </>
  );
}
