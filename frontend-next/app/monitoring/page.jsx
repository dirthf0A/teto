"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson, API_BASE } from "../_lib/api";

const CHANGE_ICONS = {
  new_subdomain:       { icon: "🌐", label: "New Subdomain",    color: "#38bdf8" },
  asset_discovered:    { icon: "🔍", label: "Asset Discovered", color: "#a78bfa" },
  port_exposed:        { icon: "🔓", label: "Port Opened",      color: "#fb923c" },
  endpoint_discovered: { icon: "🔗", label: "Endpoint Found",   color: "#22d3ee" },
  vuln_discovered:     { icon: "🐛", label: "Vuln Found",       color: "#f87171" },
  vuln_fixed:          { icon: "✅", label: "Vuln Fixed",       color: "#22c55e" },
};

function ScanStatusDot({ status }) {
  const colors = {
    completed: "#22c55e",
    running:   "#38bdf8",
    failed:    "#f87171",
    scheduled: "#94a3b8",
  };
  return (
    <span style={{
      display: "inline-block", width: 8, height: 8, borderRadius: "50%",
      background: colors[status] || "#64748b",
      boxShadow: status === "running" ? `0 0 6px ${colors.running}` : "none",
      marginRight: 6,
    }} />
  );
}

function LastScanRow({ type, ts }) {
  const typeLabels = { asset_discovery: "Asset Discovery", vuln: "Vulnerability Scan", deep: "Deep Scan" };
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "10px 0", borderBottom: "1px solid rgba(148,163,184,0.1)",
    }}>
      <span style={{ fontWeight: 500, fontSize: "0.9rem" }}>{typeLabels[type] || type}</span>
      <span style={{ fontSize: "0.82rem", color: ts ? "#94a3b8" : "#475569" }}>
        {ts ? new Date(ts).toLocaleString() : "Never"}
      </span>
    </div>
  );
}

function ChangeEventRow({ change }) {
  const meta = CHANGE_ICONS[change.type] || { icon: "📌", label: change.type, color: "#94a3b8" };
  return (
    <div style={{
      display: "flex", gap: 12, alignItems: "flex-start", padding: "8px 0",
      borderBottom: "1px solid rgba(148,163,184,0.08)",
    }}>
      <span style={{ fontSize: "1rem", flexShrink: 0 }}>{meta.icon}</span>
      <div style={{ flex: 1 }}>
        <span style={{ fontSize: "0.83rem", fontWeight: 500, color: meta.color }}>{meta.label}</span>
        {change.detail && (
          <div style={{ fontSize: "0.78rem", fontFamily: "monospace", color: "#64748b", marginTop: 2, wordBreak: "break-all" }}>
            {change.detail}
          </div>
        )}
      </div>
      <span style={{ fontSize: "0.72rem", color: "#475569", whiteSpace: "nowrap", flexShrink: 0 }}>
        {change.at ? new Date(change.at).toLocaleDateString() : ""}
      </span>
    </div>
  );
}

function QueueBar({ depth }) {
  if (!depth) return null;
  const bars = [
    { label: "Critical", value: depth.critical || 0, color: "#ef4444" },
    { label: "High",     value: depth.high     || 0, color: "#f97316" },
    { label: "Normal",   value: depth.normal   || 0, color: "#38bdf8" },
    { label: "Low",      value: depth.low      || 0, color: "#22c55e" },
  ];
  const maxVal = Math.max(...bars.map((b) => b.value), 1);
  return (
    <div style={{ marginTop: 8 }}>
      {bars.map((b) => (
        <div key={b.label} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{ width: 60, fontSize: "0.78rem", color: "#94a3b8" }}>{b.label}</span>
          <div style={{ flex: 1, height: 8, borderRadius: 999, background: "rgba(148,163,184,0.15)", overflow: "hidden" }}>
            <div style={{
              height: "100%", borderRadius: 999,
              width: `${(b.value / maxVal) * 100}%`,
              background: b.color, transition: "width 0.5s ease",
            }} />
          </div>
          <span style={{ width: 28, fontSize: "0.82rem", textAlign: "right", color: b.color, fontWeight: 600 }}>{b.value}</span>
        </div>
      ))}
      <div style={{ display: "flex", gap: 16, marginTop: 12, paddingTop: 10, borderTop: "1px solid rgba(148,163,184,0.1)" }}>
        {[
          { label: "In-flight", value: depth.inflight || 0, color: "#38bdf8" },
          { label: "Retrying",  value: depth.pending_retry || 0, color: "#fb923c" },
          { label: "DLQ",       value: depth.dlq || 0, color: "#f87171" },
        ].map((s) => (
          <div key={s.label} style={{ textAlign: "center" }}>
            <div style={{ fontSize: "1.2rem", fontWeight: 700, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: "0.72rem", color: "#475569" }}>{s.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function MonitoringPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState(null);
  const [riskData, setRiskData] = useState(null);
  const [queueDepth, setQueueDepth] = useState(null);
  const [savedToken, setSavedToken] = useState("");
  const [triggerLoading, setTriggerLoading] = useState(false);
  const [triggerMsg, setTriggerMsg] = useState("");

  const loadData = useCallback(async (tok) => {
    if (!tok) return;
    setSavedToken(tok);
    setLoading(true);
    setError("");
    try {
      const [monStatus, risk] = await Promise.all([
        fetchJson("/dashboard/monitoring", tok),
        fetchJson("/dashboard/risk-aggregate", tok).catch(() => null),
      ]);
      setStatus(monStatus);
      setRiskData(risk);

      // Queue depth (admin-only, may fail silently)
      fetchJson("/queue/status", tok)
        .then((d) => setQueueDepth(d))
        .catch(() => setQueueDepth(null));
    } catch (err) {
      setError(err.message || "Failed to load monitoring data");
    } finally {
      setLoading(false);
    }
  }, []);

  const triggerScan = async (scanType) => {
    if (!savedToken) return;
    setTriggerLoading(true);
    setTriggerMsg("");
    try {
      const res = await fetch(`${API_BASE}/scans`, {
        method: "POST",
        headers: { Authorization: `Bearer ${savedToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ scan_type: scanType }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setTriggerMsg(`✓ ${scanType} scan queued (ID: ${data.id})`);
      // Refresh status after short delay
      setTimeout(() => loadData(savedToken), 1500);
    } catch (err) {
      setTriggerMsg(`✗ ${err.message}`);
    } finally {
      setTriggerLoading(false);
    }
  };

  const riskLabel = riskData?.label || "unknown";
  const riskScore = riskData?.overall_score ?? null;
  const riskColor = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" }[riskLabel] || "#94a3b8";

  const distribution = riskData?.risk_distribution || {};
  const distTotal = Object.values(distribution).reduce((a, b) => a + b, 0) || 1;

  const nextScan = status?.next_scan;
  const recentChanges = status?.recent_changes_7d || [];
  const totalAssets = status?.total_assets || 0;

  return (
    <>
      <section className="hero">
        <h1>Continuous Monitoring</h1>
        <p>Real-time scan status, change detection, alert health, and queue depth.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Top stats */}
      <div className="grid" style={{ marginBottom: 20 }}>
        <div className="panel">
          <h3>Total Assets</h3>
          <div className="value" style={{ color: "#38bdf8" }}>{totalAssets.toLocaleString()}</div>
        </div>
        <div className="panel">
          <h3>Risk Score</h3>
          <div className="value" style={{ color: riskColor }}>
            {riskScore !== null ? riskScore : "—"}
          </div>
          {riskLabel !== "unknown" && (
            <span className="badge" style={{ marginTop: 6, background: `${riskColor}22`, color: riskColor }}>
              {riskLabel.toUpperCase()}
            </span>
          )}
        </div>
        <div className="panel">
          <h3>Changes (7d)</h3>
          <div className="value" style={{ color: "#a78bfa" }}>{recentChanges.length}</div>
        </div>
        <div className="panel">
          <h3>Next Scan</h3>
          <div style={{ fontSize: "0.9rem", fontWeight: 600, marginTop: 4 }}>
            {nextScan?.type ? (
              <>
                <span style={{ color: "#38bdf8" }}>{nextScan.type}</span>
                {nextScan.scheduled_at && (
                  <div style={{ fontSize: "0.75rem", color: "#64748b", marginTop: 4 }}>
                    {new Date(nextScan.scheduled_at).toLocaleString()}
                  </div>
                )}
              </>
            ) : (
              <span style={{ color: "#475569" }}>None scheduled</span>
            )}
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
        {/* Last scan times */}
        <div className="panel">
          <h3 style={{ marginTop: 0, marginBottom: 16 }}>Last Scan Times</h3>
          {status?.last_scans ? (
            Object.entries(status.last_scans).map(([type, ts]) => (
              <LastScanRow key={type} type={type} ts={ts} />
            ))
          ) : (
            <div className="empty">No scan history yet.</div>
          )}
        </div>

        {/* Risk distribution */}
        <div className="panel">
          <h3 style={{ marginTop: 0, marginBottom: 16 }}>Risk Distribution</h3>
          {["critical", "high", "medium", "low"].map((sev) => {
            const count = distribution[sev] || 0;
            const pct = Math.round((count / distTotal) * 100);
            const sevColor = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" }[sev];
            return (
              <div key={sev} style={{ marginBottom: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, fontSize: "0.82rem" }}>
                  <span style={{ color: sevColor, fontWeight: 500, textTransform: "capitalize" }}>{sev}</span>
                  <span style={{ color: "#475569" }}>{count}</span>
                </div>
                <div style={{ height: 8, borderRadius: 999, background: "rgba(148,163,184,0.15)", overflow: "hidden" }}>
                  <div style={{
                    height: "100%", borderRadius: 999, width: `${pct}%`,
                    background: sevColor, transition: "width 0.6s ease",
                  }} />
                </div>
              </div>
            );
          })}

          {riskData && (
            <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid rgba(148,163,184,0.1)", display: "flex", gap: 20 }}>
              <div>
                <div style={{ fontSize: "0.72rem", color: "#475569" }}>Asset Risk</div>
                <div style={{ fontWeight: 600, color: "#38bdf8" }}>{riskData.asset_risk}</div>
              </div>
              <div>
                <div style={{ fontSize: "0.72rem", color: "#475569" }}>Finding Risk</div>
                <div style={{ fontWeight: 600, color: "#f87171" }}>{riskData.finding_risk}</div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Recent changes */}
        <div className="panel" style={{ maxHeight: 420, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <h3 style={{ marginTop: 0, marginBottom: 12 }}>Recent Changes (7d)</h3>
          <div style={{ overflowY: "auto", flex: 1 }}>
            {recentChanges.length === 0 ? (
              <div className="empty">No changes in the last 7 days.</div>
            ) : (
              recentChanges.map((c, i) => <ChangeEventRow key={i} change={c} />)
            )}
          </div>
        </div>

        {/* Manual scan triggers + queue */}
        <div className="panel">
          <h3 style={{ marginTop: 0, marginBottom: 16 }}>Manual Scan Triggers</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 20 }}>
            {[
              { type: "asset_discovery", label: "Asset Discovery", color: "#38bdf8", desc: "Subdomain, IP, cloud assets" },
              { type: "vuln",            label: "Vulnerability Scan", color: "#f87171", desc: "Nuclei templates, CVE matching" },
              { type: "service",         label: "Service Scan",    color: "#fb923c", desc: "httpx + naabu port scan" },
              { type: "misconfig",       label: "Misconfig Scan",  color: "#a78bfa", desc: "Cloud & web misconfigs" },
            ].map((s) => (
              <div key={s.type} style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "10px 14px", borderRadius: 10, background: "rgba(30,41,59,0.6)",
                border: "1px solid rgba(148,163,184,0.15)",
              }}>
                <div>
                  <div style={{ fontWeight: 500, fontSize: "0.88rem", color: s.color }}>{s.label}</div>
                  <div style={{ fontSize: "0.74rem", color: "#475569" }}>{s.desc}</div>
                </div>
                <button
                  onClick={() => triggerScan(s.type)}
                  disabled={triggerLoading || !savedToken}
                  style={{
                    padding: "6px 14px", borderRadius: 8, border: "none", cursor: "pointer",
                    background: `${s.color}22`, color: s.color, fontWeight: 600, fontSize: "0.8rem",
                    opacity: (triggerLoading || !savedToken) ? 0.5 : 1,
                  }}
                >
                  Run
                </button>
              </div>
            ))}
          </div>
          {triggerMsg && (
            <p style={{ fontSize: "0.82rem", color: triggerMsg.startsWith("✓") ? "#86efac" : "#fca5a5", margin: "0 0 16px" }}>
              {triggerMsg}
            </p>
          )}

          {/* Queue depth */}
          {queueDepth && (
            <>
              <div style={{ borderTop: "1px solid rgba(148,163,184,0.1)", paddingTop: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span style={{ fontSize: "0.82rem", color: "#94a3b8", fontWeight: 500 }}>QUEUE DEPTH</span>
                  <span style={{ fontSize: "0.72rem", color: "#475569" }}>Total: {queueDepth.total || 0}</span>
                </div>
                <QueueBar depth={queueDepth} />
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}
