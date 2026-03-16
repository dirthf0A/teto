"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson } from "../_lib/api";

const SEV_COLORS = {
  critical: { bg: "rgba(248,113,113,0.18)", text: "#fecaca", dot: "#ef4444" },
  high:     { bg: "rgba(251,146,60,0.18)",  text: "#fed7aa", dot: "#f97316" },
  medium:   { bg: "rgba(250,204,21,0.18)",  text: "#fef08a", dot: "#eab308" },
  low:      { bg: "rgba(74,222,128,0.18)",  text: "#bbf7d0", dot: "#22c55e" },
  info:     { bg: "rgba(148,163,184,0.15)", text: "#cbd5e1", dot: "#64748b" },
};

const TYPE_ICONS = {
  asset_discovered:    "🔍",
  new_subdomain:       "🌐",
  subdomain_appeared:  "🌐",
  port_exposed:        "🔓",
  port_closed:         "🔒",
  endpoint_discovered: "🔗",
  vuln_found:          "🐛",
  vuln_discovered:     "🐛",
  vuln_fixed:          "✅",
  tech_changed:        "⚙️",
  bucket_exposed:      "🪣",
  risk_increased:      "⚠️",
  risk_decreased:      "📉",
  scan_completed:      "✔️",
};

function TimelineEvent({ event, isLast }) {
  const sev = event.severity || "info";
  const colors = SEV_COLORS[sev] || SEV_COLORS.info;
  const icon = TYPE_ICONS[event.type] || "📌";
  const ts = event.timestamp ? new Date(event.timestamp) : null;

  return (
    <div style={{ display: "flex", gap: 16, position: "relative" }}>
      {/* Vertical line */}
      {!isLast && (
        <div style={{
          position: "absolute", left: 17, top: 36, bottom: -4,
          width: 2, background: "rgba(148,163,184,0.12)",
        }} />
      )}

      {/* Dot */}
      <div style={{
        flexShrink: 0, width: 36, height: 36, borderRadius: "50%",
        background: `${colors.dot}22`, border: `2px solid ${colors.dot}55`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: "1rem", zIndex: 1,
      }}>
        {icon}
      </div>

      {/* Content */}
      <div style={{
        flex: 1, padding: "10px 14px", borderRadius: 12,
        background: colors.bg, border: `1px solid ${colors.dot}22`,
        marginBottom: 12,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
          <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>{event.label || event.type}</span>
          <span style={{ fontSize: "0.75rem", color: "#64748b", whiteSpace: "nowrap", flexShrink: 0 }}>
            {ts ? ts.toLocaleString() : "—"}
          </span>
        </div>
        {event.detail && (
          <div style={{ marginTop: 4, fontSize: "0.82rem", color: "#94a3b8", fontFamily: "monospace", wordBreak: "break-all" }}>
            {event.detail}
          </div>
        )}
        {event.finding_id && (
          <span className="badge" style={{ marginTop: 6, ...{ background: `${colors.dot}22`, color: colors.text } }}>
            Finding #{event.finding_id}
          </span>
        )}
      </div>
    </div>
  );
}

function AssetCard({ asset, selected, onClick }) {
  const label = asset.url || asset.subdomain || asset.domain || asset.ip || `#${asset.id}`;
  return (
    <div
      onClick={() => onClick(asset)}
      style={{
        padding: "10px 14px", borderRadius: 10, cursor: "pointer", marginBottom: 8,
        background: selected ? "rgba(99,102,241,0.25)" : "rgba(30,41,59,0.5)",
        border: selected ? "1px solid rgba(99,102,241,0.5)" : "1px solid rgba(148,163,184,0.15)",
        transition: "all 0.2s",
      }}
    >
      <div style={{ fontSize: "0.85rem", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {label}
      </div>
      <div style={{ fontSize: "0.72rem", color: "#64748b", marginTop: 2 }}>
        {asset.asset_type} {asset.exposure_class ? `· ${asset.exposure_class}` : ""}
      </div>
    </div>
  );
}

export default function HistoryPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [assets, setAssets] = useState([]);
  const [orgTimeline, setOrgTimeline] = useState([]);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [assetTimeline, setAssetTimeline] = useState([]);
  const [assetSummary, setAssetSummary] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [activeView, setActiveView] = useState("org"); // "org" | "asset"
  const [searchQ, setSearchQ] = useState("");
  const [savedToken, setSavedToken] = useState("");
  const [days, setDays] = useState(30);

  const loadData = useCallback(async (tok) => {
    if (!tok) return;
    setSavedToken(tok);
    setLoading(true);
    setError("");
    try {
      const [assetData, timeline] = await Promise.all([
        fetchJson("/assets?limit=200", tok),
        fetchJson(`/dashboard/org-timeline?days=${days}&limit=150`, tok),
      ]);
      setAssets(assetData || []);
      setOrgTimeline(timeline || []);
    } catch (err) {
      setError(err.message || "Failed to load history");
    } finally {
      setLoading(false);
    }
  }, [days]);

  const selectAsset = async (asset) => {
    setSelectedAsset(asset);
    setActiveView("asset");
    if (!savedToken) return;
    setDetailLoading(true);
    try {
      const [timeline, summary] = await Promise.all([
        fetchJson(`/assets/${asset.id}/timeline?days=90`, savedToken),
        fetchJson(`/assets/${asset.id}/history-summary`, savedToken),
      ]);
      setAssetTimeline(timeline || []);
      setAssetSummary(summary || null);
    } catch {
      setAssetTimeline([]);
      setAssetSummary(null);
    } finally {
      setDetailLoading(false);
    }
  };

  const filteredAssets = assets.filter((a) => {
    if (!searchQ) return true;
    const q = searchQ.toLowerCase();
    return (
      (a.subdomain || "").toLowerCase().includes(q) ||
      (a.domain || "").toLowerCase().includes(q) ||
      (a.ip || "").toLowerCase().includes(q) ||
      (a.url || "").toLowerCase().includes(q)
    );
  });

  const timeline = activeView === "org" ? orgTimeline : assetTimeline;

  return (
    <>
      <section className="hero">
        <h1>Asset History</h1>
        <p>Full lifecycle of every asset — discovery, changes, vulnerabilities, and remediation.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Summary stats for selected asset */}
      {activeView === "asset" && assetSummary && (
        <div className="grid" style={{ marginBottom: 20 }}>
          {[
            { label: "Open Findings",    value: assetSummary.findings?.open ?? 0,    color: "#f87171" },
            { label: "Fixed Findings",   value: assetSummary.findings?.fixed ?? 0,   color: "#22c55e" },
            { label: "Total Changes",    value: assetSummary.change_count ?? 0,      color: "#38bdf8" },
            { label: "Critical Issues",  value: assetSummary.findings?.by_severity?.critical ?? 0, color: "#ef4444" },
          ].map((s) => (
            <div key={s.label} className="panel">
              <h3>{s.label}</h3>
              <div className="value" style={{ color: s.color }}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: "flex", gap: 20, alignItems: "flex-start" }}>
        {/* Left: Asset list */}
        <div style={{ width: 260, flexShrink: 0 }}>
          <div className="panel" style={{ maxHeight: "70vh", overflow: "hidden", display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: "0.85rem", color: "#94a3b8" }}>ASSETS</h3>
              <span style={{ fontSize: "0.75rem", color: "#475569" }}>{filteredAssets.length}</span>
            </div>
            <input
              placeholder="Search assets…"
              value={searchQ}
              onChange={(e) => setSearchQ(e.target.value)}
              style={{
                width: "100%", padding: "7px 10px", borderRadius: 8, marginBottom: 12,
                border: "1px solid rgba(148,163,184,0.2)", background: "rgba(15,23,42,0.8)",
                color: "#e2e8f0", fontSize: "0.82rem",
              }}
            />
            <button
              onClick={() => { setSelectedAsset(null); setActiveView("org"); }}
              style={{
                width: "100%", padding: "8px", borderRadius: 8, border: "none", cursor: "pointer",
                marginBottom: 10, fontWeight: 500, fontSize: "0.82rem",
                background: activeView === "org" ? "rgba(99,102,241,0.25)" : "rgba(30,41,59,0.5)",
                color: activeView === "org" ? "#a5b4fc" : "#94a3b8",
              }}
            >
              📊 Org-wide Timeline
            </button>
            <div style={{ overflowY: "auto", flex: 1 }}>
              {filteredAssets.map((a) => (
                <AssetCard
                  key={a.id}
                  asset={a}
                  selected={selectedAsset?.id === a.id}
                  onClick={selectAsset}
                />
              ))}
              {filteredAssets.length === 0 && (
                <div className="empty" style={{ fontSize: "0.82rem", padding: "8px 0" }}>No assets match.</div>
              )}
            </div>
          </div>
        </div>

        {/* Right: Timeline */}
        <div style={{ flex: 1 }}>
          <div className="panel" style={{ maxHeight: "70vh", overflowY: "auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <h3 style={{ margin: 0, color: "#94a3b8", fontSize: "0.85rem" }}>
                {activeView === "org"
                  ? `ORG-WIDE TIMELINE (last ${days} days)`
                  : `ASSET TIMELINE — ${selectedAsset?.subdomain || selectedAsset?.domain || selectedAsset?.ip || ""}`}
              </h3>
              {activeView === "org" && (
                <select
                  value={days}
                  onChange={(e) => { setDays(Number(e.target.value)); loadData(savedToken); }}
                  style={{
                    padding: "4px 8px", borderRadius: 8, border: "1px solid rgba(148,163,184,0.2)",
                    background: "rgba(15,23,42,0.8)", color: "#e2e8f0", fontSize: "0.8rem",
                  }}
                >
                  {[7, 14, 30, 60, 90].map((d) => <option key={d} value={d}>{d} days</option>)}
                </select>
              )}
            </div>

            {detailLoading ? (
              <div className="empty">Loading timeline…</div>
            ) : timeline.length === 0 ? (
              <div className="empty">
                {activeView === "org"
                  ? "No changes recorded in this period."
                  : "Select an asset from the list to view its history."}
              </div>
            ) : (
              <div style={{ paddingLeft: 4 }}>
                {timeline.map((event, i) => (
                  <TimelineEvent key={event.id || i} event={event} isLast={i === timeline.length - 1} />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
