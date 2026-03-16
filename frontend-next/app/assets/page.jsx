"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson } from "../_lib/api";

const EXP_COLOR = { public:"#ef4444", vpn:"#f97316", internal:"#22c55e" };
const TYPE_ICON = { domain:"🌐", subdomain:"🔗", ip:"🖥", service:"⚡", endpoint:"📡", cloud:"☁️", external_domain:"🌍" };

function ExposurePill({ cls }) {
  return (
    <span style={{
      padding:"2px 8px", borderRadius:999, fontSize:"0.7rem", fontWeight:600,
      background:`${EXP_COLOR[cls]||"#64748b"}22`, color:EXP_COLOR[cls]||"#94a3b8",
      textTransform:"uppercase",
    }}>{cls||"unknown"}</span>
  );
}

function RiskBar({ score }) {
  if (!score) return <span style={{ color:"#475569", fontSize:"0.78rem" }}>—</span>;
  const color = score>=75?"#ef4444":score>=50?"#f97316":score>=25?"#eab308":"#22c55e";
  return (
    <div style={{ display:"flex", alignItems:"center", gap:6 }}>
      <div style={{ width:48, height:5, borderRadius:999, background:"rgba(148,163,184,0.12)", overflow:"hidden" }}>
        <div style={{ height:"100%", width:`${Math.min(score,100)}%`, background:color, borderRadius:999 }}/>
      </div>
      <span style={{ fontSize:"0.76rem", fontWeight:600, color }}>{score.toFixed(0)}</span>
    </div>
  );
}

export default function AssetInventoryPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [assets, setAssets] = useState([]);
  const [filter, setFilter] = useState("all");
  const [exposure, setExposure] = useState("all");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("risk");

  const loadData = useCallback(async (token) => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const data = await fetchJson("/assets", token);
      setAssets(data || []);
    } catch (err) {
      setError(err.message || "Failed to load assets");
    } finally {
      setLoading(false);
    }
  }, []);

  const types = ["all", ...new Set(assets.map(a => a.asset_type).filter(Boolean))];

  const filtered = assets
    .filter(a => filter === "all" || a.asset_type === filter)
    .filter(a => exposure === "all" || a.exposure_class === exposure)
    .filter(a => !search || [a.domain, a.subdomain, a.ip, a.url, a.technology]
      .some(v => v?.toLowerCase().includes(search.toLowerCase())))
    .sort((a, b) => {
      if (sortBy === "risk") return (b.risk_score||0) - (a.risk_score||0);
      if (sortBy === "exposure") {
        const o = { public:3, vpn:2, internal:1 };
        return (o[b.exposure_class]||0) - (o[a.exposure_class]||0);
      }
      return new Date(b.last_seen||0) - new Date(a.last_seen||0);
    });

  // Stats
  const stats = {
    total: assets.length,
    public: assets.filter(a => a.exposure_class === "public").length,
    high_risk: assets.filter(a => (a.risk_score||0) >= 50).length,
    types: types.filter(t => t !== "all").length,
  };

  return (
    <>
      <section className="hero">
        <h1>Asset Inventory</h1>
        <p>All discovered assets with exposure classification and risk scoring.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Summary stats */}
      <div className="grid" style={{ marginBottom:20 }}>
        {[
          { label:"Total Assets", value:stats.total.toLocaleString(), color:"#38bdf8" },
          { label:"Internet-Facing", value:stats.public, color:"#ef4444" },
          { label:"High Risk (>50)", value:stats.high_risk, color:"#f97316" },
          { label:"Asset Types", value:stats.types, color:"#a78bfa" },
        ].map(s => (
          <div key={s.label} className="panel">
            <h3>{s.label}</h3>
            <div className="value" style={{ color:s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display:"flex", gap:10, marginBottom:16, flexWrap:"wrap" }}>
        <select value={filter} onChange={e => setFilter(e.target.value)}
          style={{ padding:"6px 12px", borderRadius:10, border:"1px solid rgba(148,163,184,0.25)", background:"rgba(15,23,42,0.8)", color:"#e2e8f0", fontSize:"0.82rem", cursor:"pointer" }}>
          {types.map(t => <option key={t} value={t}>{t === "all" ? "All Types" : t}</option>)}
        </select>
        <select value={exposure} onChange={e => setExposure(e.target.value)}
          style={{ padding:"6px 12px", borderRadius:10, border:"1px solid rgba(148,163,184,0.25)", background:"rgba(15,23,42,0.8)", color:"#e2e8f0", fontSize:"0.82rem", cursor:"pointer" }}>
          <option value="all">All Exposure</option>
          <option value="public">Public</option>
          <option value="vpn">VPN</option>
          <option value="internal">Internal</option>
        </select>
        <select value={sortBy} onChange={e => setSortBy(e.target.value)}
          style={{ padding:"6px 12px", borderRadius:10, border:"1px solid rgba(148,163,184,0.25)", background:"rgba(15,23,42,0.8)", color:"#e2e8f0", fontSize:"0.82rem", cursor:"pointer" }}>
          <option value="risk">Sort: Risk</option>
          <option value="exposure">Sort: Exposure</option>
          <option value="recent">Sort: Recently Seen</option>
        </select>
        <input placeholder="Search host, IP, URL, tech…" value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ flex:1, minWidth:200, padding:"6px 12px", borderRadius:10, border:"1px solid rgba(148,163,184,0.25)", background:"rgba(15,23,42,0.8)", color:"#e2e8f0", fontSize:"0.82rem" }}/>
        <span style={{ display:"flex", alignItems:"center", fontSize:"0.78rem", color:"#475569" }}>
          {filtered.length} of {assets.length}
        </span>
      </div>

      <section className="panel">
        {filtered.length === 0 ? (
          <div className="empty">{assets.length ? "No matches." : "No assets yet. Run a scan to discover assets."}</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Host / URL</th>
                <th>IP</th>
                <th>Port</th>
                <th>Technology</th>
                <th>Exposure</th>
                <th>Risk</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 200).map(a => {
                const label = a.url || a.subdomain || a.domain || a.ip || `#${a.id}`;
                return (
                  <tr key={a.id}>
                    <td style={{ fontSize:"0.85rem" }}>
                      <span title={a.asset_type}>{TYPE_ICON[a.asset_type]||"📦"}</span>
                      <span style={{ marginLeft:4, fontSize:"0.72rem", color:"#475569" }}>{a.asset_type}</span>
                    </td>
                    <td style={{ fontFamily:"monospace", fontSize:"0.78rem", maxWidth:220, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      {label}
                    </td>
                    <td style={{ fontFamily:"monospace", fontSize:"0.75rem", color:"#64748b" }}>{a.ip||"—"}</td>
                    <td style={{ fontSize:"0.78rem", color:"#94a3b8" }}>{a.port||"—"}</td>
                    <td style={{ fontSize:"0.75rem", color:"#64748b", maxWidth:160, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      {a.technology||"—"}
                    </td>
                    <td><ExposurePill cls={a.exposure_class} /></td>
                    <td><RiskBar score={a.risk_score} /></td>
                    <td style={{ fontSize:"0.73rem", color:"#475569", whiteSpace:"nowrap" }}>
                      {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {filtered.length > 200 && (
          <div style={{ padding:"12px 0", textAlign:"center", fontSize:"0.8rem", color:"#475569" }}>
            Showing 200 of {filtered.length} assets
          </div>
        )}
      </section>
    </>
  );
}
