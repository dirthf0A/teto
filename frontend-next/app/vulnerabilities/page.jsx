"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson } from "../_lib/api";

const SEV_COLOR = { critical:"#ef4444", high:"#f97316", medium:"#eab308", low:"#22c55e", info:"#64748b" };
const STATUS_COLOR = { open:"#ef4444", fixed:"#22c55e", accepted:"#94a3b8", false_positive:"#64748b" };

function SevBadge({ sev }) {
  return (
    <span style={{
      display:"inline-block", padding:"2px 8px", borderRadius:999, fontSize:"0.7rem", fontWeight:600,
      background:`${SEV_COLOR[sev]||"#64748b"}22`, color:SEV_COLOR[sev]||"#94a3b8",
      textTransform:"uppercase", letterSpacing:"0.05em",
    }}>{sev||"info"}</span>
  );
}

function RiskMeter({ score }) {
  if (!score) return <span style={{ color:"#475569", fontSize:"0.78rem" }}>—</span>;
  const color = score>=75?"#ef4444":score>=50?"#f97316":score>=25?"#eab308":"#22c55e";
  return (
    <div style={{ display:"flex", alignItems:"center", gap:6 }}>
      <div style={{ width:48, height:6, borderRadius:999, background:"rgba(148,163,184,0.12)", overflow:"hidden" }}>
        <div style={{ height:"100%", width:`${Math.min(score,100)}%`, background:color, borderRadius:999 }}/>
      </div>
      <span style={{ fontSize:"0.78rem", fontWeight:600, color }}>{score.toFixed(0)}</span>
    </div>
  );
}

function SummaryBar({ findings }) {
  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  return (
    <div style={{ display:"flex", gap:12, flexWrap:"wrap", marginBottom:20 }}>
      {Object.entries(counts).map(([sev, n]) => (
        <div key={sev} style={{
          padding:"8px 16px", borderRadius:10,
          background:`${SEV_COLOR[sev]||"#64748b"}15`,
          border:`1px solid ${SEV_COLOR[sev]||"#64748b"}30`,
          textAlign:"center",
        }}>
          <div style={{ fontSize:"1.4rem", fontWeight:700, color:SEV_COLOR[sev]||"#94a3b8" }}>{n}</div>
          <div style={{ fontSize:"0.7rem", color:"#64748b", textTransform:"uppercase" }}>{sev}</div>
        </div>
      ))}
      <div style={{
        padding:"8px 16px", borderRadius:10,
        background:"rgba(148,163,184,0.08)",
        border:"1px solid rgba(148,163,184,0.15)",
        textAlign:"center",
      }}>
        <div style={{ fontSize:"1.4rem", fontWeight:700, color:"#94a3b8" }}>{findings.length}</div>
        <div style={{ fontSize:"0.7rem", color:"#64748b", textTransform:"uppercase" }}>total</div>
      </div>
    </div>
  );
}

export default function VulnerabilitiesPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [findings, setFindings] = useState([]);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("risk");

  const loadData = useCallback(async (token) => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const data = await fetchJson("/findings", token);
      setFindings(data || []);
    } catch (err) {
      setError(err.message || "Failed to load vulnerabilities");
    } finally {
      setLoading(false);
    }
  }, []);

  const filtered = findings
    .filter(f => filter === "all" || f.severity === filter)
    .filter(f => !search || f.title?.toLowerCase().includes(search.toLowerCase()) ||
                  f.cve?.toLowerCase().includes(search.toLowerCase()) ||
                  f.target?.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      if (sortBy === "risk") return (b.risk_score||0) - (a.risk_score||0);
      if (sortBy === "severity") {
        const order = { critical:5, high:4, medium:3, low:2, info:1 };
        return (order[b.severity]||0) - (order[a.severity]||0);
      }
      return new Date(b.first_seen||0) - new Date(a.first_seen||0);
    });

  return (
    <>
      <section className="hero">
        <h1>Vulnerability Dashboard</h1>
        <p>All findings ranked by risk score. Click a row to see enriched detail.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {findings.length > 0 && <SummaryBar findings={findings} />}

      {/* Filters */}
      <div style={{ display:"flex", gap:10, marginBottom:16, flexWrap:"wrap" }}>
        {["all","critical","high","medium","low"].map(sev => (
          <button key={sev} onClick={() => setFilter(sev)} style={{
            padding:"6px 14px", borderRadius:20, border:`1px solid ${sev==="all"?"rgba(148,163,184,0.3)":(SEV_COLOR[sev]||"#64748b")+"44"}`,
            background: filter===sev ? `${sev==="all"?"rgba(148,163,184,0.2)":(SEV_COLOR[sev]||"#64748b")+"22"}` : "transparent",
            color: sev==="all" ? "#94a3b8" : (SEV_COLOR[sev]||"#94a3b8"),
            cursor:"pointer", fontSize:"0.8rem", fontWeight:filter===sev?600:400,
          }}>{sev==="all"?"All":sev.charAt(0).toUpperCase()+sev.slice(1)}</button>
        ))}
        <input placeholder="Search title, CVE, target…" value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ flex:1, minWidth:200, padding:"6px 12px", borderRadius:20, border:"1px solid rgba(148,163,184,0.25)", background:"rgba(15,23,42,0.8)", color:"#e2e8f0", fontSize:"0.82rem" }}/>
        <select value={sortBy} onChange={e => setSortBy(e.target.value)}
          style={{ padding:"6px 12px", borderRadius:20, border:"1px solid rgba(148,163,184,0.25)", background:"rgba(15,23,42,0.8)", color:"#e2e8f0", fontSize:"0.82rem", cursor:"pointer" }}>
          <option value="risk">Sort: Risk Score</option>
          <option value="severity">Sort: Severity</option>
          <option value="date">Sort: Newest</option>
        </select>
      </div>

      <section className="panel">
        {filtered.length === 0 ? (
          <div className="empty">{findings.length ? "No matches." : "No vulnerabilities found."}</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>CVE</th>
                <th>Target</th>
                <th>Risk Score</th>
                <th>CVSS</th>
                <th>Status</th>
                <th>First Seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 100).map(f => (
                <tr key={f.id} style={{ cursor:"default" }}>
                  <td><SevBadge sev={f.severity} /></td>
                  <td style={{ maxWidth:280, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {f.title}
                    {f.occurrences > 1 && (
                      <span style={{ marginLeft:6, fontSize:"0.7rem", color:"#475569" }}>×{f.occurrences}</span>
                    )}
                  </td>
                  <td style={{ fontFamily:"monospace", fontSize:"0.78rem", color:"#f97316" }}>
                    {f.cve ? (
                      <a href={`https://nvd.nist.gov/vuln/detail/${f.cve}`} target="_blank" rel="noreferrer"
                        style={{ color:"#f97316", textDecoration:"underline dotted" }}>
                        {f.cve}
                      </a>
                    ) : "—"}
                  </td>
                  <td style={{ fontFamily:"monospace", fontSize:"0.75rem", color:"#64748b", maxWidth:180, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {f.target || "—"}
                  </td>
                  <td><RiskMeter score={f.risk_score} /></td>
                  <td style={{ fontSize:"0.78rem", color: f.cvss >= 9 ? "#ef4444" : f.cvss >= 7 ? "#f97316" : "#94a3b8" }}>
                    {f.cvss ? f.cvss.toFixed(1) : "—"}
                  </td>
                  <td>
                    <span style={{ fontSize:"0.72rem", color:STATUS_COLOR[f.status]||"#94a3b8", fontWeight:500 }}>
                      {(f.status||"open").replace("_"," ")}
                    </span>
                  </td>
                  <td style={{ fontSize:"0.74rem", color:"#475569", whiteSpace:"nowrap" }}>
                    {f.first_seen ? new Date(f.first_seen).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {filtered.length > 100 && (
          <div style={{ padding:"12px 0", textAlign:"center", fontSize:"0.8rem", color:"#475569" }}>
            Showing 100 of {filtered.length} findings
          </div>
        )}
      </section>
    </>
  );
}
