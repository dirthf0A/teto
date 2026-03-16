"use client";

import { useCallback, useState } from "react";
import TokenBar from "./_components/TokenBar";
import { fetchJson, API_BASE } from "./_lib/api";

const SEV_COLOR = { critical:"#ef4444", high:"#f97316", medium:"#eab308", low:"#22c55e", info:"#64748b" };

function StatCard({ label, value, color="#38bdf8", sub }) {
  return (
    <div className="panel">
      <h3>{label}</h3>
      <div className="value" style={{ color }}>{value ?? "—"}</div>
      {sub && <div style={{ fontSize:"0.76rem", color:"#475569", marginTop:4 }}>{sub}</div>}
    </div>
  );
}

function SevBadge({ sev }) {
  return (
    <span className="badge" style={{ background:`${SEV_COLOR[sev]||"#64748b"}22`, color:SEV_COLOR[sev]||"#94a3b8" }}>
      {(sev||"info").toUpperCase()}
    </span>
  );
}

function RiskBar({ label, value, max=100 }) {
  const pct = Math.min((value/max)*100,100);
  const color = value>=75?"#ef4444":value>=50?"#f97316":value>=25?"#eab308":"#22c55e";
  return (
    <div style={{ marginBottom:10 }}>
      <div style={{ display:"flex", justifyContent:"space-between", fontSize:"0.8rem", marginBottom:4 }}>
        <span style={{ color:"#94a3b8" }}>{label}</span>
        <span style={{ color, fontWeight:600 }}>{value}</span>
      </div>
      <div style={{ height:6, borderRadius:999, background:"rgba(148,163,184,0.12)" }}>
        <div style={{ height:"100%", width:`${pct}%`, borderRadius:999, background:color, transition:"width 0.6s ease" }}/>
      </div>
    </div>
  );
}

export default function AttackSurfacePage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [surface, setSurface] = useState(null);
  const [overview, setOverview] = useState(null);
  const [risk, setRisk] = useState(null);
  const [topFindings, setTopFindings] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [savedToken, setSavedToken] = useState("");

  const loadData = useCallback(async (token) => {
    if (!token) return;
    setSavedToken(token);
    setLoading(true);
    setError("");
    try {
      const [surfaceData, overviewData, riskData, findingsData, alertsData] = await Promise.all([
        fetchJson("/dashboard/attack-surface", token),
        fetchJson("/dashboard/overview", token),
        fetchJson("/dashboard/risk-aggregate", token).catch(() => null),
        fetchJson("/findings?severity=critical", token).catch(() => []),
        fetchJson("/alerts?status=new", token).catch(() => []),
      ]);
      setSurface(surfaceData);
      setOverview(overviewData);
      setRisk(riskData);
      setTopFindings((findingsData||[]).slice(0,5));
      setRecentAlerts((alertsData||[]).slice(0,5));
    } catch (err) {
      setError(err.message || "Failed to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  const sevCounts = overviewData?.findings_by_severity || {};
  const riskLabel = risk?.label || "unknown";
  const riskColor = SEV_COLOR[riskLabel] || "#94a3b8";

  return (
    <>
      <section className="hero">
        <h1>Attack Surface Overview</h1>
        <p>Real-time visibility into your organization's external attack surface.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Top stat cards */}
      <div className="grid" style={{ marginBottom:20 }}>
        <StatCard label="Total Assets" value={overview?.asset_count?.toLocaleString()} color="#38bdf8" />
        <StatCard label="Domains" value={surface?.domains} color="#a78bfa" />
        <StatCard label="Subdomains" value={surface?.subdomains?.toLocaleString()} color="#22d3ee" />
        <StatCard label="Endpoints" value={surface?.endpoints?.toLocaleString()} color="#fb923c" />
        <StatCard label="Open Alerts" value={overview?.open_alerts} color="#ef4444"
          sub={overview?.open_alerts > 0 ? "Requires attention" : "All clear"} />
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20, marginBottom:20 }}>
        {/* Finding severity breakdown */}
        <div className="panel">
          <h3 style={{ marginTop:0, marginBottom:16 }}>Findings by Severity</h3>
          {overview?.findings_by_severity ? (
            <>
              {["critical","high","medium","low","info"].map(sev => (
                <RiskBar key={sev} label={sev.charAt(0).toUpperCase()+sev.slice(1)}
                  value={overview.findings_by_severity[sev]||0}
                  max={Math.max(...Object.values(overview.findings_by_severity), 1)} />
              ))}
              <div style={{ marginTop:12, paddingTop:10, borderTop:"1px solid rgba(148,163,184,0.1)", fontSize:"0.82rem", color:"#94a3b8" }}>
                Total findings: <strong style={{ color:"#e2e8f0" }}>{overview.findings_total}</strong>
              </div>
            </>
          ) : (
            <div className="empty">No findings yet.</div>
          )}
        </div>

        {/* Org risk aggregate */}
        <div className="panel">
          <h3 style={{ marginTop:0, marginBottom:16 }}>Risk Summary</h3>
          {risk ? (
            <>
              <div style={{ display:"flex", alignItems:"center", gap:16, marginBottom:20 }}>
                <div style={{
                  width:72, height:72, borderRadius:"50%",
                  border:`3px solid ${riskColor}`,
                  display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center",
                  boxShadow:`0 0 20px ${riskColor}44`,
                }}>
                  <span style={{ fontSize:"1.4rem", fontWeight:700, color:riskColor }}>{risk.overall_score}</span>
                  <span style={{ fontSize:"0.55rem", color:riskColor, textTransform:"uppercase", letterSpacing:"0.08em" }}>{riskLabel}</span>
                </div>
                <div>
                  <div style={{ fontSize:"0.82rem", color:"#94a3b8", marginBottom:6 }}>Asset Risk: <strong style={{ color:"#38bdf8" }}>{risk.asset_risk}</strong></div>
                  <div style={{ fontSize:"0.82rem", color:"#94a3b8", marginBottom:6 }}>Finding Risk: <strong style={{ color:"#f87171" }}>{risk.finding_risk}</strong></div>
                  {risk.critical_count > 0 && (
                    <div style={{ fontSize:"0.82rem", color:"#ef4444", fontWeight:600 }}>⚠ {risk.critical_count} critical items</div>
                  )}
                </div>
              </div>
              {risk.risk_distribution && (
                <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                  {Object.entries(risk.risk_distribution).map(([sev, count]) => count > 0 && (
                    <span key={sev} className="badge" style={{ background:`${SEV_COLOR[sev]||"#64748b"}22`, color:SEV_COLOR[sev]||"#94a3b8" }}>
                      {sev}: {count}
                    </span>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="empty">Run a scan to compute risk scores.</div>
          )}
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
        {/* Top critical findings */}
        <div className="panel">
          <h3 style={{ marginTop:0, marginBottom:12 }}>Top Critical Findings</h3>
          {topFindings.length === 0 ? (
            <div className="empty">No critical findings.</div>
          ) : (
            <div>
              {topFindings.map(f => (
                <div key={f.id} style={{ padding:"10px 0", borderBottom:"1px solid rgba(148,163,184,0.08)" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:4 }}>
                    <span style={{ fontSize:"0.85rem", fontWeight:500, color:"#e2e8f0", flex:1, marginRight:8 }}>{f.title}</span>
                    <SevBadge sev={f.severity} />
                  </div>
                  <div style={{ display:"flex", gap:12, fontSize:"0.74rem", color:"#475569" }}>
                    {f.cve && <span style={{ color:"#f97316" }}>{f.cve}</span>}
                    {f.target && <span style={{ fontFamily:"monospace" }}>{f.target?.slice(0,40)}</span>}
                    <span style={{ color:"#ef4444", marginLeft:"auto" }}>risk: {f.risk_score?.toFixed(1)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent alerts */}
        <div className="panel">
          <h3 style={{ marginTop:0, marginBottom:12 }}>Recent Alerts</h3>
          {recentAlerts.length === 0 ? (
            <div className="empty">No open alerts.</div>
          ) : (
            <div>
              {recentAlerts.map(a => (
                <div key={a.id} style={{ padding:"10px 0", borderBottom:"1px solid rgba(148,163,184,0.08)" }}>
                  <div style={{ fontSize:"0.8rem", fontWeight:500, color:"#f87171", marginBottom:3 }}>
                    {a.alert_type.replace(/_/g," ").replace(/\b\w/g,l=>l.toUpperCase())}
                  </div>
                  <div style={{ fontSize:"0.76rem", color:"#94a3b8" }}>{a.message?.slice(0,80)}</div>
                  <div style={{ fontSize:"0.7rem", color:"#475569", marginTop:4 }}>
                    {a.created_at ? new Date(a.created_at).toLocaleString() : ""}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
