"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson } from "../_lib/api";

const SEV_COLOR  = { critical:"#ef4444", high:"#f97316", medium:"#eab308", low:"#22c55e", info:"#64748b" };
const EXP_COLOR  = { public:"#ef4444", vpn:"#f97316", internal:"#22c55e" };
const TYPE_ICON  = { domain:"🌐", subdomain:"🔗", ip:"🖥", service:"⚡", endpoint:"📡", cloud:"☁️" };

function TopAssetRow({ asset, rank }) {
  const color = asset.risk_score >= 75 ? "#ef4444" : asset.risk_score >= 50 ? "#f97316" : asset.risk_score >= 25 ? "#eab308" : "#22c55e";
  return (
    <div style={{
      display:"flex", alignItems:"center", gap:12, padding:"10px 14px",
      borderRadius:10, background:"rgba(15,23,42,0.5)",
      border:"1px solid rgba(148,163,184,0.12)", marginBottom:8,
    }}>
      <div style={{
        width:28, height:28, borderRadius:"50%", display:"flex", alignItems:"center", justifyContent:"center",
        background:`${color}22`, color, fontWeight:700, fontSize:"0.8rem", flexShrink:0,
      }}>{rank}</div>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ fontSize:"0.85rem", fontWeight:500, color:"#e2e8f0", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
          {asset.label}
        </div>
        <div style={{ display:"flex", gap:8, marginTop:3 }}>
          <span style={{ fontSize:"0.7rem", padding:"1px 6px", borderRadius:999,
            background:`${EXP_COLOR[asset.exposure]||"#64748b"}22`, color:EXP_COLOR[asset.exposure]||"#94a3b8" }}>
            {asset.exposure||"unknown"}
          </span>
          <span style={{ fontSize:"0.7rem", color:"#475569" }}>{TYPE_ICON[asset.asset_type]||"📦"} {asset.asset_type}</span>
          {asset.findings > 0 && <span style={{ fontSize:"0.7rem", color:"#f87171" }}>{asset.findings} finding{asset.findings !== 1 ? "s" : ""}</span>}
        </div>
      </div>
      <div style={{ textAlign:"right", flexShrink:0 }}>
        <div style={{ fontSize:"1.2rem", fontWeight:700, color }}>{asset.risk_score}</div>
        <div style={{ fontSize:"0.68rem", color:"#475569" }}>risk</div>
      </div>
    </div>
  );
}

function HeatmapCell({ cell }) {
  const color = cell.max_risk >= 75 ? "#ef4444" : cell.max_risk >= 50 ? "#f97316" : cell.max_risk >= 25 ? "#eab308" : "#22c55e";
  const bg    = cell.max_risk >= 75 ? "rgba(239,68,68,0.12)" : cell.max_risk >= 50 ? "rgba(249,115,22,0.12)" : cell.max_risk >= 25 ? "rgba(234,179,8,0.1)" : "rgba(34,197,94,0.08)";
  const expColor = EXP_COLOR[cell.exposure_class] || "#64748b";
  return (
    <div style={{
      padding:"14px 16px", borderRadius:12,
      background:bg, border:`1px solid ${color}30`,
      display:"flex", flexDirection:"column", gap:8,
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <div style={{ fontSize:"0.82rem", fontWeight:600, color:"#e2e8f0" }}>
            {TYPE_ICON[cell.asset_type]||"📦"} {cell.asset_type}
          </div>
          <div style={{ fontSize:"0.7rem", marginTop:2 }}>
            <span style={{ padding:"1px 6px", borderRadius:999, background:`${expColor}22`, color:expColor }}>
              {cell.exposure_class}
            </span>
          </div>
        </div>
        <div style={{ textAlign:"right" }}>
          <div style={{ fontSize:"1.4rem", fontWeight:700, color, lineHeight:1 }}>{cell.max_risk}</div>
          <div style={{ fontSize:"0.65rem", color:"#475569" }}>max risk</div>
        </div>
      </div>
      <div style={{ display:"flex", justifyContent:"space-between", fontSize:"0.72rem", color:"#64748b" }}>
        <span>{cell.count} assets</span>
        <span>avg: {cell.avg_risk}</span>
      </div>
      {cell.top_assets?.length > 0 && (
        <div style={{ borderTop:"1px solid rgba(148,163,184,0.1)", paddingTop:6 }}>
          {cell.top_assets.slice(0,3).map((a,i) => (
            <div key={i} style={{ fontSize:"0.7rem", color:"#64748b", display:"flex", justifyContent:"space-between", marginBottom:2 }}>
              <span style={{ overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:120 }}>{a.label}</span>
              <span style={{ color, fontWeight:600, flexShrink:0, marginLeft:8 }}>{a.risk}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SeverityBar({ label, count, total, color }) {
  const pct = total > 0 ? Math.round((count/total)*100) : 0;
  return (
    <div style={{ marginBottom:10 }}>
      <div style={{ display:"flex", justifyContent:"space-between", fontSize:"0.78rem", marginBottom:3 }}>
        <span style={{ color }}>{label}</span>
        <span style={{ color:"#94a3b8", fontWeight:600 }}>{count} <span style={{ color:"#475569", fontWeight:400 }}>({pct}%)</span></span>
      </div>
      <div style={{ height:7, borderRadius:999, background:"rgba(148,163,184,0.1)", overflow:"hidden" }}>
        <div style={{ height:"100%", width:`${pct}%`, borderRadius:999, background:color, transition:"width 0.6s ease" }}/>
      </div>
    </div>
  );
}

export default function RiskDashboardPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");
  const [risk, setRisk]       = useState(null);
  const [heatmap, setHeatmap] = useState(null);
  const [riskAggregate, setRiskAggregate] = useState(null);

  const loadData = useCallback(async (token) => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const [riskData, heatmapData, aggData] = await Promise.all([
        fetchJson("/dashboard/risk", token),
        fetchJson("/dashboard/risk-heatmap", token),
        fetchJson("/dashboard/risk-aggregate", token).catch(() => null),
      ]);
      setRisk(riskData);
      setHeatmap(heatmapData);
      setRiskAggregate(aggData);
    } catch (err) {
      setError(err.message || "Failed to load risk data");
    } finally {
      setLoading(false);
    }
  }, []);

  const bySev = risk?.by_severity || {};
  const total = risk?.total_open || 0;
  const aggLabel = riskAggregate?.label || "unknown";
  const aggColor = SEV_COLOR[aggLabel] || "#94a3b8";

  return (
    <>
      <section className="hero">
        <h1>Risk Dashboard</h1>
        <p>Risk heatmap, top risky assets, and finding severity breakdown.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Summary KPIs */}
      <div className="grid" style={{ marginBottom:20 }}>
        <div className="panel">
          <h3>Overall Risk</h3>
          <div className="value" style={{ color:aggColor }}>{riskAggregate?.overall_score ?? "—"}</div>
          <span className="badge" style={{ marginTop:4, background:`${aggColor}22`, color:aggColor }}>{aggLabel.toUpperCase()}</span>
        </div>
        <div className="panel">
          <h3>Max Asset Risk</h3>
          <div className="value" style={{ color:"#ef4444" }}>{risk?.max_risk?.toFixed(1) ?? "—"}</div>
        </div>
        <div className="panel">
          <h3>Avg Risk Score</h3>
          <div className="value" style={{ color:"#f97316" }}>{risk?.avg_risk?.toFixed(1) ?? "—"}</div>
        </div>
        <div className="panel">
          <h3>Open Findings</h3>
          <div className="value" style={{ color:"#f87171" }}>{total.toLocaleString()}</div>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20, marginBottom:20 }}>
        {/* Severity distribution */}
        <div className="panel">
          <h3 style={{ marginTop:0, marginBottom:16 }}>Findings by Severity</h3>
          {total > 0 ? (
            <>
              {[["critical","#ef4444"],["high","#f97316"],["medium","#eab308"],["low","#22c55e"],["info","#64748b"]].map(([s,c]) => (
                <SeverityBar key={s} label={s.charAt(0).toUpperCase()+s.slice(1)} count={bySev[s]||0} total={total} color={c} />
              ))}
            </>
          ) : (
            <div className="empty">No open findings.</div>
          )}
        </div>

        {/* Risk aggregate breakdown */}
        <div className="panel">
          <h3 style={{ marginTop:0, marginBottom:16 }}>Risk Aggregate</h3>
          {riskAggregate ? (
            <>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
                {[
                  { label:"Asset Risk", value:riskAggregate.asset_risk, color:"#38bdf8" },
                  { label:"Finding Risk", value:riskAggregate.finding_risk, color:"#f87171" },
                  { label:"Critical Items", value:riskAggregate.critical_count, color:"#ef4444" },
                  { label:"High Items", value:riskAggregate.high_count, color:"#f97316" },
                ].map(s => (
                  <div key={s.label} style={{ textAlign:"center", padding:"12px 8px", borderRadius:10, background:"rgba(15,23,42,0.5)" }}>
                    <div style={{ fontSize:"1.4rem", fontWeight:700, color:s.color }}>{s.value}</div>
                    <div style={{ fontSize:"0.7rem", color:"#475569" }}>{s.label}</div>
                  </div>
                ))}
              </div>
              {riskAggregate.risk_distribution && (
                <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                  {Object.entries(riskAggregate.risk_distribution).filter(([,v])=>v>0).map(([sev,count]) => (
                    <span key={sev} style={{
                      padding:"3px 10px", borderRadius:999, fontSize:"0.72rem",
                      background:`${SEV_COLOR[sev]||"#64748b"}22`, color:SEV_COLOR[sev]||"#94a3b8",
                    }}>{sev}: {count}</span>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="empty">Run a scan to compute risk aggregate.</div>
          )}
        </div>
      </div>

      {/* Risk heatmap */}
      <div className="panel" style={{ marginBottom:20 }}>
        <h3 style={{ marginTop:0, marginBottom:16 }}>Risk Heatmap <span style={{ fontSize:"0.78rem", color:"#475569", fontWeight:400 }}>— by asset type × exposure</span></h3>
        {heatmap?.cells?.length > 0 ? (
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(220px, 1fr))", gap:12 }}>
            {heatmap.cells.slice(0,12).map((cell,i) => (
              <HeatmapCell key={i} cell={cell} />
            ))}
          </div>
        ) : (
          <div className="empty">No heatmap data. Ingest assets and run a scan.</div>
        )}
      </div>

      {/* Top risky assets */}
      <div className="panel">
        <h3 style={{ marginTop:0, marginBottom:16 }}>Top Risky Assets <span style={{ fontSize:"0.78rem", color:"#475569", fontWeight:400 }}>— ordered by cumulative risk score</span></h3>
        {heatmap?.top_assets?.length > 0 ? (
          <div>
            {heatmap.top_assets.map((asset, i) => (
              <TopAssetRow key={asset.id} asset={asset} rank={i+1} />
            ))}
          </div>
        ) : (
          risk?.top_assets?.length > 0 ? (
            <div>
              {risk.top_assets.map((a, i) => (
                <TopAssetRow key={a.asset_id} asset={{
                  id:a.asset_id, label:a.label, risk_score:a.risk_score,
                  exposure:a.exposure_class, asset_type:a.asset_type, findings:a.finding_count||0,
                }} rank={i+1} />
              ))}
            </div>
          ) : (
            <div className="empty">No risky assets found. Run a vuln scan to populate risk scores.</div>
          )
        )}
      </div>
    </>
  );
}
