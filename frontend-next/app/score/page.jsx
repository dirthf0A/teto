"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson, API_BASE } from "../_lib/api";

const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };
const TREND_META = {
  degrading: { arrow: "↑", label: "Degrading",  color: "#ef4444" },
  improving: { arrow: "↓", label: "Improving",  color: "#22c55e" },
  stable:    { arrow: "→", label: "Stable",      color: "#94a3b8" },
};

function ScoreRing({ score, label }) {
  const color = SEV_COLOR[label] || "#94a3b8";
  const pct = Math.min(score, 100);
  const r = 42, cx = 54, cy = 54;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
      <svg width="108" height="108" viewBox="0 0 108 108">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(148,163,184,0.1)" strokeWidth="10" />
        <circle
          cx={cx} cy={cy} r={r} fill="none"
          stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeDashoffset={circ / 4}
          style={{ filter: `drop-shadow(0 0 8px ${color}88)`, transition: "stroke-dasharray 0.8s ease" }}
        />
        <text x={cx} y={cy - 4} textAnchor="middle" fill={color}
          style={{ fontSize: "1.5rem", fontWeight: 700, fontFamily: "inherit" }}>{score}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" fill={color}
          style={{ fontSize: "0.65rem", textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "inherit" }}>{label}</text>
      </svg>
      <span style={{ fontSize: "0.75rem", color: "#64748b" }}>out of 100</span>
    </div>
  );
}

function BreakdownBar({ label, value, maxVal = 40 }) {
  const pct = Math.min((value / maxVal) * 100, 100);
  const color = value === 0 ? "#22c55e" : value < 10 ? "#eab308" : "#ef4444";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
      <span style={{ width: 140, fontSize: "0.82rem", color: "#94a3b8", flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, height: 8, borderRadius: 999, background: "rgba(148,163,184,0.12)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, borderRadius: 999, background: color, transition: "width 0.6s ease" }} />
      </div>
      <span style={{ width: 28, textAlign: "right", fontSize: "0.82rem", fontWeight: 600, color }}>{value}</span>
    </div>
  );
}

function TrendChart({ history }) {
  if (!history || history.length < 2) return <div className="empty">Not enough data for trend chart.</div>;
  const scores = history.map(h => h.score);
  const max = Math.max(...scores, 1);
  const W = 500, H = 120;
  const pts = history.map((h, i) => {
    const x = (i / (history.length - 1)) * (W - 40) + 20;
    const y = H - 20 - ((h.score / max) * (H - 40));
    return [x, y, h];
  });
  const pathD = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x},${y}`).join(" ");
  return (
    <div style={{ overflowX: "auto" }}>
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ minWidth: 320 }}>
        <defs>
          <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={`${pathD} L${pts[pts.length-1][0]},${H} L${pts[0][0]},${H} Z`} fill="url(#scoreGrad)" />
        <path d={pathD} stroke="#38bdf8" strokeWidth="2.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        {pts.map(([x, y, h], i) => {
          const col = SEV_COLOR[h.label] || "#38bdf8";
          return (
            <g key={i}>
              <circle cx={x} cy={y} r={4} fill={col} stroke="#0f172a" strokeWidth="2" />
              <text x={x} y={H - 4} textAnchor="middle" fill="#475569" style={{ fontSize: "0.6rem", fontFamily: "inherit" }}>
                {h.computed_at ? new Date(h.computed_at).toLocaleDateString("en", { month: "short", day: "numeric" }) : ""}
              </text>
              <text x={x} y={y - 10} textAnchor="middle" fill={col} style={{ fontSize: "0.7rem", fontWeight: 600, fontFamily: "inherit" }}>
                {h.score}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export default function ScorePage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState(null);
  const [computing, setComputing] = useState(false);
  const [savedToken, setSavedToken] = useState("");
  const [domain, setDomain] = useState("");

  const loadData = useCallback(async (tok) => {
    setSavedToken(tok);
    setLoading(true);
    setError("");
    try {
      const result = await fetchJson("/score/latest", tok).catch(() => null);
      setData(result);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const computeNow = async () => {
    if (!savedToken) return;
    setComputing(true);
    try {
      const url = domain ? `/score/compute?domain=${encodeURIComponent(domain)}` : "/score/compute";
      const res = await fetch(`${API_BASE}${url}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${savedToken}` },
      });
      if (!res.ok) throw new Error(await res.text());
      await loadData(savedToken);
    } catch (e) {
      setError(e.message);
    } finally {
      setComputing(false);
    }
  };

  const score = data?.score ?? null;
  const label = data?.label ?? "unknown";
  const trend = data?.trend ?? "stable";
  const trendMeta = TREND_META[trend] || TREND_META.stable;
  const breakdown = data?.breakdown || {};
  const history = data?.history || [];
  const deductions = breakdown.deductions || {};
  const bonuses = breakdown.bonuses || {};

  return (
    <>
      <section className="hero">
        <h1>Attack Surface Score</h1>
        <p>Composite risk score reflecting your attack surface exposure at this moment in time.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Compute trigger */}
      <section className="panel" style={{ marginBottom: 20, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <input
          placeholder="Filter by domain (optional)"
          value={domain}
          onChange={e => setDomain(e.target.value)}
          style={{ flex: 1, minWidth: 200, padding: "9px 12px", borderRadius: 10, border: "1px solid rgba(148,163,184,0.25)", background: "rgba(15,23,42,0.9)", color: "#e2e8f0" }}
        />
        <button
          onClick={computeNow}
          disabled={computing || !savedToken}
          style={{ padding: "9px 22px", borderRadius: 10, border: "none", cursor: "pointer", fontWeight: 600, background: "linear-gradient(120deg,#6366f1,#8b5cf6)", color: "#fff", opacity: (computing || !savedToken) ? 0.5 : 1 }}
        >
          {computing ? "Computing…" : "Compute Score Now"}
        </button>
        {data?.computed_at && (
          <span style={{ fontSize: "0.78rem", color: "#475569" }}>
            Last computed: {new Date(data.computed_at).toLocaleString()}
          </span>
        )}
      </section>

      {score !== null && (
        <>
          {/* Score hero */}
          <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: 24, marginBottom: 20 }}>
            <div className="panel" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, minWidth: 160 }}>
              <ScoreRing score={score} label={label} />
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "0.82rem", color: trendMeta.color, fontWeight: 600 }}>
                  {trendMeta.arrow} {trendMeta.label}
                </div>
                {data?.delta !== undefined && (
                  <div style={{ fontSize: "0.72rem", color: "#475569" }}>
                    {data.delta > 0 ? "+" : ""}{data.delta} from last scan
                  </div>
                )}
              </div>
            </div>

            <div className="panel">
              <div style={{ color: "#94a3b8", fontSize: "0.78rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 16 }}>Score Breakdown</div>
              <BreakdownBar label="Exposed Services" value={deductions.exposed_services || 0} maxVal={20} />
              <BreakdownBar label="Critical Vulns" value={deductions.critical_vulns || 0} maxVal={40} />
              <BreakdownBar label="High Vulns" value={deductions.high_vulns || 0} maxVal={20} />
              <BreakdownBar label="Public Buckets" value={deductions.public_buckets || 0} maxVal={20} />
              <BreakdownBar label="High-Risk Ports" value={deductions.high_risk_ports || 0} maxVal={15} />
              <BreakdownBar label="External Domains" value={deductions.external_domains || 0} maxVal={5} />
              {(bonuses.fixed_this_month || bonuses.low_exposure) ? (
                <div style={{ marginTop: 10, padding: "8px 12px", borderRadius: 8, background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.2)", fontSize: "0.8rem", color: "#86efac" }}>
                  ✅ Bonuses: Fixed this month +{bonuses.fixed_this_month || 0} · Low exposure +{bonuses.low_exposure || 0}
                </div>
              ) : null}
            </div>
          </div>

          {/* Stats grid */}
          <div className="grid" style={{ marginBottom: 20 }}>
            {[
              { label: "Total Assets",      value: data.total_assets,        color: "#38bdf8" },
              { label: "Exposed Services",  value: data.exposed_services,    color: "#f97316" },
              { label: "Critical Vulns",    value: data.critical_vulns,      color: "#ef4444" },
              { label: "Public Buckets",    value: data.public_buckets,      color: "#a78bfa" },
              { label: "High-Risk Ports",   value: data.open_high_risk_ports,color: "#f97316" },
            ].map(s => (
              <div key={s.label} className="panel">
                <h3>{s.label}</h3>
                <div className="value" style={{ color: s.color }}>{s.value ?? "—"}</div>
              </div>
            ))}
          </div>

          {/* Trend chart */}
          <section className="panel">
            <div style={{ color: "#94a3b8", fontSize: "0.78rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 16 }}>Score Trend</div>
            <TrendChart history={history} />
          </section>
        </>
      )}

      {score === null && !loading && !error && (
        <div className="panel" style={{ textAlign: "center", padding: 40 }}>
          <div style={{ fontSize: "2rem", marginBottom: 12 }}>📊</div>
          <div style={{ color: "#94a3b8" }}>No score computed yet.</div>
          <div style={{ fontSize: "0.82rem", color: "#475569", marginTop: 6 }}>Click "Compute Score Now" to generate your first attack surface score.</div>
        </div>
      )}
    </>
  );
}
