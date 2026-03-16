"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson, API_BASE } from "../_lib/api";

const SEV_COLORS = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#64748b" };

function TeamCard({ team, selected, onClick }) {
  const risk = team.critical > 0 ? "critical" : team.high > 0 ? "high" : team.open_findings > 0 ? "medium" : "low";
  const color = SEV_COLORS[risk];
  return (
    <div
      onClick={() => onClick(team)}
      style={{
        padding: "14px 16px", borderRadius: 12, cursor: "pointer", marginBottom: 8,
        background: selected ? `${color}18` : "rgba(30,41,59,0.5)",
        border: selected ? `1px solid ${color}44` : "1px solid rgba(148,163,184,0.12)",
        transition: "all 0.2s",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>{team.team_name}</span>
        {team.open_findings > 0 && (
          <span style={{ background: `${color}22`, color, padding: "2px 8px", borderRadius: 999, fontSize: "0.72rem", fontWeight: 600 }}>
            {team.open_findings} issues
          </span>
        )}
      </div>
      <div style={{ display: "flex", gap: 16, marginTop: 8, fontSize: "0.78rem" }}>
        <span style={{ color: "#64748b" }}>{team.asset_count} assets</span>
        {team.critical > 0 && <span style={{ color: "#ef4444" }}>🚨 {team.critical} critical</span>}
        {team.high > 0 && <span style={{ color: "#f97316" }}>⚠️ {team.high} high</span>}
      </div>
    </div>
  );
}

function AssetRow({ asset, savedToken, onAssigned }) {
  const [editing, setEditing] = useState(false);
  const [team, setTeam] = useState(asset.owner?.team_name || "");
  const [email, setEmail] = useState(asset.owner?.owner_email || "");
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!team || !savedToken) return;
    setSaving(true);
    try {
      const res = await fetch(
        `${API_BASE}/assets/${asset.id}/owner?team_name=${encodeURIComponent(team)}&owner_email=${encodeURIComponent(email)}`,
        { method: "POST", headers: { Authorization: `Bearer ${savedToken}` } }
      );
      if (!res.ok) throw new Error(await res.text());
      setEditing(false);
      onAssigned && onAssigned(asset.id, team, email);
    } catch (e) {
      alert(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <tr>
      <td style={{ fontFamily: "monospace", fontSize: "0.82rem", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {asset.label || asset.subdomain || asset.domain || asset.ip || `#${asset.id}`}
      </td>
      <td><span className="badge">{asset.type || asset.asset_type || "—"}</span></td>
      <td>
        <span style={{ fontSize: "0.78rem", color: asset.exposure === "public" ? "#f97316" : "#64748b" }}>
          {asset.exposure || "—"}
        </span>
      </td>
      <td>
        {editing ? (
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input
              value={team}
              onChange={e => setTeam(e.target.value)}
              placeholder="Team name"
              style={{ width: 120, padding: "4px 8px", borderRadius: 6, border: "1px solid rgba(148,163,184,0.25)", background: "rgba(15,23,42,0.9)", color: "#e2e8f0", fontSize: "0.8rem" }}
            />
            <input
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="owner@email"
              style={{ width: 140, padding: "4px 8px", borderRadius: 6, border: "1px solid rgba(148,163,184,0.25)", background: "rgba(15,23,42,0.9)", color: "#e2e8f0", fontSize: "0.8rem" }}
            />
            <button onClick={save} disabled={saving} style={{ padding: "4px 10px", borderRadius: 6, border: "none", cursor: "pointer", background: "rgba(34,197,94,0.2)", color: "#22c55e", fontSize: "0.78rem" }}>
              {saving ? "…" : "Save"}
            </button>
            <button onClick={() => setEditing(false)} style={{ padding: "4px 8px", borderRadius: 6, border: "none", cursor: "pointer", background: "rgba(148,163,184,0.1)", color: "#94a3b8", fontSize: "0.78rem" }}>✕</button>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {asset.owner ? (
              <span style={{ color: "#38bdf8", fontSize: "0.82rem" }}>{asset.owner.team_name}</span>
            ) : (
              <span style={{ color: "#475569", fontSize: "0.78rem" }}>Unassigned</span>
            )}
            <button onClick={() => setEditing(true)} style={{ padding: "2px 8px", borderRadius: 6, border: "none", cursor: "pointer", background: "rgba(99,102,241,0.15)", color: "#a5b4fc", fontSize: "0.72rem" }}>
              Edit
            </button>
          </div>
        )}
      </td>
    </tr>
  );
}

export default function OwnershipPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [savedToken, setSavedToken] = useState("");
  const [teams, setTeams] = useState([]);
  const [unowned, setUnowned] = useState([]);
  const [allAssets, setAllAssets] = useState([]);
  const [selectedTeam, setSelectedTeam] = useState(null);
  const [activeTab, setActiveTab] = useState("teams"); // teams | unowned | all | bulk
  const [bulkPattern, setBulkPattern] = useState("");
  const [bulkTeam, setBulkTeam] = useState("");
  const [bulkEmail, setBulkEmail] = useState("");
  const [bulkResult, setBulkResult] = useState("");
  const [bulkLoading, setBulkLoading] = useState(false);

  const loadData = useCallback(async (tok) => {
    setSavedToken(tok);
    setLoading(true);
    setError("");
    try {
      const [teamData, unownedData, assetData] = await Promise.all([
        fetchJson("/ownership/team-exposure", tok),
        fetchJson("/ownership/unowned?limit=100", tok),
        fetchJson("/assets?limit=300", tok),
      ]);

      // Merge ownership into assets
      const ownerMap = {};
      for (const t of (teamData || [])) {
        for (const a of (t.assets || [])) {
          ownerMap[a.id] = { team_name: t.team_name };
        }
      }
      const enriched = (assetData || []).map(a => ({ ...a, label: a.subdomain || a.domain || a.ip, owner: ownerMap[a.id] || null }));

      setTeams(teamData || []);
      setUnowned(unownedData || []);
      setAllAssets(enriched);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const runBulkAssign = async () => {
    if (!bulkPattern || !bulkTeam || !savedToken) return;
    setBulkLoading(true);
    setBulkResult("");
    try {
      const url = `${API_BASE}/assets/bulk-assign-owner?pattern=${encodeURIComponent(bulkPattern)}&team_name=${encodeURIComponent(bulkTeam)}&owner_email=${encodeURIComponent(bulkEmail)}`;
      const res = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${savedToken}` } });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setBulkResult(`✓ Assigned ${data.assigned} assets matching "${bulkPattern}" to "${bulkTeam}"`);
      await loadData(savedToken);
    } catch (e) {
      setBulkResult(`✗ ${e.message}`);
    } finally {
      setBulkLoading(false);
    }
  };

  const teamAssets = selectedTeam ? allAssets.filter(a => a.owner?.team_name === selectedTeam.team_name) : [];

  const tabs = [
    { id: "teams",   label: `Teams (${teams.length})` },
    { id: "unowned", label: `Unowned (${unowned.length})` },
    { id: "all",     label: `All Assets (${allAssets.length})` },
    { id: "bulk",    label: "Bulk Assign" },
  ];

  return (
    <>
      <section className="hero">
        <h1>Asset Ownership</h1>
        <p>Map every asset to a responsible team. Track exposure and risk per team.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Summary stats */}
      <div className="grid" style={{ marginBottom: 20 }}>
        {[
          { label: "Teams",          value: teams.length,   color: "#38bdf8" },
          { label: "Unowned Assets", value: unowned.length, color: "#f87171" },
          { label: "Total Assets",   value: allAssets.length, color: "#a78bfa" },
          { label: "Teams with Issues", value: teams.filter(t => t.open_findings > 0).length, color: "#f97316" },
        ].map(s => (
          <div key={s.label} className="panel">
            <h3>{s.label}</h3>
            <div className="value" style={{ color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => { setActiveTab(t.id); setSelectedTeam(null); }}
            style={{
              padding: "7px 16px", borderRadius: 10, border: "none", cursor: "pointer",
              background: activeTab === t.id ? "rgba(99,102,241,0.3)" : "rgba(30,41,59,0.6)",
              color: activeTab === t.id ? "#a5b4fc" : "#94a3b8", fontWeight: 500, fontSize: "0.85rem",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Teams tab */}
      {activeTab === "teams" && (
        <div style={{ display: "flex", gap: 20 }}>
          <div style={{ width: 240, flexShrink: 0 }}>
            <div className="panel" style={{ maxHeight: "65vh", overflowY: "auto" }}>
              <div style={{ fontSize: "0.75rem", color: "#475569", marginBottom: 12, fontWeight: 600, textTransform: "uppercase" }}>Teams</div>
              {teams.length === 0 ? (
                <div className="empty" style={{ fontSize: "0.82rem" }}>No teams assigned yet.</div>
              ) : teams.map(t => (
                <TeamCard key={t.team_name} team={t} selected={selectedTeam?.team_name === t.team_name} onClick={setSelectedTeam} />
              ))}
            </div>
          </div>
          <div style={{ flex: 1 }}>
            {selectedTeam ? (
              <div className="panel">
                <div style={{ display: "flex", justify: "space-between", marginBottom: 16 }}>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: "1.1rem" }}>{selectedTeam.team_name}</div>
                    <div style={{ color: "#64748b", fontSize: "0.82rem" }}>{selectedTeam.asset_count} assets · {selectedTeam.open_findings} open findings</div>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 16, marginBottom: 16 }}>
                  {["critical","high","medium","low"].map(sev => (
                    selectedTeam[sev] > 0 && (
                      <div key={sev} style={{ textAlign: "center" }}>
                        <div style={{ fontSize: "1.2rem", fontWeight: 700, color: SEV_COLORS[sev] }}>{selectedTeam[sev]}</div>
                        <div style={{ fontSize: "0.72rem", color: "#475569", textTransform: "capitalize" }}>{sev}</div>
                      </div>
                    )
                  ))}
                </div>
                <table className="table">
                  <thead><tr><th>Asset</th><th>Type</th><th>Exposure</th></tr></thead>
                  <tbody>
                    {(selectedTeam.assets || []).map(a => (
                      <tr key={a.id}>
                        <td style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{a.label}</td>
                        <td><span className="badge">{a.type}</span></td>
                        <td style={{ color: a.exposure === "public" ? "#f97316" : "#64748b", fontSize: "0.78rem" }}>{a.exposure}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="panel" style={{ textAlign: "center", padding: 40 }}>
                <div style={{ fontSize: "2rem", marginBottom: 8 }}>👥</div>
                <div style={{ color: "#94a3b8" }}>Select a team to see their assets and risk breakdown.</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Unowned tab */}
      {activeTab === "unowned" && (
        <section className="panel">
          <div style={{ color: "#f87171", fontSize: "0.82rem", marginBottom: 14 }}>
            ⚠️ These public-facing assets have no owner assigned — click Edit to assign them.
          </div>
          {unowned.length === 0 ? (
            <div className="empty">All public assets have owners. 🎉</div>
          ) : (
            <table className="table">
              <thead><tr><th>Asset</th><th>Type</th><th>Exposure</th><th>Technology</th><th>Action</th></tr></thead>
              <tbody>
                {unowned.map(a => (
                  <tr key={a.id}>
                    <td style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{a.label}</td>
                    <td><span className="badge">{a.type}</span></td>
                    <td style={{ color: "#f97316", fontSize: "0.78rem" }}>{a.exposure}</td>
                    <td style={{ fontSize: "0.78rem", color: "#64748b" }}>{a.technology || "—"}</td>
                    <td>
                      <button onClick={() => { setActiveTab("all"); }} style={{ padding: "3px 10px", borderRadius: 6, border: "none", cursor: "pointer", background: "rgba(99,102,241,0.15)", color: "#a5b4fc", fontSize: "0.72rem" }}>
                        Assign
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {/* All assets tab */}
      {activeTab === "all" && (
        <section className="panel">
          <table className="table">
            <thead><tr><th>Asset</th><th>Type</th><th>Exposure</th><th>Owner</th></tr></thead>
            <tbody>
              {allAssets.slice(0, 200).map(a => (
                <AssetRow key={a.id} asset={a} savedToken={savedToken} onAssigned={(id, team) => {
                  setAllAssets(prev => prev.map(x => x.id === id ? { ...x, owner: { team_name: team } } : x));
                }} />
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* Bulk assign tab */}
      {activeTab === "bulk" && (
        <section className="panel">
          <div style={{ color: "#94a3b8", fontSize: "0.82rem", marginBottom: 16 }}>
            Use glob patterns to assign ownership to multiple assets at once. Examples: <code>*.api.*</code>, <code>cdn.*</code>, <code>*.internal.*</code>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, maxWidth: 500 }}>
            {[
              { label: "Hostname Pattern", val: bulkPattern, set: setBulkPattern, ph: "e.g. *.api.* or cdn.*" },
              { label: "Team Name",        val: bulkTeam,    set: setBulkTeam,    ph: "e.g. Backend Team" },
              { label: "Owner Email (opt)",val: bulkEmail,   set: setBulkEmail,   ph: "team@company.com" },
            ].map(f => (
              <div key={f.label}>
                <div style={{ fontSize: "0.78rem", color: "#64748b", marginBottom: 4 }}>{f.label}</div>
                <input
                  value={f.val}
                  onChange={e => f.set(e.target.value)}
                  placeholder={f.ph}
                  style={{ width: "100%", padding: "9px 12px", borderRadius: 10, border: "1px solid rgba(148,163,184,0.25)", background: "rgba(15,23,42,0.9)", color: "#e2e8f0", fontSize: "0.88rem" }}
                />
              </div>
            ))}
            <button
              onClick={runBulkAssign}
              disabled={bulkLoading || !bulkPattern || !bulkTeam || !savedToken}
              style={{ padding: "10px 20px", borderRadius: 10, border: "none", cursor: "pointer", fontWeight: 600, background: "linear-gradient(120deg,#6366f1,#8b5cf6)", color: "#fff", opacity: (bulkLoading || !bulkPattern || !bulkTeam || !savedToken) ? 0.5 : 1, alignSelf: "flex-start" }}
            >
              {bulkLoading ? "Assigning…" : "Run Bulk Assign"}
            </button>
            {bulkResult && (
              <p style={{ fontSize: "0.85rem", color: bulkResult.startsWith("✓") ? "#86efac" : "#fca5a5", margin: 0 }}>
                {bulkResult}
              </p>
            )}
          </div>
        </section>
      )}
    </>
  );
}
