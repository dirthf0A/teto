"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson, API_BASE } from "../_lib/api";

const METHOD_COLORS = { GET: "#38bdf8", POST: "#f472b6", PUT: "#fb923c", DELETE: "#f87171", WS: "#a78bfa" };

function EndpointRow({ ep }) {
  const method = ep.is_websocket ? "WS" : "GET";
  const color = METHOD_COLORS[method] || "#94a3b8";
  const url = ep.url || ep;
  const isApi = ep.is_api;
  return (
    <tr>
      <td>
        <span className="badge" style={{ background: `${color}22`, color }}>{method}</span>
      </td>
      <td style={{ fontFamily: "monospace", fontSize: "0.82rem", wordBreak: "break-all" }}>{url}</td>
      <td>
        {isApi && <span className="badge" style={{ background: "rgba(168,85,247,0.2)", color: "#d8b4fe" }}>API</span>}
        {ep.is_websocket && <span className="badge" style={{ background: "rgba(167,139,250,0.2)", color: "#c4b5fd" }}>WS</span>}
      </td>
      <td style={{ fontSize: "0.78rem", color: "#94a3b8", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {ep.source_js || "—"}
      </td>
    </tr>
  );
}

function SubdomainPill({ host }) {
  return (
    <span style={{
      display: "inline-block", padding: "3px 10px", borderRadius: 999, fontSize: "0.78rem",
      background: "rgba(34,197,94,0.12)", color: "#86efac", border: "1px solid rgba(34,197,94,0.2)",
      marginRight: 8, marginBottom: 8, fontFamily: "monospace"
    }}>{host}</span>
  );
}

async function triggerJsScan(token, domain) {
  const res = await fetch(`${API_BASE}/scans`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ scan_type: "web", domain }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export default function JsDiscoveryPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [token, setToken] = useState("");
  const [data, setData] = useState(null);
  const [scanDomain, setScanDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState("");
  const [activeTab, setActiveTab] = useState("endpoints");
  const [searchQ, setSearchQ] = useState("");

  const loadData = useCallback(async (tok) => {
    if (!tok) return;
    setToken(tok);
    setLoading(true);
    setError("");
    try {
      // Load assets that have JS-derived data
      const assets = await fetchJson("/assets?asset_type=endpoint&limit=500", tok);
      // Try to load any existing JS discovery results from findings
      const findings = await fetchJson("/findings?tool=js_endpoint_extractor&limit=200", tok).catch(() => []);
      setData({ assets: assets || [], findings: findings || [] });
    } catch (err) {
      setError(err.message || "Failed to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  const runScan = async () => {
    if (!scanDomain || !token) return;
    setScanning(true);
    setScanMsg("");
    try {
      const scan = await triggerJsScan(token, scanDomain);
      setScanMsg(`✓ Scan queued (ID: ${scan.id}) — results will appear after completion`);
    } catch (err) {
      setScanMsg(`✗ ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  // Derive mock-structured endpoint list from assets + findings
  const endpoints = data
    ? data.assets
        .filter((a) => a.url && (searchQ === "" || a.url.toLowerCase().includes(searchQ.toLowerCase())))
        .map((a) => ({
          url: a.url,
          is_api: a.url.includes("/api/") || a.url.includes("/v1/") || a.url.includes("/graphql"),
          is_websocket: a.url.startsWith("ws"),
          source_js: a.subdomain || a.domain || "",
        }))
    : [];

  const subdomains = data
    ? [...new Set(data.assets.map((a) => a.subdomain).filter(Boolean))]
    : [];

  const apiCount = endpoints.filter((e) => e.is_api).length;
  const wsCount = endpoints.filter((e) => e.is_websocket).length;
  const secretHints = data ? data.findings.filter((f) => f.tool === "js_endpoint_extractor").length : 0;

  const tabs = [
    { id: "endpoints", label: `Endpoints (${endpoints.length})` },
    { id: "subdomains", label: `Subdomains (${subdomains.length})` },
    { id: "findings", label: `JS Findings (${secretHints})` },
  ];

  return (
    <>
      <section className="hero">
        <h1>JS Asset Discovery</h1>
        <p>Endpoints, API paths, WebSocket URLs, and subdomains extracted from JavaScript bundles.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Trigger scan panel */}
      <section className="panel" style={{ marginBottom: 20 }}>
        <h3 style={{ marginTop: 0 }}>Trigger JS Scan</h3>
        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <input
            placeholder="target domain (e.g. example.com)"
            value={scanDomain}
            onChange={(e) => setScanDomain(e.target.value)}
            style={{
              flex: 1, minWidth: 200, padding: "9px 12px", borderRadius: 10,
              border: "1px solid rgba(148,163,184,0.3)", background: "rgba(15,23,42,0.9)", color: "#e2e8f0",
            }}
          />
          <button
            onClick={runScan}
            disabled={!scanDomain || !token || scanning}
            style={{
              padding: "9px 20px", borderRadius: 10, border: "none", cursor: "pointer",
              background: "linear-gradient(120deg,#6366f1,#8b5cf6)", color: "#fff", fontWeight: 600,
              opacity: (!scanDomain || !token || scanning) ? 0.5 : 1,
            }}
          >
            {scanning ? "Queuing…" : "Run JS Scan"}
          </button>
        </div>
        {scanMsg && (
          <p style={{ marginTop: 10, fontSize: "0.85rem", color: scanMsg.startsWith("✓") ? "#86efac" : "#fca5a5" }}>
            {scanMsg}
          </p>
        )}
      </section>

      {/* Stats bar */}
      <div className="grid" style={{ marginBottom: 20 }}>
        {[
          { label: "Endpoints Found", value: endpoints.length, color: "#38bdf8" },
          { label: "API Paths", value: apiCount, color: "#a78bfa" },
          { label: "WebSocket URLs", value: wsCount, color: "#f472b6" },
          { label: "Subdomains via JS", value: subdomains.length, color: "#22c55e" },
        ].map((s) => (
          <div key={s.label} className="panel">
            <h3>{s.label}</h3>
            <div className="value" style={{ color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <section className="panel">
        {/* Tab headers */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20, borderBottom: "1px solid rgba(148,163,184,0.15)", paddingBottom: 12 }}>
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              style={{
                padding: "6px 16px", borderRadius: 10, border: "none", cursor: "pointer", fontWeight: 500,
                background: activeTab === t.id ? "rgba(99,102,241,0.3)" : "rgba(30,41,59,0.6)",
                color: activeTab === t.id ? "#a5b4fc" : "#94a3b8", transition: "all 0.2s",
              }}
            >
              {t.label}
            </button>
          ))}

          {activeTab === "endpoints" && (
            <input
              placeholder="Filter endpoints…"
              value={searchQ}
              onChange={(e) => setSearchQ(e.target.value)}
              style={{
                marginLeft: "auto", width: 220, padding: "5px 10px", borderRadius: 8,
                border: "1px solid rgba(148,163,184,0.25)", background: "rgba(15,23,42,0.8)", color: "#e2e8f0", fontSize: "0.85rem",
              }}
            />
          )}
        </div>

        {/* Endpoints tab */}
        {activeTab === "endpoints" && (
          endpoints.length === 0 ? (
            <div className="empty">No endpoints discovered yet. Run a JS scan to populate this view.</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Method</th>
                  <th>URL</th>
                  <th style={{ width: 100 }}>Tags</th>
                  <th>Source JS</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.slice(0, 200).map((ep, i) => (
                  <EndpointRow key={i} ep={ep} />
                ))}
              </tbody>
            </table>
          )
        )}

        {/* Subdomains tab */}
        {activeTab === "subdomains" && (
          subdomains.length === 0 ? (
            <div className="empty">No JS-derived subdomains yet.</div>
          ) : (
            <div style={{ padding: "8px 0" }}>
              {subdomains.map((h) => <SubdomainPill key={h} host={h} />)}
            </div>
          )
        )}

        {/* Findings tab */}
        {activeTab === "findings" && (
          data?.findings.length === 0 ? (
            <div className="empty">No JS findings recorded.</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Target</th>
                  <th>Tool</th>
                </tr>
              </thead>
              <tbody>
                {(data?.findings || []).map((f) => (
                  <tr key={f.id}>
                    <td><span className={`badge severity-${f.severity}`}>{f.severity}</span></td>
                    <td>{f.title}</td>
                    <td style={{ fontSize: "0.82rem", fontFamily: "monospace" }}>{f.target || "—"}</td>
                    <td><span className="badge">{f.tool}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </section>
    </>
  );
}
