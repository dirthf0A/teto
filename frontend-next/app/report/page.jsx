"use client";

import { useCallback, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { API_BASE } from "../_lib/api";

function FormatButton({ format, icon, desc, color, onClick, loading }) {
  return (
    <button
      onClick={() => onClick(format)}
      disabled={loading}
      style={{
        flex: 1, padding: "18px 16px", borderRadius: 14, border: `1px solid ${color}33`,
        background: `${color}11`, cursor: loading ? "not-allowed" : "pointer",
        display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
        transition: "all 0.2s", opacity: loading ? 0.5 : 1,
      }}
      onMouseEnter={e => { if (!loading) e.currentTarget.style.background = `${color}22`; }}
      onMouseLeave={e => { e.currentTarget.style.background = `${color}11`; }}
    >
      <span style={{ fontSize: "2rem" }}>{icon}</span>
      <span style={{ fontWeight: 700, fontSize: "1rem", color }}>{format.toUpperCase()}</span>
      <span style={{ fontSize: "0.78rem", color: "#64748b", textAlign: "center" }}>{desc}</span>
    </button>
  );
}

export default function ReportPage() {
  const [savedToken, setSavedToken] = useState("");
  const [loading, setLoading] = useState(false);
  const [domain, setDomain] = useState("");
  const [msg, setMsg] = useState("");
  const [previewHtml, setPreviewHtml] = useState("");

  const loadData = useCallback(async (tok) => {
    setSavedToken(tok);
  }, []);

  const downloadReport = async (format) => {
    if (!savedToken) { setMsg("Please load your token first."); return; }
    setLoading(true);
    setMsg("");
    setPreviewHtml("");
    try {
      const domainParam = domain ? `?domain=${encodeURIComponent(domain)}` : "";
      const endpoint = `/reports/security.${format}${domainParam}`;
      const res = await fetch(`${API_BASE}${endpoint}`, {
        headers: { Authorization: `Bearer ${savedToken}` },
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || "Report generation failed");
      }

      if (format === "html") {
        const html = await res.text();
        setPreviewHtml(html);
        return;
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `security-report.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setMsg(`✓ ${format.toUpperCase()} report downloaded.`);
    } catch (e) {
      setMsg(`✗ ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <section className="hero">
        <h1>Security Report</h1>
        <p>One-click professional reports — PDF for clients, Markdown for dev teams, HTML for executives.</p>
        <TokenBar onLoad={loadData} loading={false} />
      </section>

      <section className="panel" style={{ marginBottom: 20 }}>
        <div style={{ color: "#94a3b8", fontSize: "0.78rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 }}>Report Options</div>
        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <input
            placeholder="Filter by domain (optional, e.g. example.com)"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            style={{ flex: 1, minWidth: 220, padding: "9px 12px", borderRadius: 10, border: "1px solid rgba(148,163,184,0.25)", background: "rgba(15,23,42,0.9)", color: "#e2e8f0", fontSize: "0.88rem" }}
          />
          <span style={{ fontSize: "0.78rem", color: "#475569" }}>Leave blank for all domains</span>
        </div>
      </section>

      {/* Format buttons */}
      <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
        <FormatButton
          format="pdf"
          icon="📄"
          desc="Professional PDF for clients & pentesters"
          color="#ef4444"
          onClick={downloadReport}
          loading={loading}
        />
        <FormatButton
          format="md"
          icon="📝"
          desc="Markdown for GitHub, Confluence, Notion"
          color="#38bdf8"
          onClick={downloadReport}
          loading={loading}
        />
        <FormatButton
          format="html"
          icon="🌐"
          desc="Rich HTML — preview inline or save"
          color="#a78bfa"
          onClick={downloadReport}
          loading={loading}
        />
      </div>

      {loading && (
        <div className="panel" style={{ textAlign: "center", padding: 32 }}>
          <div style={{ fontSize: "1.5rem", marginBottom: 8 }}>⏳</div>
          <div style={{ color: "#94a3b8" }}>Generating report — collecting data from all modules…</div>
        </div>
      )}

      {msg && (
        <div style={{
          padding: "12px 16px", borderRadius: 10, marginBottom: 16,
          background: msg.startsWith("✓") ? "rgba(34,197,94,0.1)" : "rgba(239,68,68,0.1)",
          border: `1px solid ${msg.startsWith("✓") ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)"}`,
          color: msg.startsWith("✓") ? "#86efac" : "#fca5a5",
          fontSize: "0.88rem",
        }}>
          {msg}
        </div>
      )}

      {/* HTML preview */}
      {previewHtml && (
        <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 20px", borderBottom: "1px solid rgba(148,163,184,0.1)" }}>
            <span style={{ fontWeight: 600, fontSize: "0.88rem" }}>HTML Report Preview</span>
            <div style={{ display: "flex", gap: 10 }}>
              <button
                onClick={() => {
                  const blob = new Blob([previewHtml], { type: "text/html" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url; a.download = "security-report.html";
                  document.body.appendChild(a); a.click();
                  document.body.removeChild(a); URL.revokeObjectURL(url);
                }}
                style={{ padding: "5px 14px", borderRadius: 8, border: "none", cursor: "pointer", background: "rgba(167,139,250,0.2)", color: "#a78bfa", fontWeight: 600, fontSize: "0.82rem" }}
              >
                Download HTML
              </button>
              <button
                onClick={() => setPreviewHtml("")}
                style={{ padding: "5px 14px", borderRadius: 8, border: "none", cursor: "pointer", background: "rgba(148,163,184,0.1)", color: "#94a3b8", fontSize: "0.82rem" }}
              >
                Close
              </button>
            </div>
          </div>
          <iframe
            srcDoc={previewHtml}
            style={{ width: "100%", height: "70vh", border: "none", borderRadius: "0 0 16px 16px" }}
            title="Security Report Preview"
          />
        </div>
      )}

      {/* What's included */}
      {!previewHtml && !loading && (
        <section className="panel">
          <div style={{ color: "#94a3b8", fontSize: "0.78rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 16 }}>Report Contents</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
            {[
              ["📊", "Executive Summary",        "Score, trend, key metrics at a glance"],
              ["🗂️", "Asset Inventory",           "Breakdown by type, exposure, provider"],
              ["🐛", "Top Findings",              "Critical & high vulns with CVE + CVSS"],
              ["📈", "Attack Surface Changes",    "What changed in the last 30 days"],
              ["👥", "Team Ownership",            "Risk breakdown per team"],
              ["✅", "Recommendations",           "Prioritized remediation action items"],
            ].map(([icon, title, desc]) => (
              <div key={title} style={{ padding: "12px 14px", borderRadius: 10, background: "rgba(30,41,59,0.5)", border: "1px solid rgba(148,163,184,0.1)" }}>
                <div style={{ fontSize: "1.2rem", marginBottom: 6 }}>{icon}</div>
                <div style={{ fontWeight: 600, fontSize: "0.88rem", marginBottom: 3 }}>{title}</div>
                <div style={{ fontSize: "0.76rem", color: "#64748b" }}>{desc}</div>
              </div>
            ))}
          </div>
        </section>
      )}
    </>
  );
}
