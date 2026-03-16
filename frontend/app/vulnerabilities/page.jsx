"use client";

import React, { useEffect, useMemo, useState } from "react";

import { fetchJson } from "../lib/api";

export default function VulnerabilitiesPage() {
  const [findings, setFindings] = useState([]);
  const [severity, setSeverity] = useState("all");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError("");
    fetchJson("/vulnerabilities")
      .then((data) => setFindings(data))
      .catch((err) => setError(err.message || "Failed to load findings"))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    if (severity === "all") return findings;
    return findings.filter((finding) => finding.severity === severity);
  }, [findings, severity]);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Vulnerability List</h1>
        <p className="page-subtitle">
          Findings across services, endpoints, and exposed infrastructure.
        </p>
      </div>

      <div className="panel">
        <div className="panel-title">Filter</div>
        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          className="search-input"
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      {error ? <div className="panel">{error}</div> : null}
      {loading ? <div className="panel">Loading vulnerabilities...</div> : null}

      <div className="panel">
        <div className="panel-title">Findings</div>
        {filtered.length === 0 ? (
          <div className="empty">No findings found.</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Asset/Scan</th>
                <th>Detected</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 40).map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <span className={`pill ${finding.severity}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td>{finding.title}</td>
                  <td>{finding.asset_id || finding.scan_job_id || "--"}</td>
                  <td>{finding.created_at || "--"}</td>
                  <td>{finding.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
