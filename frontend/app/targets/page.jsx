"use client";

import React, { useCallback, useEffect, useState } from "react";

import { fetchJson, postJson } from "../lib/api";

export default function TargetsPage() {
  const [targets, setTargets] = useState([]);
  const [domain, setDomain] = useState("");
  const [environment, setEnvironment] = useState("prod");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");

  const loadTargets = useCallback(() => {
    setLoading(true);
    setError("");
    fetchJson("/targets")
      .then((data) => setTargets(data))
      .catch((err) => setError(err.message || "Failed to load targets"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadTargets();
  }, [loadTargets]);

  const startScan = async (targetDomain, targetEnv) => {
    const trimmed = (targetDomain || "").trim();
    if (!trimmed) return;
    setStatus("Starting scan...");
    setError("");
    try {
      const response = await postJson("/scan/start", {
        domain: trimmed,
        environment: targetEnv || "prod",
      });
      setStatus(`Scan queued (#${response.job_id}) for ${trimmed}`);
      setDomain("");
      loadTargets();
    } catch (err) {
      setError(err.message || "Failed to start scan");
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Targets</h1>
        <p className="page-subtitle">
          Register domains and trigger discovery scans.
        </p>
      </div>

      <div className="panel">
        <div className="panel-title">Start Scan</div>
        <div className="form-row">
          <input
            className="search-input"
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
          />
          <select
            className="search-input"
            value={environment}
            onChange={(event) => setEnvironment(event.target.value)}
          >
            <option value="prod">prod</option>
            <option value="staging">staging</option>
            <option value="dev">dev</option>
          </select>
          <button
            className="primary-button"
            type="button"
            onClick={() => startScan(domain, environment)}
          >
            Start Scan
          </button>
        </div>
        {status ? <div className="status-meta">{status}</div> : null}
      </div>

      {error ? <div className="panel">{error}</div> : null}
      {loading ? <div className="panel">Loading targets...</div> : null}

      <div className="panel">
        <div className="panel-title">Registered Targets</div>
        {targets.length === 0 ? (
          <div className="empty">No targets yet.</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Environment</th>
                <th>Status</th>
                <th>Last Scan</th>
                <th>Latest Job</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {targets.map((target) => (
                <tr key={target.id}>
                  <td>{target.domain}</td>
                  <td>{target.environment || "--"}</td>
                  <td>{target.status || "--"}</td>
                  <td>{target.last_scanned_at || "--"}</td>
                  <td>{target.latest_job_status || "--"}</td>
                  <td>
                    <button
                      className="secondary-button"
                      type="button"
                      onClick={() => startScan(target.domain, target.environment)}
                    >
                      Start Scan
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
