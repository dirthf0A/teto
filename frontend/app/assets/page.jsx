"use client";

import React, { useEffect, useMemo, useState } from "react";

import { fetchJson } from "../lib/api";

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [targets, setTargets] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError("");
    fetchJson("/targets")
      .then((targetData) => {
        setTargets(targetData);
        if (targetData.length > 0) {
          setSelectedTarget(String(targetData[0].id));
        }
      })
      .catch((err) => setError(err.message || "Failed to load targets"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const targetParam = selectedTarget ? `?target_id=${selectedTarget}` : "";
    fetchJson(`/assets${targetParam}`)
      .then((data) => setAssets(data))
      .catch((err) => setError(err.message || "Failed to load assets"));
  }, [selectedTarget]);

  const filtered = useMemo(() => {
    if (!query) return assets;
    const lower = query.toLowerCase();
    return assets.filter((asset) => {
      const label =
        asset.url ||
        asset.subdomain ||
        asset.domain ||
        asset.ip ||
        `asset-${asset.id}`;
      return label.toLowerCase().includes(lower);
    });
  }, [assets, query]);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Asset Inventory</h1>
        <p className="page-subtitle">
          All tracked domains, subdomains, IPs, and services in one view.
        </p>
      </div>

      <div className="panel">
        <div className="panel-title">Search</div>
        <input
          className="search-input"
          type="text"
          placeholder="Filter by hostname, IP, or URL"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>

      <div className="panel">
        <div className="panel-title">Target</div>
        <select
          className="search-input"
          value={selectedTarget}
          onChange={(event) => setSelectedTarget(event.target.value)}
        >
          {targets.length === 0 ? (
            <option value="">No targets</option>
          ) : (
            targets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.domain}
              </option>
            ))
          )}
        </select>
      </div>

      {error ? <div className="panel">{error}</div> : null}
      {loading ? <div className="panel">Loading assets...</div> : null}

      <div className="panel">
        <div className="panel-title">Assets</div>
        {filtered.length === 0 ? (
          <div className="empty">No assets found.</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Type</th>
                <th>IP</th>
                <th>Port</th>
                <th>Tech</th>
                <th>Exposure</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 40).map((asset) => (
                <tr key={asset.id}>
                  <td>
                    {asset.url ||
                      asset.subdomain ||
                      asset.domain ||
                      asset.ip ||
                      `asset-${asset.id}`}
                  </td>
                  <td>{asset.asset_type || "--"}</td>
                  <td>{asset.ip || "--"}</td>
                  <td>
                    {asset.port
                      ? `${asset.port}/${asset.protocol || "tcp"}`
                      : "--"}
                  </td>
                  <td>{asset.technology || "--"}</td>
                  <td>{asset.exposure_class || "--"}</td>
                  <td>{asset.risk_score ?? "--"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
