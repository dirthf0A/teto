"use client";

import React, { useEffect, useState } from "react";

import Graph from "../components/Graph";
import { fetchJson } from "../lib/api";

export default function GraphPage() {
  const [targets, setTargets] = useState([]);
  const [selected, setSelected] = useState("");
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchJson("/targets")
      .then((data) => {
        setTargets(data);
        if (data.length > 0) {
          setSelected(String(data[0].id));
        }
      })
      .catch((err) => setError(err.message || "Failed to load targets"));
  }, []);

  useEffect(() => {
    if (!selected) {
      setGraph(null);
      return;
    }
    setLoading(true);
    setError("");
    fetchJson(`/graph?target_id=${selected}`)
      .then((data) => setGraph(data))
      .catch((err) => setError(err.message || "Failed to load graph"))
      .finally(() => setLoading(false));
  }, [selected]);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Attack Surface Graph</h1>
        <p className="page-subtitle">
          Domain to bucket relationships and discovery paths.
        </p>
      </div>

      <div className="panel">
        <div className="panel-title">Target</div>
        <select
          className="search-input"
          value={selected}
          onChange={(event) => setSelected(event.target.value)}
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
      {loading ? <div className="panel">Loading graph...</div> : null}

      <Graph graph={graph} />
    </div>
  );
}
