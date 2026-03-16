"use client";

import React, { useEffect, useState } from "react";

import { useAuth } from "../components/AuthContext";
import { fetchJson } from "../lib/api";

export default function RiskTrendPage() {
  const { token } = useAuth();
  const [trend, setTrend] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    setError("");
    fetchJson("/dashboard/risk-trend", token)
      .then((data) => setTrend(data?.days || []))
      .catch((err) => setError(err.message || "Failed to load risk trend"))
      .finally(() => setLoading(false));
  }, [token]);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Risk Trend</h1>
        <p className="page-subtitle">
          Changes in average risk score over the last two weeks.
        </p>
      </div>

      {error ? <div className="panel">{error}</div> : null}
      {loading ? <div className="panel">Loading risk trend...</div> : null}

      <div className="panel">
        <div className="panel-title">Risk Over Time</div>
        {trend.length === 0 ? (
          <div className="empty">No trend data yet.</div>
        ) : (
          <div className="chart">
            {trend.map((day) => (
              <div className="chart-row" key={day.date}>
                <div style={{ width: 90 }}>{day.date}</div>
                <div className="chart-bar">
                  <div
                    className="chart-fill"
                    style={{ width: `${Math.min(100, day.avg_risk || 0)}%` }}
                  />
                </div>
                <div style={{ width: 50, textAlign: "right" }}>
                  {(day.avg_risk || 0).toFixed(1)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
