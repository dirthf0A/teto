"use client";

import React, { useMemo } from "react";

function normalizeLabel(node) {
  if (!node) return "";
  return node.label || `asset-${node.id}`;
}

export default function Graph({ graph }) {
  if (!graph || !graph.nodes?.length) {
    return <div className="panel empty">No graph data yet.</div>;
  }

  const nodes = graph.nodes;
  const links = graph.links || [];
  const size = 320;
  const radius = 120;
  const center = size / 2;
  const positions = useMemo(() => {
    const map = new Map();
    nodes.forEach((node, index) => {
      const angle = (2 * Math.PI * index) / nodes.length;
      const x = center + radius * Math.cos(angle);
      const y = center + radius * Math.sin(angle);
      map.set(node.id, { x, y });
    });
    return map;
  }, [nodes]);

  return (
    <div className="panel">
      <div className="panel-title">Asset Graph</div>
      <svg className="graph-svg" viewBox={`0 0 ${size} ${size}`}>
        {links.map((link, idx) => {
          const source = positions.get(link.source);
          const target = positions.get(link.target);
          if (!source || !target) return null;
          return (
            <line
              key={`${link.source}-${link.target}-${idx}`}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="rgba(33, 208, 162, 0.25)"
              strokeWidth="1.2"
            />
          );
        })}
        {nodes.map((node) => {
          const point = positions.get(node.id);
          if (!point) return null;
          return (
            <g key={node.id}>
              <circle cx={point.x} cy={point.y} r="6" fill="#21d0a2" />
              <text x={point.x + 10} y={point.y + 4} className="graph-label">
                {normalizeLabel(node)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
