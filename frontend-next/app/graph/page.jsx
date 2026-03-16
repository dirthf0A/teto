"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import TokenBar from "../_components/TokenBar";
import { fetchJson } from "../_lib/api";

/* ─── Color constants ───────────────────────────────────────────────────── */
const TYPE_COLOR = {
  domain:          { fill:"#6366f1", stroke:"#818cf8" },
  subdomain:       { fill:"#0ea5e9", stroke:"#38bdf8" },
  ip:              { fill:"#10b981", stroke:"#34d399" },
  service:         { fill:"#f59e0b", stroke:"#fbbf24" },
  endpoint:        { fill:"#8b5cf6", stroke:"#a78bfa" },
  cloud:           { fill:"#ef4444", stroke:"#f87171" },
  external_domain: { fill:"#94a3b8", stroke:"#cbd5e1" },
};
const EXP_GLOW = { public:"#ef444460", vpn:"#f9731640", internal:"transparent" };
const RISK_BORDER = (r) => r >= 75 ? "#ef4444" : r >= 50 ? "#f97316" : r >= 25 ? "#eab308" : "transparent";

/* ─── Force-directed layout engine ─────────────────────────────────────── */
function forceLayout(nodes, edges, iterations = 180) {
  const W = 960, H = 680;
  const k  = Math.sqrt((W * H) / Math.max(nodes.length, 1));
  const kk = k * 1.4;

  // Initialise positions on a circle with jitter
  nodes.forEach((n, i) => {
    const angle = (i / nodes.length) * Math.PI * 2;
    n.x = W / 2 + (W * 0.35) * Math.cos(angle) + (Math.random() - 0.5) * 40;
    n.y = H / 2 + (H * 0.35) * Math.sin(angle) + (Math.random() - 0.5) * 40;
    n.vx = 0; n.vy = 0;
  });

  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
  const temp0 = kk * 1.5;

  for (let iter = 0; iter < iterations; iter++) {
    const temp = temp0 * (1 - iter / iterations);
    nodes.forEach(n => { n.dx = 0; n.dy = 0; });

    // Repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x || 0.01;
        const dy = nodes[i].y - nodes[j].y || 0.01;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const force = (kk * kk) / dist;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        nodes[i].dx += fx; nodes[i].dy += fy;
        nodes[j].dx -= fx; nodes[j].dy -= fy;
      }
    }

    // Attraction (edges)
    edges.forEach(e => {
      const s = nodeById[e.source];
      const t = nodeById[e.target];
      if (!s || !t) return;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const force = (dist * dist) / kk;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      s.dx += fx; s.dy += fy;
      t.dx -= fx; t.dy -= fy;
    });

    // Apply + clamp
    nodes.forEach(n => {
      const len = Math.sqrt(n.dx * n.dx + n.dy * n.dy) || 0.01;
      const clamped = Math.min(len, temp);
      n.x += (n.dx / len) * clamped;
      n.y += (n.dy / len) * clamped;
      n.x = Math.max(24, Math.min(W - 24, n.x));
      n.y = Math.max(24, Math.min(H - 24, n.y));
    });
  }
  return nodes;
}

/* ─── Main component ────────────────────────────────────────────────────── */
export default function AttackSurfaceMapPage() {
  const canvasRef     = useRef(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");
  const [rawData, setRawData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter]     = useState("all");
  const [showLabels, setShowLabels] = useState(true);
  const [hoveredId, setHoveredId] = useState(null);
  const nodesRef  = useRef([]);
  const edgesRef  = useRef([]);
  const animRef   = useRef(null);
  const scaleRef  = useRef(1);
  const offsetRef = useRef({ x: 0, y: 0 });
  const dragRef   = useRef(null);

  const loadData = useCallback(async (token) => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const data = await fetchJson("/dashboard/graph", token);
      setRawData(data);
    } catch (err) {
      setError(err.message || "Failed to load graph");
    } finally {
      setLoading(false);
    }
  }, []);

  /* Layout + draw */
  useEffect(() => {
    if (!rawData || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx    = canvas.getContext("2d");

    let nodes = (rawData.nodes || []).filter(n =>
      filter === "all" || n.type === filter ||
      (filter === "public"   && n.exposure_class === "public") ||
      (filter === "high-risk" && (n.risk_score || 0) >= 50)
    ).map(n => ({ ...n }));

    const nodeIds = new Set(nodes.map(n => n.id));
    const edges = (rawData.links || []).filter(
      e => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    // Limit for performance
    if (nodes.length > 400) nodes = nodes.slice(0, 400);

    forceLayout(nodes, edges, nodes.length > 150 ? 100 : 180);
    nodesRef.current = nodes;
    edgesRef.current = edges;

    function draw() {
      const W = canvas.width, H = canvas.height;
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.translate(offsetRef.current.x, offsetRef.current.y);
      ctx.scale(scaleRef.current, scaleRef.current);

      const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));

      // Edges
      edges.forEach(e => {
        const s = nodeById[e.source], t = nodeById[e.target];
        if (!s || !t) return;
        const isHovered = hoveredId === s.id || hoveredId === t.id;
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        ctx.strokeStyle = isHovered ? "rgba(148,163,184,0.5)" : "rgba(148,163,184,0.12)";
        ctx.lineWidth   = isHovered ? 1.5 : 0.8;
        ctx.stroke();
      });

      // Nodes
      nodes.forEach(n => {
        const col    = TYPE_COLOR[n.type] || TYPE_COLOR.subdomain;
        const r      = n.type === "domain" ? 14 : n.type === "subdomain" ? 9 : 7;
        const isHov  = hoveredId === n.id;
        const isSel  = selected?.id === n.id;

        // Glow for public / high-risk
        if (n.exposure_class === "public" || (n.risk_score || 0) >= 50) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
          const grd = ctx.createRadialGradient(n.x, n.y, r, n.x, n.y, r + 6);
          grd.addColorStop(0, n.exposure_class === "public" ? "rgba(239,68,68,0.25)" : "rgba(249,115,22,0.2)");
          grd.addColorStop(1, "transparent");
          ctx.fillStyle = grd;
          ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, isSel ? r + 3 : isHov ? r + 2 : r, 0, Math.PI * 2);
        ctx.fillStyle   = col.fill;
        ctx.fill();

        // Risk border ring
        const rb = RISK_BORDER(n.risk_score || 0);
        if (rb !== "transparent" || isSel) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, r + (isSel ? 5 : 3), 0, Math.PI * 2);
          ctx.strokeStyle = isSel ? "#fff" : rb;
          ctx.lineWidth   = isSel ? 2 : 1.5;
          ctx.stroke();
        }

        // Labels
        if (showLabels && (isHov || isSel || scaleRef.current > 0.8 || n.type === "domain")) {
          const lbl = n.label?.length > 28 ? n.label.slice(0, 28) + "…" : (n.label || "");
          ctx.font      = `${isSel || isHov ? 500 : 400} ${isSel ? 11 : 10}px 'Space Grotesk', sans-serif`;
          ctx.fillStyle = isSel ? "#ffffff" : isHov ? "#e2e8f0" : "#94a3b8";
          ctx.textAlign = "center";
          ctx.fillText(lbl, n.x, n.y + r + 13);
        }
      });

      ctx.restore();
    }

    function loop() {
      draw();
      animRef.current = requestAnimationFrame(loop);
    }
    if (animRef.current) cancelAnimationFrame(animRef.current);
    loop();
    return () => cancelAnimationFrame(animRef.current);
  }, [rawData, filter, showLabels, hoveredId, selected]);

  /* Mouse interactions */
  function screenToWorld(canvas, cx, cy) {
    const rect = canvas.getBoundingClientRect();
    const sx = (cx - rect.left - offsetRef.current.x) / scaleRef.current;
    const sy = (cy - rect.top  - offsetRef.current.y) / scaleRef.current;
    return { x: sx, y: sy };
  }

  function findNode(wx, wy) {
    const r2 = 18 * 18;
    return nodesRef.current.find(n => {
      const dx = n.x - wx, dy = n.y - wy;
      return dx*dx + dy*dy < r2;
    });
  }

  function onMouseMove(e) {
    const canvas = canvasRef.current;
    if (dragRef.current) {
      offsetRef.current = {
        x: offsetRef.current.x + e.movementX,
        y: offsetRef.current.y + e.movementY,
      };
      return;
    }
    const { x, y } = screenToWorld(canvas, e.clientX, e.clientY);
    const n = findNode(x, y);
    setHoveredId(n?.id ?? null);
    canvas.style.cursor = n ? "pointer" : "grab";
  }

  function onClick(e) {
    const canvas = canvasRef.current;
    const { x, y } = screenToWorld(canvas, e.clientX, e.clientY);
    const n = findNode(x, y);
    setSelected(n || null);
  }

  function onWheel(e) {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 1.12 : 0.89;
    scaleRef.current = Math.min(4, Math.max(0.2, scaleRef.current * delta));
  }

  const typeOptions = ["all", "domain", "subdomain", "ip", "service", "endpoint", "cloud", "public", "high-risk"];
  const typeCount   = rawData ? Object.entries(
    (rawData.nodes||[]).reduce((acc,n)=>{ acc[n.type]=(acc[n.type]||0)+1; return acc; }, {})
  ) : [];

  return (
    <>
      <section className="hero">
        <h1>Attack Surface Map</h1>
        <p>Force-directed graph of your attack surface. Drag to pan, scroll to zoom, click nodes to inspect.</p>
        <TokenBar onLoad={loadData} loading={loading} />
        {error && <p className="empty">{error}</p>}
      </section>

      {/* Legend + controls */}
      <div style={{ display:"flex", gap:10, marginBottom:12, flexWrap:"wrap", alignItems:"center" }}>
        {Object.entries(TYPE_COLOR).slice(0,6).map(([type,col]) => (
          <div key={type} style={{ display:"flex", alignItems:"center", gap:5, fontSize:"0.76rem", color:"#94a3b8" }}>
            <div style={{ width:10, height:10, borderRadius:"50%", background:col.fill }}/>
            {type}
          </div>
        ))}
        <div style={{ display:"flex", alignItems:"center", gap:5, fontSize:"0.76rem", color:"#94a3b8" }}>
          <div style={{ width:10, height:10, borderRadius:"50%", background:"transparent", border:"1.5px solid #ef4444" }}/>
          public/risky
        </div>
      </div>

      <div style={{ display:"flex", gap:10, marginBottom:12, flexWrap:"wrap" }}>
        {["all","domain","subdomain","ip","service","endpoint","cloud","public","high-risk"].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            padding:"5px 12px", borderRadius:20, fontSize:"0.78rem", cursor:"pointer",
            border: filter===f ? `1px solid #6366f1` : "1px solid rgba(148,163,184,0.2)",
            background: filter===f ? "rgba(99,102,241,0.2)" : "transparent",
            color: filter===f ? "#a5b4fc" : "#94a3b8",
          }}>{f}</button>
        ))}
        <button onClick={() => setShowLabels(v => !v)} style={{
          padding:"5px 12px", borderRadius:20, fontSize:"0.78rem", cursor:"pointer",
          border:"1px solid rgba(148,163,184,0.2)",
          background: showLabels ? "rgba(148,163,184,0.1)" : "transparent",
          color:"#94a3b8",
          marginLeft:"auto",
        }}>{showLabels ? "Hide" : "Show"} Labels</button>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 280px", gap:16 }}>
        {/* Canvas */}
        <div style={{ position:"relative", borderRadius:16, overflow:"hidden", background:"rgba(11,18,32,0.8)", border:"1px solid rgba(148,163,184,0.15)" }}>
          <canvas
            ref={canvasRef}
            width={960} height={600}
            style={{ display:"block", width:"100%", height:"auto", cursor:"grab" }}
            onMouseMove={onMouseMove}
            onClick={onClick}
            onMouseDown={() => { dragRef.current = true; }}
            onMouseUp={() => { dragRef.current = false; }}
            onMouseLeave={() => { dragRef.current = false; setHoveredId(null); }}
            onWheel={onWheel}
          />
          {rawData && (
            <div style={{ position:"absolute", top:10, left:10, fontSize:"0.72rem", color:"#475569",
              background:"rgba(11,18,32,0.8)", padding:"4px 10px", borderRadius:8 }}>
              {nodesRef.current.length} nodes · {edgesRef.current.length} edges
            </div>
          )}
          {!rawData && !loading && (
            <div style={{ position:"absolute", inset:0, display:"flex", alignItems:"center", justifyContent:"center", color:"#475569" }}>
              Load data to visualize your attack surface
            </div>
          )}
        </div>

        {/* Side panel */}
        <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
          {/* Type breakdown */}
          {typeCount.length > 0 && (
            <div className="panel" style={{ padding:"14px 16px" }}>
              <div style={{ fontSize:"0.72rem", fontWeight:600, color:"#64748b", textTransform:"uppercase", letterSpacing:"0.05em", marginBottom:10 }}>Asset Types</div>
              {typeCount.sort((a,b)=>b[1]-a[1]).slice(0,8).map(([type,count]) => {
                const col = TYPE_COLOR[type]?.fill || "#64748b";
                const total = rawData?.nodes?.length || 1;
                return (
                  <div key={type} style={{ marginBottom:7 }}>
                    <div style={{ display:"flex", justifyContent:"space-between", fontSize:"0.75rem", marginBottom:3 }}>
                      <span style={{ color:"#94a3b8" }}>{type}</span>
                      <span style={{ color:col, fontWeight:600 }}>{count}</span>
                    </div>
                    <div style={{ height:5, borderRadius:999, background:"rgba(148,163,184,0.1)" }}>
                      <div style={{ height:"100%", width:`${(count/total)*100}%`, background:col, borderRadius:999 }}/>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Selected node detail */}
          {selected ? (
            <div className="panel" style={{ padding:"14px 16px" }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:10 }}>
                <div style={{ fontSize:"0.72rem", fontWeight:600, color:"#64748b", textTransform:"uppercase", letterSpacing:"0.05em" }}>Node Detail</div>
                <button onClick={() => setSelected(null)} style={{
                  padding:"2px 8px", borderRadius:6, border:"none",
                  background:"rgba(148,163,184,0.15)", color:"#94a3b8", cursor:"pointer", fontSize:"0.75rem",
                }}>✕</button>
              </div>
              <div style={{ fontFamily:"monospace", fontSize:"0.8rem", color:"#e2e8f0", wordBreak:"break-all", marginBottom:10 }}>
                {selected.label}
              </div>
              {[
                ["Type",     selected.type,     TYPE_COLOR[selected.type]?.fill || "#94a3b8"],
                ["Exposure", selected.exposure_class, EXP_COLOR[selected.exposure_class] || "#94a3b8"],
                ["Risk Score", selected.risk_score?.toFixed(1) ?? "—", RISK_BORDER(selected.risk_score||0) !== "transparent" ? RISK_BORDER(selected.risk_score||0) : "#94a3b8"],
                ["IP",        selected.ip || "—",         "#64748b"],
                ["Port",      selected.port || "—",       "#64748b"],
                ["Technology",selected.technology || "—", "#64748b"],
              ].map(([k,v,c]) => (
                <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:"1px solid rgba(148,163,184,0.08)", fontSize:"0.76rem" }}>
                  <span style={{ color:"#475569" }}>{k}</span>
                  <span style={{ color:c, fontWeight:500, maxWidth:130, textAlign:"right", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="panel" style={{ padding:"14px 16px", textAlign:"center" }}>
              <div style={{ fontSize:"1.5rem", marginBottom:8 }}>🖱️</div>
              <div style={{ fontSize:"0.78rem", color:"#475569" }}>Click a node to inspect</div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
