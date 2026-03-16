"use client";

import { useEffect, useState } from "react";

export default function TokenBar({ onLoad, loading }) {
  const [token, setToken] = useState("");

  useEffect(() => {
    const saved = window.localStorage.getItem("asm_token") || "";
    setToken(saved);
    if (saved) {
      onLoad(saved);
    }
  }, [onLoad]);

  function handleLoad() {
    window.localStorage.setItem("asm_token", token);
    onLoad(token);
  }

  return (
    <div className="token-bar">
      <input
        type="password"
        placeholder="Paste JWT token"
        value={token}
        onChange={(event) => setToken(event.target.value)}
      />
      <button onClick={handleLoad} disabled={!token || loading}>
        {loading ? "Loading..." : "Load Data"}
      </button>
    </div>
  );
}
