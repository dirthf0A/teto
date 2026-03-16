"use client";

import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

const AuthContext = createContext({ token: "", setToken: () => {} });

export function AuthProvider({ children }) {
  const [token, setTokenState] = useState("");

  useEffect(() => {
    const saved = localStorage.getItem("asm_token") || "";
    setTokenState(saved);
  }, []);

  const setToken = (value) => {
    setTokenState(value);
    localStorage.setItem("asm_token", value);
  };

  const value = useMemo(() => ({ token, setToken }), [token]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
