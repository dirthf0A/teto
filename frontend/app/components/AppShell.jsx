"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React from "react";

function TopBar() {
  const pathname = usePathname();

  const links = [
    { href: "/targets", label: "Targets" },
    { href: "/assets", label: "Assets" },
    { href: "/vulnerabilities", label: "Vulnerabilities" },
    { href: "/graph", label: "Graph" },
  ];

  return (
    <header className="top-bar">
      <div className="brand">Teto ASM</div>
      <nav className="nav-links">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className={pathname === link.href ? "active" : undefined}
          >
            {link.label}
          </Link>
        ))}
      </nav>
    </header>
  );
}

export default function AppShell({ children }) {
  return (
    <div className="app-shell">
      <TopBar />
      {children}
    </div>
  );
}
