import "./globals.css";
import Link from "next/link";

export const metadata = {
  title: "ASM Dashboard",
  description: "Attack surface intelligence and risk monitoring"
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <div className="app-shell">
          <aside className="sidebar">
            <div className="brand">Teto ASM</div>
            <nav className="nav">
              <Link href="/">Attack Surface</Link>
              <Link href="/assets">Asset Inventory</Link>
              <Link href="/vulnerabilities">Vulnerabilities</Link>
              <Link href="/score">Surface Score</Link>
              <Link href="/history">Asset History</Link>
              <Link href="/ownership">Ownership</Link>
              <Link href="/monitoring">Monitoring</Link>
              <Link href="/js-discovery">JS Discovery</Link>
              <Link href="/graph">Attack Map</Link>
              <Link href="/risk-trend">Risk Dashboard</Link>
              <Link href="/report">Reports</Link>
            </nav>
          </aside>
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
