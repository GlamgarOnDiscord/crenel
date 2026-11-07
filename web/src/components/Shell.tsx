import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  LayoutGrid, ShieldAlert, Radar, FolderClosed, KeyRound, LockKeyhole,
  Plug, FileCheck2, BookOpen, Settings, Search,
} from "lucide-react";
import { Mark, Wordmark } from "../brand/Logo.tsx";
import { cn } from "../lib/cn.ts";
import { DOCS_URL } from "../lib/links.ts";
import { CommandPalette } from "./CommandPalette.tsx";

const nav = [
  { group: "Sécurité", items: [
    { to: "/app/overview", icon: LayoutGrid, label: "Vue d'ensemble" },
    { to: "/app/findings", icon: ShieldAlert, label: "Findings", count: 12 },
    { to: "/app/scans", icon: Radar, label: "Scans" },
    { to: "/app/targets", icon: FolderClosed, label: "Cibles", count: 3 },
  ]},
  { group: "Analyses", items: [
    { to: "/app/secrets", icon: KeyRound, label: "Secrets", count: 3 },
    { to: "/app/authz", icon: LockKeyhole, label: "Autorisation" },
    { to: "/app/tests", icon: FileCheck2, label: "Tests générés", count: 7 },
  ]},
  { group: "Réglages", items: [
    { to: "/app/integrations", icon: Plug, label: "Intégrations" },
    { to: "/app/settings", icon: Settings, label: "Paramètres" },
  ]},
];

export function Shell() {
  const [palette, setPalette] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const { pathname } = useLocation();
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((p) => !p); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  // Reset scroll to the top of the content on every route change, so a new page
  // does not open at the previous page's scroll offset.
  useEffect(() => { mainRef.current?.scrollTo(0, 0); }, [pathname]);
  return (
    <div className="app">
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
      <aside className="side">
        <NavLink to="/" className="brand"><Mark /><Wordmark /></NavLink>
        <button className="search" onClick={() => setPalette(true)}><Search size={15} /> Rechercher <span className="kbd">⌘K</span></button>
        {nav.map((g) => (
          <div key={g.group} className="navgroup">
            <div className="navlabel">{g.group}</div>
            {g.items.map((it) => (
              <NavLink key={it.to} to={it.to} className={({ isActive }) => cn("nav", isActive && "active")}>
                <it.icon size={16} /> {it.label}
                {it.count !== undefined && <span className="count">{it.count}</span>}
              </NavLink>
            ))}
          </div>
        ))}
        <div className="spacer" />
        <div className="foot">
          <a className="nav" href={DOCS_URL} target="_blank" rel="noopener noreferrer"><BookOpen size={16} /> Documentation</a>
        </div>
      </aside>
      <main className="main" ref={mainRef}><Outlet /></main>
    </div>
  );
}

export function Topbar({ crumb, title, actions }: { crumb?: string; title: string; actions?: React.ReactNode }) {
  // Keep the document title in sync with the page, so a route change is a real
  // navigation a screen reader announces (and browser history is legible).
  useEffect(() => { document.title = `${title} · Crenel`; }, [title]);
  return (
    <header className="topbar">
      <div>
        {crumb && <div className="crumb">{crumb}</div>}
        <h1>{title}</h1>
      </div>
      {actions && <div className="right">{actions}</div>}
    </header>
  );
}
