import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutGrid, ShieldAlert, Radar, FolderClosed, KeyRound, LockKeyhole,
  Plug, FileCheck2, BookOpen, Settings, Search,
} from "lucide-react";
import { Mark, Wordmark } from "../brand/Logo.tsx";
import { cn } from "../lib/cn.ts";

const nav = [
  { group: "Sécurité", items: [
    { to: "/app/overview", icon: LayoutGrid, label: "Vue d'ensemble" },
    { to: "/app/findings", icon: ShieldAlert, label: "Findings", count: 14 },
    { to: "/app/scans", icon: Radar, label: "Scans" },
    { to: "/app/targets", icon: FolderClosed, label: "Cibles", count: 3 },
  ]},
  { group: "Analyses", items: [
    { to: "/app/secrets", icon: KeyRound, label: "Secrets", count: 3 },
    { to: "/app/authz", icon: LockKeyhole, label: "Autorisation" },
    { to: "/app/tests", icon: FileCheck2, label: "Tests générés", count: 9 },
  ]},
  { group: "Réglages", items: [
    { to: "/app/integrations", icon: Plug, label: "Intégrations" },
    { to: "/app/settings", icon: Settings, label: "Paramètres" },
  ]},
];

export function Shell() {
  return (
    <div className="app">
      <aside className="side">
        <NavLink to="/" className="brand"><Mark /><Wordmark /></NavLink>
        <div className="search"><Search size={15} /> Rechercher <span className="kbd">⌘K</span></div>
        {nav.map((g) => (
          <div key={g.group}>
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
          <a className="nav" href="#/app/docs"><BookOpen size={16} /> Documentation</a>
        </div>
      </aside>
      <main className="main"><Outlet /></main>
    </div>
  );
}

export function Topbar({ crumb, title, actions }: { crumb?: string; title: string; actions?: React.ReactNode }) {
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
