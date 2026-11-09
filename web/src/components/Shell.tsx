import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import {
  ShieldAlert, ListTodo, FolderClosed, KeyRound, LockKeyhole,
  Plug, ShieldCheck, BookOpen, Settings, Search, Menu, X, ChevronsUpDown, Globe, FolderGit2, SquarePen, ChevronDown,
} from "lucide-react";
import { Mark, Wordmark } from "../brand/Logo.tsx";
import { cn } from "../lib/cn.ts";
import { DOCS_URL } from "../lib/links.ts";
import { WorkspaceProvider, useWorkspace } from "../lib/workspace.tsx";
import { useData, type Data } from "../data/api.ts";
import { CommandPalette } from "./CommandPalette.tsx";
import { Picker } from "./ui.tsx";
import { ToastProvider } from "./toast.tsx";
import { AnimatedBackground } from "./kit/animated-background.tsx";
import { Tooltip } from "./arc/tooltip/tooltip.tsx";

// Only what a founder opens every day stays visible: start a task, follow
// tasks, read proven findings, check what CI keeps out. The rest sits under a
// collapsed "Plus" group and stays one ⌘K away.
const navOf = ({ findings, guardedCount, tasks }: Data) => {
const proven = findings.filter((f) => f.state === "proven").length;
const waiting = tasks.filter((t) => t.status === "waiting" || t.status === "running").length;
return [
  { group: null, items: [
    { to: "/app/scans", icon: ListTodo, label: "Tâches", count: waiting || undefined },
    { to: "/app/findings", icon: ShieldAlert, label: "Findings", count: proven, danger: true },
    { to: "/app/tests", icon: ShieldCheck, label: "Tests gardés", count: guardedCount, guard: true },
  ]},
  { group: "Plus", collapsed: true, items: [
    { to: "/app/secrets", icon: KeyRound, label: "Secrets" },
    { to: "/app/authz", icon: LockKeyhole, label: "Autorisation" },
    { to: "/app/targets", icon: FolderClosed, label: "Cibles" },
    { to: "/app/integrations", icon: Plug, label: "Intégrations" },
  ]},
];
};

function TargetSwitcher() {
  const ws = useWorkspace();
  const { targets } = useData();
  const Icon = ws.target.kind === "repo" ? FolderGit2 : Globe;
  return (
    <Picker
      label="Cible active" value={ws.target.id} onChange={ws.setTargetId} className="tswitch" buttonClassName="tswitch-btn"
      options={targets.map((t) => ({
        value: t.id, label: t.name, desc: t.url,
        icon: t.kind === "repo" ? <FolderGit2 size={15} /> : <Globe size={15} />,
        aside: t.proven ? <span className="pop-badge">{t.proven}</span> : undefined,
      }))}
      footer={<Link to="/app/onboarding" className="pop-link">+ Ajouter une cible</Link>}
    >
      <span className="tswitch-ic"><Icon size={15} /></span>
      <span className="tswitch-tx"><span className="tswitch-n">{ws.target.name}</span><span className="tswitch-u">{ws.target.url}</span></span>
      <ChevronsUpDown size={14} className="faint" />
    </Picker>
  );
}

function NavGroup({ g }: { g: ReturnType<typeof navOf>[number] }) {
  const { pathname } = useLocation();
  const holds = g.items.some((it) => pathname.startsWith(it.to));
  const [open, setOpen] = useState(!("collapsed" in g && g.collapsed));
  const shown = open || holds;
  return (
    <div className="navgroup">
      {g.group && (
        <button type="button" className="navlabel" aria-expanded={shown} onClick={() => setOpen((o) => !o)} disabled={holds} title={holds ? "Contient la page ouverte" : undefined}>
          {g.group}<ChevronDown size={13} className={cn("navchev", !shown && "closed")} aria-hidden="true" />
        </button>
      )}
      {shown && (
        <AnimatedBackground enableHover className="navhover" transition={{ type: "spring", bounce: 0, duration: 0.3 }}>
          {g.items.map((it) => (
            <div key={it.to} data-id={it.to} className="navwrap">
              <NavLink to={it.to} className={({ isActive }) => cn("nav", isActive && "active")}>
                <it.icon size={16} aria-hidden="true" /> {it.label}
                {"count" in it && it.count !== undefined && (
                  <span className={cn("count t-badge", "danger" in it && it.danger && "danger", "guard" in it && it.guard && "guard")}>{it.count}</span>
                )}
              </NavLink>
            </div>
          ))}
        </AnimatedBackground>
      )}
    </div>
  );
}

function SideContent({ onSearch }: { onSearch: () => void }) {
  const data = useData();
  const nav = navOf(data);
  // Live: no accounts, a local server for one project. Demo: a demo identity.
  const me = data.live ? { name: data.project, role: "local, crenel serve" } : { name: "Tom", role: "démo" };
  return (
    <>
      <Link to="/" className="brand"><Mark size={28} /><Wordmark /></Link>
      <Tooltip content="Pages, cibles et actions" side="right"><button type="button" className="search" onClick={onSearch}><Search size={15} aria-hidden="true" /><span>Rechercher</span><span className="kbd">⌘K</span></button></Tooltip>
      <TargetSwitcher />
      <Link to="/app/overview" state={{ fresh: Date.now() }} className="nav newtask"><SquarePen size={16} aria-hidden="true" /> Nouvelle tâche</Link>
      {nav.map((g, gi) => <NavGroup key={gi} g={g} />)}
      <div className="spacer" />
      <div className="foot">
        <div className="me">
          <span className="av">{(me.name[0] ?? "C").toUpperCase()}</span><span className="me-tx"><span>{me.name}</span><span className="me-r">{me.role}</span></span>
          <span className="me-actions">
            <Tooltip content="Documentation"><a className="me-btn" href={DOCS_URL} target="_blank" rel="noopener noreferrer" aria-label="Documentation"><BookOpen size={15} aria-hidden="true" /></a></Tooltip>
            <Tooltip content="Paramètres"><NavLink to="/app/settings" className={({ isActive }) => cn("me-btn", isActive && "active")} aria-label="Paramètres"><Settings size={15} aria-hidden="true" /></NavLink></Tooltip>
          </span>
        </div>
      </div>
    </>
  );
}

function Drawer({ open, onClose, onSearch }: { open: boolean; onClose: () => void; onSearch: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.querySelector<HTMLElement>("button, a")?.focus();
    return () => prev?.focus?.();
  }, [open]);
  if (!open) return null;
  function onKey(e: React.KeyboardEvent) {
    if (e.key === "Escape") { e.preventDefault(); onClose(); return; }
    if (e.key === "Tab") {
      const els = ref.current?.querySelectorAll<HTMLElement>('a, button, [tabindex]:not([tabindex="-1"])');
      if (!els?.length) return;
      const first = els[0]!, last = els[els.length - 1]!;
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }
  return (
    <div className="drawer-overlay" onMouseDown={onClose}>
      <div ref={ref} className="drawer" role="dialog" aria-modal="true" aria-label="Menu" onMouseDown={(e) => e.stopPropagation()} onKeyDown={onKey}>
        <button type="button" className="drawer-close" aria-label="Fermer le menu" onClick={onClose}><X size={18} /></button>
        <SideContent onSearch={() => { onClose(); onSearch(); }} />
      </div>
    </div>
  );
}

export function Shell() {
  return <WorkspaceProvider><ToastProvider><ShellInner /></ToastProvider></WorkspaceProvider>;
}

function ShellInner() {
  const [palette, setPalette] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const { pathname } = useLocation();
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((p) => !p); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  // New page opens at the top, and the mobile drawer closes on navigation.
  useEffect(() => { mainRef.current?.scrollTo(0, 0); setDrawer(false); }, [pathname]);
  return (
    <div className="app">
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
      <aside className="side" aria-label="Navigation principale"><SideContent onSearch={() => setPalette(true)} /></aside>
      <header className="mbar">
        <Link to="/app/overview" className="brand"><Mark size={26} /><Wordmark /></Link>
        <span className="sp" />
        <button type="button" className="iconbtn" aria-label="Rechercher" onClick={() => setPalette(true)}><Search size={18} /></button>
        <button type="button" className="iconbtn" aria-label="Ouvrir le menu" aria-expanded={drawer} onClick={() => setDrawer(true)}><Menu size={19} /></button>
      </header>
      <Drawer open={drawer} onClose={() => setDrawer(false)} onSearch={() => setPalette(true)} />
      <main className="main" ref={mainRef} id="main"><div key={pathname} className="t-page">{<Outlet />}</div></main>
    </div>
  );
}

// Page header, two parts like the admin references: a thin sticky crumb bar
// (target, page, optional controls such as the period) and the page head
// (30 px title, one sentence that says the one thing that matters, actions).
// `scoped` prefixes the crumb with the active target. `width` matches the page
// head to a narrower `.content` so the actions line up with the cards below.
export function Topbar({ crumb, title, insight, actions, bar, scoped, compact, width }: {
  crumb?: string; title: string; insight?: React.ReactNode; actions?: React.ReactNode; bar?: React.ReactNode; scoped?: boolean; compact?: boolean; width?: "mid" | "narrow";
}) {
  const { target } = useWorkspace();
  useEffect(() => { document.title = `${title} · Crenel`; }, [title]);
  const parts = [scoped ? target.name : null, crumb].filter(Boolean) as string[];
  return (
    <>
      <div className="crumbbar">
        <nav className="crumbs" aria-label="Fil d'Ariane">
          {parts.map((p, i) => <span key={i} className="crumb">{p}</span>)}
          <span className={cn("crumb", "cur", compact && "clip")} aria-current="page">{title}</span>
        </nav>
        {(bar || (compact && actions)) && <div className="right">{bar}{compact && actions}</div>}
      </div>
      {!compact && (
        <header className={cn("pagehead", width)}>
          <div className="ph-l">
            <h1>{title}</h1>
            {insight && <p className="insight">{insight}</p>}
          </div>
          {actions && <div className="right">{actions}</div>}
        </header>
      )}
    </>
  );
}
