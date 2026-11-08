import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight, Check, Copy, Eye, FileCode2, FlaskConical, Github, Hand, KeyRound, LayoutDashboard,
  ListChecks, Radar, ShieldCheck, Users, Zap,
} from "lucide-react";
import { Mark, Wordmark, Mascot } from "../brand/Logo.tsx";
import { Shimmer } from "../components/ai/shimmer.tsx";
import { REPO_URL, DOCS_URL } from "../lib/links.ts";
import "@fontsource/instrument-serif/latin-400.css";
import "@fontsource/instrument-serif/latin-400-italic.css";
import { BundleFigure, CiFigure, GateFigure, MatrixFigure, ProofBenchFigure } from "../components/iso/IsoFigures.tsx";
import "../styles/landing.css";
import "../styles/iso.css";

/* Landing page. Dark product page lit by an amber curtain of light: a hero
   with a framed console shot rising out of the beam, a marquee of the real
   checks, a "why" split card around the proof bench, a bento of what Crenel
   does (each card an interactive isometric figure, components/iso), the bench numbers as tiles, the method, and a closing card
   under the same curtain. Every number here is checked against the engine:
   42 checks in src/core/registry.ts, `node bench/run.mjs` → 27/27 flaws found,
   0/34 decoys flagged, on 23 cases. */

// The engine's real check list (src/core/registry.ts), grouped for reading.
const CHECK_GROUPS: { name: string; ids: string[] }[] = [
  { name: "Secrets", ids: ["exposed-secrets", "live-bundle", "public-env", "sourcemaps", "committed-env", "committed-credentials", "git-history"] },
  { name: "Autorisation", ids: ["authz-matrix", "authz-write", "auth-variants", "auth-config", "jwt-config", "baas-exposure", "supabase-rpc", "supabase-functions", "storage-buckets", "webhook-signature", "business-logic", "mass-assignment", "race"] },
  { name: "Site en ligne", ids: ["headers", "exposed-files", "graphql", "open-redirect", "next-middleware", "cache-deception", "dev-server", "ai-infra", "mcp-surface", "vercel-preview", "ssrf", "next-image", "cache-poisoning", "api-docs"] },
  { name: "Infra et DNS", ids: ["subdomain-takeover", "email-dns", "transport", "cloudflare-audit", "dockerfile"] },
  { name: "Chaîne d'appro.", ids: ["dependency-risk", "ci-hardening", "tls-verification"] },
];
const ALL_CHECKS = CHECK_GROUPS.flatMap((g) => g.ids);
const CHECK_COUNT = ALL_CHECKS.length;
const BENCH = { found: "27/27", decoys: "0/34", cases: 23 };
const INSTALL = "npx crenel scan";

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

// Fades sections in once as they enter the viewport (no-op without IO).
function useReveal() {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const root = ref.current;
    if (!root || typeof IntersectionObserver === "undefined") return;
    const els = root.querySelectorAll<HTMLElement>("[data-reveal]");
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    }, { rootMargin: "0px 0px -10% 0px" });
    els.forEach((el) => io.observe(el));
    root.classList.add("lx-armed");
    return () => io.disconnect();
  }, []);
  return ref;
}

// Pill badge flanked by two hairlines ending in a diamond.
function Badge({ children, icon }: { children: ReactNode; icon?: ReactNode }) {
  return (
    <span className="lx-badge">
      <i className="lx-badge-line l" aria-hidden="true" />
      <span className="lx-badge-pill">{icon}{children}</span>
      <i className="lx-badge-line r" aria-hidden="true" />
    </span>
  );
}

function InstallField() {
  const [done, setDone] = useState(false);
  useEffect(() => { if (!done) return; const t = setTimeout(() => setDone(false), 1600); return () => clearTimeout(t); }, [done]);
  async function copy() {
    try { await navigator.clipboard.writeText(INSTALL); } catch { /* clipboard blocked: the command stays selectable */ }
    setDone(true);
  }
  return (
    <div className="lx-install">
      <code className="mono"><span aria-hidden="true">$</span>{INSTALL}</code>
      <button type="button" className="lx-glossy" onClick={copy} aria-label={done ? "Commande copiée" : `Copier ${INSTALL}`}>
        {done ? <Check size={15} /> : <Copy size={15} />}<span>{done ? "Copié" : "Copier"}</span>
      </button>
      <span className="sr-only" aria-live="polite">{done ? "Copié dans le presse-papiers" : ""}</span>
    </div>
  );
}

// The console as the product shot: sidebar, the agent transcript, the proof.
function ConsoleShot() {
  return (
    <div className="lx-shot" aria-label="Aperçu de la console Crenel" role="img">
      <div className="lx-shot-glow" aria-hidden="true" />
      <div className="lx-app" aria-hidden="true">
        <aside className="lx-app-side">
          <div className="lx-app-brand"><Mark size={18} /><b>crenel</b></div>
          <div className="lx-app-search mono">Rechercher <kbd>⌘K</kbd></div>
          <span className="lx-app-h">Espace</span>
          <span className="lx-app-nav on"><LayoutDashboard size={13} />Vue d'ensemble</span>
          <span className="lx-app-nav"><Radar size={13} />Scans</span>
          <span className="lx-app-nav"><ShieldCheck size={13} />Failles<em>3</em></span>
          <span className="lx-app-nav"><Users size={13} />Autorisation</span>
          <span className="lx-app-nav"><FlaskConical size={13} />Tests</span>
          <span className="lx-app-h">Cibles</span>
          <span className="lx-app-nav"><i className="lx-dot a" />acme-app</span>
          <span className="lx-app-nav"><i className="lx-dot" />acme-staging</span>
        </aside>
        <main className="lx-app-main">
          <div className="lx-app-top">
            <span className="lx-crumb">Cibles / acme-app / <b>Agent</b></span>
            <span className="mode"><Eye size={12} />Lecture seule</span>
          </div>
          <div className="lx-app-body mono">
            <div className="u">› Scanne acme-app, et prouve ce que tu trouves</div>
            <div className="r"><i className="b" />scan.secrets <s>(bundle en ligne)</s></div>
            <div className="x"><span className="t crit">CRIT</span> sk_live_ dans assets/index-4f2a.js <span className="p">prouvé</span></div>
            <div className="r"><i className="b a" /><Shimmer>authz.matrix</Shimmer> <s>(compte A → objet de B)</s></div>
            <div className="lx-perm">Envoyer 4 GET à staging.acme.app ? <span className="on">Autoriser une fois</span><span>Toujours</span><span>Refuser</span></div>
            <div className="x"><span className="t high">HAUTE</span> GET /api/projects/proj_b_1 → 200 ×3 <span className="p">prouvé</span></div>
            <div className="x"><span className="g">gardé</span> 3 tests de régression prêts pour la CI</div>
          </div>
        </main>
        <aside className="lx-app-proof">
          <span className="lx-app-h">Preuve · authz.matrix</span>
          <div className="pf"><b>Propriétaire</b><span>B lit proj_b_1</span><em className="ok">200</em></div>
          <div className="pf hot"><b>Attaquant</b><span>A lit proj_b_1</span><em className="bad">200 ×3</em></div>
          <div className="pf"><b>Contrôle</b><span>sans session</span><em>401</em></div>
          <div className="pf-foot">Rejouable · <span className="mono">crenel replay f_7c2</span></div>
        </aside>
      </div>
      <div className="lx-scan" aria-hidden="true"><span className="lx-scan-chip mono">{CHECK_COUNT} checks</span></div>
    </div>
  );
}

function Marquee({ items, reverse }: { items: string[]; reverse?: boolean }) {
  return (
    <div className={`lx-marquee${reverse ? " rev" : ""}`} aria-hidden="true">
      <div className="lx-marquee-track">
        {[0, 1].map((k) => (
          <div className="lx-marquee-set" key={k}>
            {items.map((id) => <span className="lx-chip mono" key={id}><i />{id}</span>)}
          </div>
        ))}
      </div>
    </div>
  );
}

export function Landing() {
  useEffect(() => { document.title = "Crenel · prouvé, puis gardé"; }, []);
  const ref = useReveal();
  const half = Math.ceil(ALL_CHECKS.length / 2);
  return (
    <div className="lx" ref={ref}>
      <nav className="lx-nav" aria-label="Navigation du site">
        <Link to="/" className="brand"><Mark size={26} /><Wordmark /></Link>
        <div className="lx-links">
          <button type="button" onClick={() => scrollTo("pourquoi")}>Pourquoi</button>
          <button type="button" onClick={() => scrollTo("produit")}>Produit</button>
          <button type="button" onClick={() => scrollTo("banc")}>Banc</button>
          <button type="button" onClick={() => scrollTo("methode")}>Méthode</button>
          <a href={DOCS_URL} target="_blank" rel="noopener noreferrer">Docs</a>
        </div>
        <div className="lx-nav-cta">
          <a className="lx-btn dark hide-sm" href={REPO_URL} target="_blank" rel="noopener noreferrer"><Github size={14} />GitHub</a>
          <Link className="lx-btn light" to="/app/overview">Console</Link>
        </div>
      </nav>

      {/* ---------- Hero ---------- */}
      <header className="lx-hero">
        <div className="lx-curtain" aria-hidden="true"><i className="lx-pillar" /></div>
        <div className="lx-wrap lx-hero-in">
          <Badge><span className="lx-tag mono">MIT</span>Open source, lecture seule par défaut</Badge>
          <h1>Attaquez votre app<br /><span className="lx-serif">avant qu'on le fasse.</span></h1>
          <p className="lx-sub">Crenel cherche les secrets exposés et les failles d'autorisation entre comptes, prouve chacune par une requête rejouable, puis la garde en CI.</p>
          <div className="lx-hero-cta">
            <InstallField />
            <div className="lx-score">
              <div className="n"><ShieldCheck size={17} /><b>{BENCH.found}</b></div>
              <span>failles trouvées sur notre banc</span>
            </div>
          </div>
          <Link to="/app/overview" className="lx-textlink">Ouvrir la console <ArrowRight size={14} /></Link>
        </div>
        <div className="lx-wrap lx-hero-shot"><ConsoleShot /></div>
      </header>

      {/* ---------- Checks marquee ---------- */}
      <section className="lx-wrap lx-band" aria-label="Les checks">
        <p className="lx-band-l"><b>{CHECK_COUNT} checks déterministes,</b><br />du bundle servi jusqu'au DNS.</p>
        <div className="lx-band-r">
          <Marquee items={ALL_CHECKS.slice(0, half)} />
          <Marquee items={ALL_CHECKS.slice(half)} reverse />
        </div>
      </section>

      {/* ---------- Why ---------- */}
      <section id="pourquoi" className="lx-wrap lx-sec" aria-labelledby="w-t">
        <div className="lx-head c" data-reveal>
          <span className="lx-chip-badge"><Mark size={16} />Pourquoi Crenel</span>
          <h2 id="w-t" className="lx-serif-h">Trois cents alertes,<br />aucune preuve,<br />plus aucune confiance.</h2>
        </div>
        <div className="lx-why" data-reveal>
          <div className="lx-why-art"><ProofBenchFigure /></div>
          <div className="lx-why-copy">
            <span className="lx-why-mark"><Mark size={44} /></span>
            <h3>Pourquoi Crenel</h3>
            <p>Les scanners classiques empilent des alertes que personne ne peut trier. Crenel ne retient une faille que <b>si elle se rejoue</b> : le propriétaire, l'attaquant, puis un contrôle négatif. Le reste reste une piste, et le dit.</p>
            <p>Une fois prouvée, la faille devient un test. Elle ne revient plus sans casser le build.</p>
            <button type="button" className="lx-btn light lx-lg" onClick={() => scrollTo("methode")}>Voir la méthode <ArrowRight size={15} /></button>
          </div>
        </div>
      </section>

      {/* ---------- Bento ---------- */}
      <section id="produit" className="lx-wrap lx-sec" aria-labelledby="p-t">
        <div className="lx-head c" data-reveal>
          <span className="lx-kicker">Crenel, dans votre terminal et votre CI, pour…</span>
          <h2 id="p-t">Passer d'une liste d'alertes<br />à des failles prouvées.</h2>
        </div>
        <div className="lx-bento">
          <article className="lx-card" data-reveal>
            <BundleFigure />
            <p className="lx-card-t"><b>Le bundle relu, chunk par chunk.</b> Chaque fichier JS servi est lu, source maps comprises. Une clé n'est vérifiée en direct que si vous l'autorisez.</p>
          </article>
          <article className="lx-card" data-reveal>
            <MatrixFigure />
            <p className="lx-card-t"><b>Autorisation entre comptes.</b> Chaque objet de B lu par A, par C et sans session. Un 200 qui ne devrait pas l'être est une faille, rejouée avant d'être signalée.</p>
          </article>
          <article className="lx-card" data-reveal>
            <GateFigure />
            <p className="lx-card-t"><b>Vous gardez la main.</b> Une question avant chaque sonde réseau, sur les seuls hôtes déclarés. Chaque envoi est écrit dans un journal chaîné.</p>
          </article>
          <article className="lx-card" data-reveal>
            <CiFigure />
            <p className="lx-card-t"><b>Gardé en CI.</b> Chaque preuve devient un test de régression. Sans correctif, le build reste rouge.</p>
          </article>
        </div>
      </section>

      {/* ---------- Bench tiles ---------- */}
      <section id="banc" className="lx-wrap lx-sec lx-bench" aria-labelledby="b-t">
        <div className="lx-bench-copy" data-reveal>
          <h2 id="b-t">Mesuré sur un banc,<br />ratés compris.</h2>
          <p>{BENCH.cases} cibles multi-tenant avec la vérité terrain : des failles réelles à trouver, et des leurres qui doivent rester muets. <span className="mono">node bench/run.mjs</span> rejoue tout.</p>
          <a className="lx-textlink" href={`${REPO_URL}/tree/main/bench`} target="_blank" rel="noopener noreferrer">Voir le banc <ArrowRight size={14} /></a>
        </div>
        <div className="lx-tiles" data-reveal>
          <div className="tile hot"><b>{BENCH.found}</b><span>failles trouvées</span></div>
          <div className="tile"><b>{BENCH.decoys}</b><span>leurres signalés à tort</span></div>
          <div className="tile"><b>{CHECK_COUNT}</b><span>checks déterministes</span></div>
          <div className="tile"><b>{BENCH.cases}</b><span>cibles de test</span></div>
          <div className="tile"><b>GET</b><span>par défaut, imposé par le client HTTP</span></div>
          <div className="tile"><b>MIT</b><span>code ouvert, rien à cacher</span></div>
        </div>
      </section>

      {/* ---------- Method ---------- */}
      <section id="methode" className="lx-wrap lx-sec" aria-labelledby="m-t">
        <div className="lx-head c" data-reveal>
          <Badge>Notre méthode</Badge>
          <h2 id="m-t">Détecter, prouver, <span className="lx-serif">garder.</span></h2>
        </div>
        <ol className="lx-steps">
          {[
            { n: "01", icon: <Radar size={16} />, t: "Détecter", p: "Bundle servi, dépôt, historique git, dépendances, CI, en-têtes, DNS.", c: "npx crenel scan" },
            { n: "02", icon: <KeyRound size={16} />, t: "Prouver", p: "Propriétaire, attaquant, contrôle négatif. Sans rejeu, ce n'est qu'une piste.", c: "A lit proj_b_1 → 200 (×3)" },
            { n: "03", icon: <ShieldCheck size={16} />, t: "Garder", p: "La preuve devient un test. La faille ne revient plus sans casser le build.", c: "✓ A ne lit pas le projet de B", g: true },
          ].map((s) => (
            <li key={s.n} data-reveal>
              <div className="lx-hd"><span className="ic">{s.icon}</span><span className="mono n">{s.n}</span></div>
              <h3>{s.t}</h3>
              <p>{s.p}</p>
              <code className={`mono${s.g ? " g" : ""}`}>{s.c}</code>
            </li>
          ))}
        </ol>
        <div className="lx-modes" data-reveal>
          <div><Hand size={15} /><b>Demander</b><span>Une question avant chaque sonde réseau.</span></div>
          <div><Eye size={15} /><b>Lecture seule</b><span>Code et bundle seulement.</span></div>
          <div><Zap size={15} /><b>Bypass</b><span>Tout le périmètre, pour la CI.</span></div>
          <div><FileCode2 size={15} /><b>Journal chaîné</b><span>Chaque action est écrite.</span></div>
        </div>
        <details className="lx-all" data-reveal>
          <summary><ListChecks size={15} />Voir les {CHECK_COUNT} checks</summary>
          <div className="lx-groups">
            {CHECK_GROUPS.map((g) => (
              <div key={g.name}>
                <h4>{g.name} <span>{g.ids.length}</span></h4>
                <ul>{g.ids.map((id) => <li key={id} className="mono">{id}</li>)}</ul>
              </div>
            ))}
          </div>
        </details>
      </section>

      {/* ---------- Final CTA ---------- */}
      <section className="lx-wrap lx-final-wrap">
        <div className="lx-final" data-reveal>
          <div className="lx-curtain small" aria-hidden="true" />
          <Mascot size={84} mood="hello" />
          <h2>Lancez votre <span className="lx-serif">premier scan.</span></h2>
          <p>Deux minutes, en local, sur une app à vous.</p>
          <div className="lx-final-cta">
            <Link className="lx-btn light lx-lg" to="/app/onboarding">Ajouter une cible <ArrowRight size={15} /></Link>
            <a className="lx-btn dark lx-lg" href={DOCS_URL} target="_blank" rel="noopener noreferrer">Lire la doc</a>
          </div>
        </div>
      </section>

      <footer className="lx-wrap lx-foot">
        <div className="lx-foot-cols">
          <div className="lx-foot-brand"><Mark size={22} /><span>Prouvé, puis gardé.<br />Un outil indépendant, sous licence MIT.</span></div>
          <div><h4>Produit</h4><button type="button" onClick={() => scrollTo("produit")}>Fonctionnalités</button><button type="button" onClick={() => scrollTo("banc")}>Banc</button><Link to="/app/overview">Console</Link></div>
          <div><h4>Ressources</h4><a href={DOCS_URL} target="_blank" rel="noopener noreferrer">Docs</a><a href={`${REPO_URL}/tree/main/bench`} target="_blank" rel="noopener noreferrer">Banc</a><a href={REPO_URL} target="_blank" rel="noopener noreferrer">GitHub</a></div>
          <div><h4>Démarrer</h4><Link to="/app/onboarding">Ajouter une cible</Link><button type="button" onClick={() => scrollTo("methode")}>Méthode</button></div>
        </div>
        <div className="lx-giant" aria-hidden="true">crenel</div>
        <div className="lx-foot-bot"><span>crenel · MIT · outil indépendant</span><span className="sp" /><a href={REPO_URL} target="_blank" rel="noopener noreferrer"><Github size={14} /></a></div>
      </footer>
    </div>
  );
}
