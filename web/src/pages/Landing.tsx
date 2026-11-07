import { useEffect } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, Github, KeyRound, Users, Database, Package, FileWarning, ShieldCheck, Hand, Eye, Zap } from "lucide-react";
import { Mark, Wordmark, Mascot } from "../brand/Logo.tsx";
import { Button, CopyButton } from "../components/ui.tsx";
import { Tooltip } from "../components/arc/tooltip/tooltip.tsx";
import { Shimmer } from "../components/ai/shimmer.tsx";
import { REPO_URL, DOCS_URL } from "../lib/links.ts";
import "../styles/landing.css";

// The engine's real check list (src/core/registry.ts), grouped for reading.
const CHECK_GROUPS: { name: string; ids: string[] }[] = [
  { name: "Secrets", ids: ["exposed-secrets", "live-bundle", "public-env", "sourcemaps", "committed-env", "committed-credentials", "git-history"] },
  { name: "Autorisation", ids: ["authz-matrix", "auth-variants", "auth-config", "jwt-config", "baas-exposure", "supabase-rpc", "supabase-functions", "storage-buckets", "webhook-signature", "business-logic"] },
  { name: "Site en ligne", ids: ["headers", "exposed-files", "graphql", "open-redirect", "next-middleware", "cache-deception", "dev-server", "ai-infra", "mcp-surface", "vercel-preview", "ssrf", "next-image", "cache-poisoning", "api-docs"] },
  { name: "Infra et DNS", ids: ["subdomain-takeover", "email-dns", "transport", "cloudflare-audit", "dockerfile"] },
  { name: "Chaîne d'appro.", ids: ["dependency-risk", "ci-hardening", "tls-verification"] },
];
const CHECK_COUNT = CHECK_GROUPS.reduce((n, g) => n + g.ids.length, 0);

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

function Eyebrow({ n, children }: { n: string; children: string }) {
  return <span className="ln-eyebrow mono">[{n} / {children}]</span>;
}

export function Landing() {
  useEffect(() => { document.title = "Crenel · prouvé, puis gardé"; }, []);
  return (
    <div className="lp ln">
      <div className="ln-beam" aria-hidden="true" />

      <nav className="ln-nav" aria-label="Navigation du site">
        <Link to="/" className="brand"><Mark size={26} /><Wordmark /></Link>
        <div className="ln-links hide-sm">
          <button type="button" onClick={() => scrollTo("methode")}>Méthode</button>
          <button type="button" onClick={() => scrollTo("couverture")}>Couverture</button>
          <button type="button" onClick={() => scrollTo("controle")}>Contrôle</button>
          <a href={DOCS_URL} target="_blank" rel="noopener noreferrer">Docs</a>
        </div>
        <Button to="/app/overview" size="sm">Console <ArrowRight size={14} /></Button>
      </nav>

      <header className="ln-hero ln-wrap">
        <a className="ln-pill" href={REPO_URL} target="_blank" rel="noopener noreferrer">
          <span className="ln-pill-tag">MIT</span> Open source, lecture seule par défaut <ArrowRight size={13} />
        </a>
        <h1>Attaquez votre app<br /><span className="ln-dim"><em>avant</em> qu'on le fasse.</span></h1>
        <p className="ln-sub">Crenel cherche les secrets exposés et les failles d'autorisation entre comptes, prouve chacune par une requête rejouable, puis la garde en CI.</p>
        <div className="ln-cta">
          <Button to="/app/overview">Ouvrir la console <ArrowRight size={15} /></Button>
          <Button href={REPO_URL} variant="ghost"><Github size={15} /> GitHub</Button>
        </div>
        <div className="ln-install">
          <code><span aria-hidden="true">$</span> npx crenel scan</code>
          <Tooltip content="Copier la commande"><span><CopyButton text="npx crenel scan" /></span></Tooltip>
        </div>
      </header>

      <section className="ln-wrap ln-shot" aria-label="Démo de l'agent">
        <div className="ln-frame">
          <i className="c tl" /><i className="c tr" /><i className="c bl" /><i className="c br" />
          <div className="ln-term">
            <div className="ln-term-bar"><span /><span /><span /><b className="mono">crenel · acme-app</b><em className="mono">lecture seule</em></div>
            <div className="ln-term-body mono">
              <div className="u">› Scanne acme-app, et prouve ce que tu trouves</div>
              <div className="r"><i className="b" />scan.secrets <s>(dist/ · bundle en ligne)</s></div>
              <div className="x"><span className="t crit">CRIT</span> sk_live_ dans assets/index-4f2a.js <span className="p">prouvé</span></div>
              <div className="r"><i className="b" />scan.deps <s>(pnpm-lock.yaml · OSV)</s></div>
              <div className="x"><span className="t crit">CRIT</span> better-auth 1.6.26 · GHSA-965c <span className="p">avis publié</span></div>
              <div className="r"><i className="b a" /><Shimmer>authz.matrix</Shimmer> <s>(compte A → objet de B)</s></div>
              <div className="perm">Envoyer 4 GET à staging.acme.app ? <span className="on">1 Autoriser une fois</span><span>2 Toujours</span><span>3 Refuser</span></div>
              <div className="x"><span className="t high">HAUTE</span> GET /api/projects/proj_b_1 → 200, rejoué 3 fois <span className="p">prouvé</span></div>
              <div className="r"><i className="b a" />tests.generate <s>(3 preuves)</s></div>
              <div className="x"><span className="g">gardé</span> 3 tests de régression prêts pour la CI</div>
            </div>
          </div>
          <div className="ln-mascot" aria-hidden="true"><Mascot size={92} mood="found" /></div>
        </div>
      </section>

      <section className="ln-wrap ln-stats" aria-label="En chiffres">
        <div><b>{CHECK_COUNT}</b><span>checks déterministes</span></div>
        <div><b>22/22</b><span>failles trouvées sur notre banc</span></div>
        <div><b>0/28</b><span>leurres signalés à tort</span></div>
        <div><b>GET</b><span>par défaut, imposé par le client HTTP</span></div>
      </section>

      <section id="methode" className="ln-wrap ln-sec" aria-labelledby="m-t">
        <div className="ln-head">
          <Eyebrow n="01">MÉTHODE</Eyebrow>
          <h2 id="m-t">Prouvé, <span className="ln-dim">puis gardé.</span></h2>
          <p>Pas de liste de 300 alertes. Une faille compte quand elle se rejoue, et cesse de compter quand un test l'empêche de revenir.</p>
        </div>
        <ol className="ln-steps">
          <li>
            <span className="mono n">01</span><h3>Détecter</h3>
            <p>Bundle servi, dépôt, historique git, dépendances, CI, en-têtes, DNS.</p>
            <code className="mono">npx crenel scan</code>
          </li>
          <li>
            <span className="mono n">02</span><h3>Prouver</h3>
            <p>Propriétaire, attaquant, contrôle négatif. Sans rejeu, ce n'est qu'une piste.</p>
            <code className="mono">A lit proj_b_1 → 200 (×3)</code>
          </li>
          <li>
            <span className="mono n">03</span><h3>Garder</h3>
            <p>La preuve devient un test. La faille ne revient plus sans casser le build.</p>
            <code className="mono g">✓ A ne lit pas le projet de B</code>
          </li>
        </ol>
      </section>

      <section id="couverture" className="ln-wrap ln-sec" aria-labelledby="c-t">
        <div className="ln-head">
          <Eyebrow n="02">COUVERTURE</Eyebrow>
          <h2 id="c-t">Ce que le code généré <span className="ln-dim">oublie le plus souvent.</span></h2>
        </div>
        <div className="ln-bento">
          <article className="ln-card wide">
            <header><KeyRound size={16} /><h3>Clés serveur dans le bundle</h3></header>
            <p>Chaque chunk JS servi est relu, source maps comprises. Une clé est vérifiée en direct seulement si vous l'autorisez.</p>
            <pre className="ln-code mono"><span className="dim">// assets/index-4f2a.js</span>{"\n"}const stripe = new Stripe(<mark>"sk_live_51N…q8"</mark>){"\n"}<span className="dim">// supabase: anon key + table sans RLS</span></pre>
          </article>
          <article className="ln-card">
            <header><Users size={16} /><h3>Autorisation entre comptes</h3></header>
            <p>Chaque ressource lue par A, par C et sans session.</p>
            <div className="ln-matrix mono" role="table" aria-label="Exemple de matrice">
              <span /><span>A</span><span>C</span><span>anon</span>
              <span>/projects/:id</span><i className="no" /><i className="ok" /><i className="ok" />
              <span>/invoices/:id</span><i className="ok" /><i className="ok" /><i className="ok" />
              <span>/files/:id</span><i className="no" /><i className="no" /><i className="ok" />
            </div>
          </article>
          <article className="ln-card">
            <header><Database size={16} /><h3>BaaS ouverts</h3></header>
            <p>Supabase sans RLS, Firestore lisible, buckets listables, inscription auto-confirmée.</p>
          </article>
          <article className="ln-card">
            <header><Package size={16} /><h3>Dépendances</h3></header>
            <p>Avis OSV sur le lockfile et sur la version de Next.js réellement servie.</p>
          </article>
          <article className="ln-card">
            <header><FileWarning size={16} /><h3>Fichiers exposés</h3></header>
            <p>.env, .git, dumps SQL. Signature du contenu et contrôle négatif, jamais un simple 200.</p>
          </article>
        </div>
        <details className="ln-all">
          <summary>Voir les {CHECK_COUNT} checks</summary>
          <div className="ln-groups">
            {CHECK_GROUPS.map((g) => (
              <div key={g.name}>
                <h4>{g.name}</h4>
                <ul>{g.ids.map((id) => <li key={id} className="mono">{id}</li>)}</ul>
              </div>
            ))}
          </div>
        </details>
      </section>

      <section id="controle" className="ln-wrap ln-sec" aria-labelledby="k-t">
        <div className="ln-head">
          <Eyebrow n="03">CONTRÔLE</Eyebrow>
          <h2 id="k-t">Rien ne part <span className="ln-dim">sans votre accord.</span></h2>
          <p>L'agent ne touche qu'aux hôtes déclarés. Chaque requête passe par une porte, chaque action est écrite dans un journal chaîné.</p>
        </div>
        <div className="ln-modes">
          <div><Hand size={16} /><h3>Demander</h3><p>Une question avant chaque sonde réseau.</p></div>
          <div><Eye size={16} /><h3>Lecture seule</h3><p>Code et bundle seulement, aucune requête vers la cible.</p></div>
          <div><Zap size={16} /><h3>Bypass</h3><p>Tout autorisé dans le périmètre, pour la CI.</p></div>
          <div><ShieldCheck size={16} /><h3>Objectif</h3><p>L'agent continue jusqu'à l'atteindre, puis s'arrête.</p></div>
        </div>
      </section>

      <section className="ln-wrap ln-final">
        <Mascot size={96} mood="hello" />
        <h2>Lancez votre premier scan.</h2>
        <p>Deux minutes, en local, sur une app à vous.</p>
        <div className="ln-cta">
          <Button to="/app/onboarding">Ajouter une cible <ArrowRight size={15} /></Button>
          <Button href={DOCS_URL} variant="ghost">Lire la doc</Button>
        </div>
      </section>

      <footer className="ln-wrap ln-foot">
        <Mark size={18} /><span>crenel · MIT · outil indépendant</span>
        <span className="sp" />
        <a href={REPO_URL} target="_blank" rel="noopener noreferrer">GitHub</a>
        <a href={DOCS_URL} target="_blank" rel="noopener noreferrer">Docs</a>
      </footer>
    </div>
  );
}
