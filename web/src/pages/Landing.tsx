import { useEffect } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, Github } from "lucide-react";
import { Mark, Wordmark, Mascot } from "../brand/Logo.tsx";
import { Button, CopyButton } from "../components/ui.tsx";
import { CHECKS } from "../data/mock.ts";
import { REPO_URL, DOCS_URL } from "../lib/links.ts";

const STEPS = [
  { n: "1", title: "Détecter", desc: "14 checks déterministes parcourent le bundle, le dépôt, les dépendances, la CI et vos en-têtes.", code: "npx crenel scan --target acme-app" },
  { n: "2", title: "Prouver", desc: "Chaque faille doit se rejouer: une commande, une requête, une réponse. Sinon ce n'est qu'une piste.", code: "curl -H 'Bearer A' /api/projects/proj_b_1  → 200" },
  { n: "3", title: "Garder", desc: "La preuve devient un test de régression. En CI, la faille ne revient plus sans casser le build.", code: "✓ A ne peut pas lire le projet de B  (en CI)" },
];

const GROUPS = Array.from(new Set(CHECKS.map((c) => c.group)));

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

export function Landing() {
  useEffect(() => { document.title = "Crenel · prouvé, puis gardé"; }, []);
  return (
    <div className="lp">
      <nav className="lp-nav landing" aria-label="Navigation du site">
        <Link to="/" className="brand"><Mark size={28} /><Wordmark /></Link>
        <span className="sp" />
        <button type="button" className="lp-link hide-sm" onClick={() => scrollTo("how")}>Comment ça marche</button>
        <button type="button" className="lp-link hide-sm" onClick={() => scrollTo("checks")}>Checks</button>
        <a className="lp-link hide-sm" href={DOCS_URL} target="_blank" rel="noopener noreferrer">Docs</a>
        <Button to="/app/overview" size="sm">Ouvrir la console</Button>
      </nav>

      <header className="landing lp-hero">
        <div className="lp-hero-tx">
          <span className="eyebrow">Open source · pour fondateurs de SaaS</span>
          <h1>Attaquez votre app <em>avant</em> qu'on le fasse.</h1>
          <p className="sub">Crenel trouve les secrets exposés et les failles d'autorisation entre comptes, prouve chacune par une requête rejouable, puis la garde en CI pour qu'elle ne revienne jamais.</p>
          <div className="cta">
            <Button to="/app/overview">Ouvrir la console <ArrowRight size={15} /></Button>
            <Button href={REPO_URL} variant="ghost"><Github size={15} /> GitHub</Button>
          </div>
          <div className="install"><code><span className="k" aria-hidden="true">$</span> npx crenel scan</code><CopyButton text="npx crenel scan" /></div>
        </div>
        <div className="lp-mascot" aria-hidden="false">
          <div className="halo big"><Mascot size={280} /></div>
          <span className="float f1"><i className="fd red" />sk_live_ prouvée</span>
          <span className="float f2"><i className="fd amber" />gardée en CI</span>
        </div>
      </header>

      <section className="landing" aria-label="Démo">
        <div className="term">
          <div className="term-bar"><i /><i /><i /><span className="mono">crenel · acme-app</span></div>
          <div className="term-body mono">
            <div className="tl-user">› Scanne acme-app, et prouve ce que tu trouves</div>
            <div className="tl-row"><span className="b ok" />scan.secrets<span className="dim">(dist/ · 12 motifs)</span></div>
            <div className="tl-res"><span className="tag crit">CRIT</span> sk_live_ dans dist/app.js:5 <span className="pv">prouvé</span></div>
            <div className="tl-row"><span className="b ok" />scan.deps<span className="dim">(pnpm-lock.yaml · 842 paquets)</span></div>
            <div className="tl-res"><span className="tag crit">CRIT</span> @tanstack/react-router@1.169.5 <span className="pv">prouvé</span></div>
            <div className="tl-row"><span className="b wait" />authz.matrix<span className="dim">(compte A → compte B)</span></div>
            <div className="tl-perm">Envoyer 4 requêtes à staging.acme.app ? <span className="opt on">1 Autoriser une fois</span><span className="opt">2 Toujours</span><span className="opt">3 Refuser</span></div>
            <div className="tl-res"><span className="tag high">HAUTE</span> GET /api/projects/:id → 200 <span className="pv">prouvé</span></div>
            <div className="tl-row"><span className="b amb" />tests.generate<span className="dim">(4 failles)</span></div>
            <div className="tl-res"><span className="gd">gardé</span> 4 tests prêts pour la CI</div>
          </div>
        </div>
      </section>

      <section id="how" className="landing lp-sec" aria-labelledby="how-t">
        <h2 id="how-t" className="lp-h2">Prouvé, puis gardé.</h2>
        <p className="lp-lede">Pas de liste de 300 alertes. Une faille compte quand elle se rejoue, et elle ne compte plus quand un test l'empêche de revenir.</p>
        <ol className="how">
          {STEPS.map((s) => (
            <li key={s.n} className={`how-step s${s.n}`}>
              <span className="how-n" aria-hidden="true">{s.n}</span>
              <h3>{s.title}</h3>
              <p>{s.desc}</p>
              <code className="how-code">{s.code}</code>
            </li>
          ))}
        </ol>
      </section>

      <section id="checks" className="landing lp-sec" aria-labelledby="checks-t">
        <h2 id="checks-t" className="lp-h2">14 checks, zéro magie.</h2>
        <p className="lp-lede">Chacun est déterministe et lisible dans le dépôt. L'agent les orchestre; le verdict ne dépend jamais d'un modèle.</p>
        <div className="checks">
          {GROUPS.map((g) => (
            <div key={g} className="chk-group">
              <h3>{g}</h3>
              <ul>
                {CHECKS.filter((c) => c.group === g).map((c) => (
                  <li key={c.id} className="chk"><span className="mono chk-id">{c.id}</span><span className="chk-d">{c.desc}</span></li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section className="landing lp-sec">
        <div className="lp-cta">
          <Mark size={44} />
          <div><h2>Lancez votre premier scan.</h2><p className="muted">Deux minutes, lecture seule par défaut, rien ne part sans votre accord.</p></div>
          <span className="sp" />
          <Button to="/app/onboarding">Ajouter une cible <ArrowRight size={15} /></Button>
        </div>
      </section>

      <footer className="landing lp-foot">
        <Mark size={20} /><span>crenel · MIT · un outil indépendant</span>
        <span className="sp" />
        <a href={REPO_URL} target="_blank" rel="noopener noreferrer">GitHub</a>
        <a href={DOCS_URL} target="_blank" rel="noopener noreferrer">Docs</a>
      </footer>
    </div>
  );
}
