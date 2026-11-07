import { Link } from "react-router-dom";
import { KeyRound, LockKeyhole, FileCheck2, ArrowRight, Github } from "lucide-react";
import { Mark, Wordmark, Mascot } from "../brand/Logo.tsx";
import { Button } from "../components/ui.tsx";
import { REPO_URL, DOCS_URL } from "../lib/links.ts";

export function Landing() {
  return (
    <div style={{ minHeight: "100%", overflowY: "auto" }}>
      <nav className="landing" style={{ display: "flex", alignItems: "center", gap: 12, padding: "20px 24px" }}>
        <Link to="/" className="brand" style={{ padding: 0 }}><Mark size={28} /><Wordmark /></Link>
        <span className="sp" style={{ flex: 1 }} />
        <a className="nav" href={DOCS_URL} target="_blank" rel="noopener noreferrer" style={{ display: "inline-flex" }}>Docs</a>
        <Link to="/app/overview"><Button variant="ghost" size="sm">Ouvrir la console</Button></Link>
      </nav>

      <header className="landing">
        <div className="lhero">
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", gap: 24, alignItems: "center" }}>
            <div style={{ display: "grid", gap: 20 }}>
              <span className="eyebrow">Sécurité pour fondateurs · open source</span>
              <h1>Attaquez votre app <em>avant</em> qu'on le fasse.</h1>
              <p className="sub">Crenel trouve les secrets exposés et les failles d'autorisation entre comptes, prouve chacune par une requête rejouable, et la transforme en test qui ne revient plus.</p>
              <div className="cta">
                <Link to="/app/overview"><Button>Ouvrir la console <ArrowRight size={15} /></Button></Link>
                <a href={REPO_URL} target="_blank" rel="noopener noreferrer"><Button variant="ghost"><Github size={15} /> GitHub</Button></a>
              </div>
            </div>
            <div className="hide-sm"><Mascot size={168} /></div>
          </div>

          <div className="termcard">
            <div className="bar"><i /><i /><i /><span className="mono faint" style={{ fontSize: 12, marginLeft: 6 }}>crenel</span></div>
            <pre><span className="p">$</span> npx crenel scan --target acme-app{"\n\n"}
  <span className="cr">CRIT</span>  clé Stripe dans le bundle      dist/app.js:5      <span className="ok">prouvé</span>{"\n"}
  <span className="cr">CRIT</span>  paquet malveillant verrouillé  @tanstack@1.169.5  <span className="ok">prouvé</span>{"\n"}
  HIGH  autorisation inter-tenant      /api/projects/:id  lead{"\n\n"}
  <span className="ok">→</span> 2 critiques prouvés · test de régression généré{"\n"}
  la CI échoue sur un nouveau prouvé high ou critique
</pre>
          </div>
        </div>

        <section className="feat">
          <div className="f"><span className="fi"><KeyRound size={18} /></span><h3>Secrets exposés</h3><p>Clés serveur embarquées dans le bundle client, clés privées commitées, paquets malveillants. Match déterministe, quasi zéro faux positif.</p></div>
          <div className="f"><span className="fi"><LockKeyhole size={18} /></span><h3>Autorisation inter-tenant</h3><p>La faille où les LLM sont aveugles. Une matrice déterministe prouve qu'un compte ne peut pas lire les données d'un autre.</p></div>
          <div className="f"><span className="fi"><FileCheck2 size={18} /></span><h3>Preuve puis régression</h3><p>Chaque finding prouvé devient un test en CI. La faille ne peut plus revenir sans casser le build.</p></div>
        </section>

        <footer style={{ padding: "32px 0 56px", borderTop: "1px solid var(--line)", color: "var(--fg-faint)", fontSize: 13, display: "flex", gap: 16, alignItems: "center" }}>
          <Mark size={20} /> <span>crenel · MIT · un outil indépendant</span>
        </footer>
      </header>
    </div>
  );
}
