/* Feature cards for the landing: a dark bento where each card opens with an
   icon, a title and one line, then shows a slice of real Crenel interface
   that runs off the card's edge. The slices share the hero console's UI kit
   (ui-* classes), so the page reads as one product. */
import type { ReactNode } from "react";
import { Bot, Code2, FileCheck2, Globe, GitPullRequest, Hand, ScrollText, Terminal, FileJson, Hash } from "lucide-react";
import { Mark } from "../../brand/Logo.tsx";

function Card({ icon, title, children, className, art, artFirst }: {
  icon: ReactNode; title: string; children: ReactNode; className?: string; art?: ReactNode; artFirst?: boolean;
}) {
  return (
    <article className={`fc ${className ?? ""}`} data-reveal>
      {artFirst && art}
      <div className="fc-text">
        <h3><span className="fc-ic">{icon}</span>{title}</h3>
        <p>{children}</p>
      </div>
      {!artFirst && art}
    </article>
  );
}

// Four-point star used as the sparkle accent.
function Spark({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" className="fc-spark" aria-hidden="true">
      <path d="M5 0 C5.4 3.2 6.8 4.6 10 5 C6.8 5.4 5.4 6.8 5 10 C4.6 6.8 3.2 5.4 0 5 C3.2 4.6 4.6 3.2 5 0Z" />
    </svg>
  );
}

export function FeatureCards() {
  return (
    <div className="fc-grid">
      <div className="fc-left">
        <Card className="fc-a" icon={<Code2 size={15} />} title="Bundle relu" art={
          <div className="fc-art bleed" aria-hidden="true">
            <div className="ui-win">
              <div className="ui-bar"><i /><i /><i /><span className="ui-url"><Globe size={10} />https://<b>acme.app</b></span></div>
              <div className="ui-body fc-site">
                <span className="sk w30" /><span className="sk w40 r" />
                <span className="sk blk" /><span className="sk blk2" />
                <span className="sk w50" />
                <span className="fc-leak mono">sk_live_51N…q8</span>
              </div>
            </div>
            <div className="fc-beam"><span className="mono">chunk 14/31</span></div>
          </div>
        }>Chaque fichier JS servi est relu, source maps comprises.</Card>

        <Card className="fc-b" icon={<Bot size={15} />} title="Un agent qui prouve" art={
          <div className="fc-art bleed" aria-hidden="true">
            <div className="ui-win fc-chat">
              <div className="fc-chat-hd"><span className="fc-av"><Mark size={22} mood="idle" /></span>Crenel <span className="ui-badge">AGENT</span></div>
              <div className="fc-msg">
                <b>Faille prouvée sur /api/projects <Spark /></b>
                <span className="sk w80" /><span className="sk w60" />
                <span className="sk w40 dim" />
              </div>
              <div className="ui-input sm"><span className="ph">Message à Crenel…</span></div>
            </div>
          </div>
        }>Il propose, vous validez. Une faille n'est retenue que si elle se rejoue.</Card>

        <Card className="fc-d" icon={<Hand size={15} />} title="Vous gardez la main" art={
          <div className="fc-art fc-rings" aria-hidden="true">
            <i /><i /><i /><i />
            <span className="fc-core"><Hand size={20} /></span>
          </div>
        }>Une question avant chaque sonde réseau, sur vos seuls hôtes.</Card>

        <Card className="fc-e" icon={<Terminal size={15} />} title="Partout où vous codez" art={
          <div className="fc-art bleed fc-dockwrap" aria-hidden="true">
            <div className="fc-dock">
              <span className="tile term">&gt;_</span>
              <span className="tile main"><Mark size={52} /><i /></span>
              <span className="tile gh"><GitPullRequest size={24} /></span>
              <span className="tile sarif"><FileJson size={24} /></span>
              <span className="tile web"><Globe size={24} /></span>
            </div>
          </div>
        }>CLI, console, GitHub Action et rapport SARIF : les mêmes 43 checks.</Card>
      </div>

      <div className="fc-right">
        <Card className="fc-c" artFirst icon={<ScrollText size={15} />} title="Journal chaîné" art={
          <div className="fc-art fc-circuit" aria-hidden="true">
            <span className="fc-chiptile"><Hash size={20} /></span>
            <svg viewBox="0 0 300 70" preserveAspectRatio="none"><path d="M64 34 H200 Q214 34 214 20 V0" /><path d="M64 40 H252 Q266 40 266 54 V70" /></svg>
          </div>
        }>Chaque action de l'agent est écrite dans un journal chaîné par hash : une ligne modifiée se voit.</Card>

        <Card className="fc-f" icon={<FileCheck2 size={15} />} title="Gardé en CI" art={
          <div className="fc-art fc-docwrap" aria-hidden="true">
            <div className="fc-doc">
              <span className="fc-fold" />
              <b className="mono">authz.test.ts</b>
              <pre className="mono">{`test("A ne lit pas proj_b_1", async () => {
  const r = await as("A")
    .get("/api/projects/proj_b_1");
  expect(r.status).not.toBe(200);
});`}</pre>
              <span className="ui-frost"><FileCheck2 size={16} />Ajouter à la CI</span>
            </div>
          </div>
        }>Chaque preuve devient un test de régression. La faille ne revient plus sans casser le build.</Card>
      </div>
    </div>
  );
}
