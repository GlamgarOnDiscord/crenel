import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Check, Eye, EyeOff, FileCheck2, Link2, MoreHorizontal, RotateCcw, Sparkles, TerminalSquare } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, CopyButton, EmptyState, GuardBadge, Pill, SeverityChip, StateBadge } from "../components/ui.tsx";
import { CodeBlock } from "../components/ai/code-block.tsx";
import { DropdownMenu } from "../components/arc/dropdown-menu/dropdown-menu.tsx";
import { Tooltip } from "../components/arc/tooltip/tooltip.tsx";
import { useToast } from "../components/toast.tsx";
import { useData } from "../data/api.ts";
import { copyText, ignoreFinding, linkTo, triageFinding } from "../data/actions.ts";
import { IgnoreFinding, useServerAction } from "../components/console-actions.tsx";
import { cn } from "../lib/cn.ts";

export function FindingDetail() {
  const { id } = useParams();
  const toast = useToast();
  const navigate = useNavigate();
  const run = useServerAction();
  const { findings, llm } = useData();
  const [asking, setAsking] = useState(false);
  const [advice, setAdvice] = useState<{ id: string; text: string } | null>(null);
  const [triaging, setTriaging] = useState(false);
  const f = findings.find((x) => x.id === id);
  if (!f) return (
    <>
      <Topbar width="narrow" title="Finding introuvable" />
      <div className="content">
        <EmptyState icon={<Mascot size={96} />} title="Introuvable" action={<Button variant="ghost" size="sm" to="/app/findings">Tous les findings</Button>}>Ce finding n'existe pas ou plus.</EmptyState>
      </div>
    </>
  );

  // The advice asked for here, else the one the server kept from an earlier ask.
  const shownAdvice = advice?.id === f.id ? advice.text : f.advice ?? null;
  const fid = f.id;
  async function triage() {
    setTriaging(true);
    const r = await run(() => triageFinding(fid), () => null, "Pas d'avis du modèle");
    setTriaging(false);
    if (r) setAdvice({ id: fid, text: r.advice });
  }

  const proven = f.state === "proven" || (f.state === "fixed" && !!f.proof);
  const steps = [
    { label: "Trouvé", sub: `il y a ${f.seen}`, done: true, tone: "" },
    { label: "Prouvé", sub: proven ? "requête rejouable" : "pas encore", done: proven, tone: "t-bad" },
    { label: "Test généré", sub: f.regression ? "régression prête" : "à générer", done: !!f.regression, tone: "" },
    { label: "En CI", sub: f.guarded ? "gardé" : "pas encore", done: !!f.guarded, tone: "t-guard" },
  ];

  return (
    <>
      <Topbar width="narrow" scoped crumb="Findings" title={f.title} actions={
        <>
          <Button variant="ghost" size="sm" to="/app/agent" state={{ prompt: `/explain ${f.id}: ${f.title}` }}><TerminalSquare size={14} /> Demander à l'agent</Button>
          {f.state === "fixed"
            ? <Button variant="ghost" size="sm" disabled><Check size={14} /> Corrigé</Button>
            : f.regression ? null
            : <Button size="sm" to="/app/agent" state={{ prompt: `/test ${f.id}` }}><FileCheck2 size={14} /> Générer le test</Button>}
          <DropdownMenu iconOnly label="Plus d'actions" icon={<MoreHorizontal size={16} />} items={[
            { label: "Copier le lien", icon: <Link2 size={14} />, onSelect: async () => {
              const ok = await copyText(linkTo(`/app/findings/${f.id}`));
              toast(ok ? { type: "success", title: "Lien copié" } : { type: "error", title: "Lien non copié", description: "Le navigateur refuse l'accès au presse-papiers." });
            } },
            { label: "Avis du modèle", icon: <Sparkles size={14} />, disabled: triaging, onSelect: () => void triage() },
            { label: "Revérifier (/scan)", icon: <RotateCcw size={14} />, onSelect: () => navigate("/app/agent", { state: { prompt: "/scan" } }) },
            f.ignored
              ? { label: "Ne plus ignorer", icon: <Eye size={14} />, separatorBefore: true, onSelect: () => void run(() => ignoreFinding(f.id, false), () => ({ title: "Finding de nouveau suivi" }), "Finding toujours ignoré") }
              : { label: "Ignorer ce finding...", icon: <EyeOff size={14} />, destructive: true, separatorBefore: true, onSelect: () => setAsking(true) },
          ]} />
        </>
      } />
      <div className="content narrow">
        <Link to="/app/findings" className="backlink"><ArrowLeft size={14} /> Tous les findings</Link>

        <div className="fd-meta">
          <SeverityChip sev={f.sev} /><StateBadge state={f.state} />{f.guarded && <GuardBadge label="gardé en CI" />}
          <span className="mono faint">{f.check}</span>
          <span className="mono faint">{f.location}</span>
        </div>

        {f.ignored && (
          <div className="fd-ignored">
            <Pill><EyeOff size={11} aria-hidden="true" /> ignoré</Pill>
            <span>{f.ignored.reason ? `Raison: ${f.ignored.reason}. ` : ""}Ignoré dans la console, il reste dans les rapports.</span>
            <Button size="sm" variant="quiet" onClick={() => void run(() => ignoreFinding(f.id, false), () => ({ title: "Finding de nouveau suivi" }), "Finding toujours ignoré")}><Eye size={13} /> Ne plus ignorer</Button>
          </div>
        )}
        {asking && !f.ignored && <IgnoreFinding uid={f.id} title={f.title} onClose={() => setAsking(false)} />}

        <ol className="timeline" aria-label="Cycle de vie">
          {steps.map((s, i) => (
            <li key={s.label} className={cn("tl", s.done && "done", s.done && s.tone)}>
              <span className="tl-dot" aria-hidden="true">{s.done ? <Check size={12} strokeWidth={3} /> : i + 1}</span>
              <span className="tl-l">{s.label}<span className="sr-only">{s.done ? " (fait)" : " (à faire)"}</span></span>
              <span className="tl-s">{s.sub}</span>
            </li>
          ))}
        </ol>

        <Card title="Description"><div className="pad prose">{f.description}</div></Card>

        {(triaging || shownAdvice) && (
          <Card title="Avis du modèle" meta={llm ?? undefined}>
            <div className="pad">
              {triaging ? <div className="muted">Le modèle relit le finding et sa preuve...</div> : <div className="prose advice">{shownAdvice}</div>}
              <div className="advice-note">Un avis seulement: l'état (prouvé, piste, corrigé) est décidé par les validateurs, pas par le modèle.</div>
            </div>
          </Card>
        )}

        {f.proof && (
          <Card title="Preuve" meta={f.proof.method}>
            <div className="pad stack">
              <div className="cmd"><code><span className="k" aria-hidden="true">$</span> {f.proof.replay}</code><Tooltip content="Copier la commande de preuve"><span><CopyButton text={f.proof.replay} /></span></Tooltip></div>
              {f.proof.evidence && <div className={cn("mono evidence", f.state === "proven" && "bad")}><span className="elbow" aria-hidden="true" />{f.proof.evidence}</div>}
            </div>
          </Card>
        )}

        <Card title="Remédiation"><div className="pad prose">{f.remediation}</div></Card>

        <Card title="Test de régression" meta={f.guarded ? <GuardBadge label="en CI" /> : "pour qu'il ne revienne pas"}>
          <div className="pad">
            {f.regression
              ? <CodeBlock filename={`tests/crenel/${f.check}.test.ts`} code={f.regression} language="ts" />
              : <div className="muted">Pas encore de test. <Link to="/app/agent" state={{ prompt: `/test ${f.id}` }} className="linkish">Demander à l'agent de le générer</Link></div>}
          </div>
        </Card>
      </div>
    </>
  );
}
