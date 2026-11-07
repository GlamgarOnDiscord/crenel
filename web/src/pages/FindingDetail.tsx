import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Check, CircleCheck, EyeOff, FileCheck2, GitPullRequest, Link2, MoreHorizontal, TerminalSquare } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, CopyButton, EmptyState, GuardBadge, SeverityChip, StateBadge } from "../components/ui.tsx";
import { CodeBlock } from "../components/ai/code-block.tsx";
import { DropdownMenu } from "../components/arc/dropdown-menu/dropdown-menu.tsx";
import { Tooltip } from "../components/arc/tooltip/tooltip.tsx";
import { useToast } from "../components/toast.tsx";
import { findings } from "../data/mock.ts";
import { cn } from "../lib/cn.ts";

export function FindingDetail() {
  const { id } = useParams();
  const toast = useToast();
  const f = findings.find((x) => x.id === id);
  if (!f) return (
    <>
      <Topbar title="Finding introuvable" />
      <div className="content">
        <EmptyState icon={<Mascot size={96} />} title="Introuvable" action={<Button variant="ghost" size="sm" to="/app/findings">Tous les findings</Button>}>Ce finding n'existe pas ou plus.</EmptyState>
      </div>
    </>
  );

  const proven = f.state === "proven" || (f.state === "fixed" && !!f.proof);
  const steps = [
    { label: "Trouvé", sub: `il y a ${f.seen}`, done: true, tone: "" },
    { label: "Prouvé", sub: proven ? "requête rejouable" : "pas encore", done: proven, tone: "t-bad" },
    { label: "Test généré", sub: f.regression ? "régression prête" : "à générer", done: !!f.regression, tone: "" },
    { label: "En CI", sub: f.guarded ? "gardé" : "pas encore", done: !!f.guarded, tone: "t-guard" },
  ];

  return (
    <>
      <Topbar scoped crumb="Findings" title={f.title} actions={
        <>
          <Button variant="ghost" size="sm" to="/app/agent" state={{ prompt: `/explain ${f.id}: ${f.title}` }}><TerminalSquare size={14} /> Demander à l'agent</Button>
          {f.state === "fixed"
            ? <Button variant="ghost" size="sm" disabled><Check size={14} /> Corrigé</Button>
            : f.regression ? <Button size="sm"><GitPullRequest size={14} /> Ouvrir la PR</Button>
            : <Button size="sm"><FileCheck2 size={14} /> Générer le test</Button>}
          <DropdownMenu iconOnly label="Plus d'actions" icon={<MoreHorizontal size={16} />} items={[
            { label: "Copier le lien", icon: <Link2 size={14} />, onSelect: () => toast({ type: "success", title: "Lien copié" }) },
            { label: "Marquer corrigé", icon: <CircleCheck size={14} />, disabled: f.state === "fixed", onSelect: () => toast({ type: "success", title: "Marqué corrigé", description: "Le test reste gardé en CI." }) },
            { label: "Ignorer ce finding", icon: <EyeOff size={14} />, destructive: true, separatorBefore: true, onSelect: () => toast({ type: "warning", title: "Finding ignoré", description: "Il ne bloquera plus la CI." }) },
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
