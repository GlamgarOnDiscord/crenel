import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Check, FileCheck2 } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, SeverityChip, StateBadge, EmptyState } from "../components/ui.tsx";
import { findings } from "../data/mock.ts";

export function FindingDetail() {
  const { id } = useParams();
  const f = findings.find((x) => x.id === id);
  if (!f) return <><Topbar title="Finding introuvable" /><div className="content"><EmptyState title="Introuvable">Ce finding n'existe pas ou plus.</EmptyState></div></>;
  return (
    <>
      <Topbar crumb="Findings" title={f.title} actions={
        <>
          {f.state === "lead" ? <Button variant="ghost" size="sm"><FileCheck2 size={14} /> Générer le test</Button> : <Button variant="ghost" size="sm"><Check size={14} /> Marquer corrigé</Button>}
          <Button size="sm">Ouvrir la PR</Button>
        </>
      } />
      <div className="content" style={{ maxWidth: 820 }}>
        <Link to="/app/findings" className="muted" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 13 }}><ArrowLeft size={14} /> Tous les findings</Link>

        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <SeverityChip sev={f.sev} /><StateBadge state={f.state} />
          <span className="mono faint" style={{ fontSize: 13 }}>{f.check}</span>
          <span className="mono faint" style={{ fontSize: 13 }}>{f.location}</span>
        </div>

        <section className="card"><div className="hd"><h2>Description</h2></div><div style={{ padding: 18, lineHeight: 1.65 }}>{f.description}</div></section>

        {f.proof && (
          <section className="card">
            <div className="hd"><h2>Preuve</h2><span className="meta">{f.proof.method}</span></div>
            <div style={{ padding: 18, display: "grid", gap: 10 }}>
              <div className="toolcall"><span className="k">$</span> {f.proof.replay}</div>
              {f.proof.evidence && <div className="mono faint" style={{ fontSize: 12 }}>→ {f.proof.evidence}</div>}
            </div>
          </section>
        )}

        <section className="card"><div className="hd"><h2>Remédiation</h2></div><div style={{ padding: 18, lineHeight: 1.65 }}>{f.remediation}</div></section>

        {f.regression && (
          <section className="card">
            <div className="hd"><h2>Test de régression</h2><span className="meta">pour qu'il ne revienne pas</span></div>
            <div style={{ padding: 18 }}><div className="toolcall">{f.regression}</div></div>
          </section>
        )}
      </div>
    </>
  );
}
