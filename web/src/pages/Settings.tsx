import { useState } from "react";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, Toggle } from "../components/ui.tsx";
import { useWorkspace } from "../lib/workspace.tsx";
import { UsageMeter } from "../components/arc/usage-meter/usage-meter.tsx";
import { Counter } from "../components/bencho/Counter.tsx";
import "../components/bencho/Counter.css";
import { SlideConfirm } from "../components/bencho/SlideConfirm.tsx";
import "../components/bencho/SlideConfirm.css";
import { useToast } from "../components/toast.tsx";

function Row({ title, desc, control }: { title: string; desc: string; control: React.ReactNode }) {
  return (
    <div className="srow">
      <div className="srow-tx"><div className="srow-t">{title}</div><div className="muted srow-d">{desc}</div></div>
      {control}
    </div>
  );
}

function PolicyToggle({ title, desc, initial }: { title: string; desc: string; initial: boolean }) {
  const [on, setOn] = useState(initial);
  return <Row title={title} desc={desc} control={<Toggle on={on} onChange={setOn} label={title} />} />;
}

export function Settings() {
  const { target } = useWorkspace();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  return (
    <>
      <Topbar crumb="Espace" title="Paramètres" insight={<>La CI ne casse que sur une faille <b>prouvée</b>, haute ou critique.</>} />
      <div className="content narrow">
        <Card title="Utilisation ce mois-ci" meta="forfait Équipe">
          <div className="pad">
            <UsageMeter label="Sondes envoyées aux hôtes déclarés" unit=" sondes" decimals={0} limit={2000}
              segments={[{ id: "acme", label: "acme-app", value: 1120 }, { id: "inbox", label: "inboxly", value: 310 }, { id: "page", label: "pagefold", value: 240 }]} />
          </div>
        </Card>

        <Card title="Scans planifiés">
          <div className="srow">
            <div className="srow-tx"><div className="srow-t">Scans par jour et par cible</div><div className="muted srow-d">Un scan complet dure environ une minute.</div></div>
            <div className="bencho counter-wrap"><Counter start={2} min={0} max={24} label="Scans par jour" corner={12} onChange={() => {}} /></div>
          </div>
        </Card>

        <Card title="Politique de CI" meta="ce qui casse le build">
          <PolicyToggle title="Bloquer sur critique prouvé" desc="Un nouveau critique prouvé fait échouer la CI." initial />
          <PolicyToggle title="Bloquer sur haute prouvée" desc="Une nouvelle faille haute prouvée fait échouer la CI." initial />
          <PolicyToggle title="Bloquer sur les pistes" desc="Déconseillé: une piste n'est pas prouvée." initial={false} />
          <PolicyToggle title="Refuser les scripts d'install en CI" desc="Installe avec --ignore-scripts (recommandé)." initial />
        </Card>

        <Card title="Membres" actions={<Button variant="ghost" size="sm">Inviter</Button>}>
          {[["Tom", "propriétaire"], ["Pierre", "admin"]].map(([n, r]) => (
            <div key={n} className="srow">
              <span className="av">{n![0]}</span>
              <span className="srow-tx">{n}</span><span className="mono faint">{r}</span>
            </div>
          ))}
        </Card>

        <Card title="Zone de danger" className="danger-card">
          <Row title={`Supprimer la cible ${target.name}`} desc="Efface ses tâches, findings et tests. Irréversible."
            control={confirm ? (
              <div className="confirm-slide bencho danger-slide">
                <SlideConfirm width={260} label="Glisser pour supprimer" doneLabel="Supprimée" onConfirm={() => { toast({ type: "warning", title: `Suppression de ${target.name} programmée`, description: "Annulable pendant 24 h depuis le support." }); setTimeout(() => setConfirm(false), 900); }} />
                <Button size="sm" variant="quiet" onClick={() => setConfirm(false)}>Annuler</Button>
              </div>
            ) : <Button size="sm" variant="ghost" className="danger-ghost" onClick={() => setConfirm(true)}>Supprimer</Button>} />
        </Card>
      </div>
    </>
  );
}
