import { useState } from "react";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, Toggle } from "../components/ui.tsx";
import { useWorkspace } from "../lib/workspace.tsx";

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
  const [confirm, setConfirm] = useState(false);
  return (
    <>
      <Topbar crumb="Espace" title="Paramètres" />
      <div className="content narrow">
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
              <div className="confirm">
                <Button size="sm" variant="danger" autoFocus onClick={() => setConfirm(false)}>Supprimer définitivement</Button>
                <Button size="sm" variant="quiet" onClick={() => setConfirm(false)}>Annuler</Button>
              </div>
            ) : <Button size="sm" variant="ghost" className="danger-ghost" onClick={() => setConfirm(true)}>Supprimer</Button>} />
        </Card>
      </div>
    </>
  );
}
