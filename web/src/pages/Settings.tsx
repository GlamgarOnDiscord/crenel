import { useEffect, useState } from "react";
import { OctagonX } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, CodeBlock, Pill, Toggle } from "../components/ui.tsx";
import { UsageMeter } from "../components/arc/usage-meter/usage-meter.tsx";
import { useToast } from "../components/toast.tsx";
import { HostList, useServerAction } from "../components/console-actions.tsx";
import { apiFetch, isLive, useData } from "../data/api.ts";
import { killAll } from "../data/actions.ts";
import { ciWorkflowYaml, failOnOf, SCHEDULE_YAML, type CiPolicy } from "../lib/console.ts";
import "../styles/console-a.css";

function Row({ title, desc, control }: { title: string; desc: string; control: React.ReactNode }) {
  return (
    <div className="srow">
      <div className="srow-tx"><div className="srow-t">{title}</div><div className="muted srow-d">{desc}</div></div>
      {control}
    </div>
  );
}

interface ToolboxState { backend: "docker" | "wsl"; ready: boolean; reason?: string; options?: { wsl?: { distro?: string } } | null }

/** options.toolbox.backend: the Docker image (default) or a WSL distro on Windows. Written to the config by the server. */
function ToolboxCard() {
  const toast = useToast();
  const [st, setSt] = useState<ToolboxState | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!isLive()) return;
    apiFetch<ToolboxState>("api/toolbox").then(setSt).catch(() => {});
  }, []);
  const wsl = st?.backend === "wsl";
  const distro = st?.options?.wsl?.distro ?? "kali-linux";
  const status = !st ? "Désactivé par défaut. Les outils passent par le proxy à périmètre, sous WSL ils y sont dirigés, pas confinés."
    : st.ready ? `${wsl ? `WSL, distribution ${distro}` : "Docker"}: prêt.` : `${wsl ? `WSL, distribution ${distro}` : "Docker"}: ${st.reason ?? "indisponible"}.`;
  async function toggle(on: boolean) {
    if (!isLive()) { setSt({ backend: on ? "wsl" : "docker", ready: false, reason: "démo, rien n'est écrit", options: null }); return; }
    setBusy(true);
    try {
      await apiFetch("api/toolbox", { method: "PUT", body: { backend: on ? "wsl" : "docker" } });
      setSt(await apiFetch<ToolboxState>("api/toolbox"));
      toast({ type: "success", title: on ? "Outils WSL activés" : "Retour à Docker", description: "options.toolbox.backend écrit dans la config." });
    } catch (err) {
      toast({ type: "error", title: "Config non modifiée", description: (err as Error).message });
    } finally { setBusy(false); }
  }
  return (
    <Card title="Boîte à outils" meta="nuclei, katana, trufflehog, httpx">
      <Row title={`Utiliser WSL (${distro}) au lieu de Docker`} desc={status}
        control={<Toggle on={wsl} onChange={(v) => { if (!busy) void toggle(v); }} label="Utiliser WSL au lieu de Docker" />} />
    </Card>
  );
}

/** CI policy lives in the GitHub workflow (`fail-on`), so the toggles generate it. */
function CiPolicyCard() {
  const [p, setP] = useState<CiPolicy>({ critical: true, high: true });
  const failOn = failOnOf(p);
  const yaml = ciWorkflowYaml(p);
  return (
    <Card title="Politique de CI" meta="ce qui casse le build">
      <Row title="Bloquer sur critique prouvé" desc="Un critique prouvé fait échouer le job."
        control={<Toggle on={p.critical} onChange={(v) => setP({ critical: v, high: v && p.high })} label="Bloquer sur critique prouvé" />} />
      <Row title="Bloquer sur haute prouvée" desc="Une faille haute ou critique prouvée fait échouer le job."
        control={<Toggle on={p.high} onChange={(v) => setP({ high: v, critical: v || p.critical })} label="Bloquer sur haute prouvée" />} />
      <div className="srow is-off">
        <div className="srow-tx"><div className="srow-t">Bloquer sur les pistes</div><div className="muted srow-d">Jamais: une piste n'est pas prouvée, elle ne fait échouer aucun build.</div></div>
        <Pill>jamais</Pill>
      </div>
      <div className="yaml-wrap">
        <p className="yaml-note">{failOn ? <>Ces réglages donnent <code>fail-on: {failOn}</code>.</> : <>Rien ne bloque: le job ne casse jamais, le SARIF reste publié.</>} Copiez ce fichier dans <code>.github/workflows/crenel.yml</code>. Même règle en local avec <code>crenel scan --fail-on {failOn ?? "critical"}</code>. L'Action installe Crenel avec <code>--ignore-scripts</code>.</p>
        <CodeBlock file=".github/workflows/crenel.yml" code={yaml} />
      </div>
    </Card>
  );
}

/** The kill switch: stops every running run on this server. */
function KillCard() {
  const { tasks } = useData();
  const run = useServerAction();
  const [busy, setBusy] = useState(false);
  const running = tasks.filter((t) => t.status === "running" || t.status === "waiting").length;
  return (
    <Card title="Arrêt d'urgence" icon={<OctagonX size={14} />}>
      <Row title="Arrêter toutes les tâches" desc={`Stoppe chaque tâche en cours sur ce serveur, sondes comprises. ${running} en cours.`}
        control={<Button size="sm" variant="ghost" className="danger-ghost" disabled={busy} onClick={async () => {
          setBusy(true);
          await run(killAll, (r) => ({ title: r.stopped ? `${r.stopped} tâche${r.stopped > 1 ? "s" : ""} arrêtée${r.stopped > 1 ? "s" : ""}` : "Aucune tâche en cours", description: r.stopped ? "Plus aucune requête ne part." : undefined }), "Arrêt non effectué");
          setBusy(false);
        }}><OctagonX size={13} /> Tout arrêter</Button>} />
    </Card>
  );
}

export function Settings() {
  const { live, project } = useData();
  return (
    <>
      <Topbar width="narrow" crumb="Espace" title="Paramètres" insight={<>La CI ne casse que sur une faille <b>prouvée</b>, au niveau choisi par <code>fail-on</code>.</>} />
      <div className="content narrow">
        {!live && (
          <Card title="Utilisation ce mois-ci" meta="démo, chiffres d'exemple">
            <div className="pad">
              <UsageMeter label="Sondes envoyées aux hôtes déclarés" unit=" sondes" decimals={0} limit={2000}
                segments={[{ id: "acme", label: "acme-app", value: 1120 }, { id: "inbox", label: "inboxly", value: 310 }, { id: "page", label: "pagefold", value: 240 }]} />
            </div>
          </Card>
        )}

        <KillCard />

        <Card title="Scans planifiés" meta="GitHub Actions">
          <div className="yaml-wrap">
            <p className="yaml-note">crenel serve ne planifie rien. Pour un scan régulier, ajoutez un <code>schedule</code> au workflow de l'Action (déjà inclus dans le fichier ci-dessous). Un scan complet dure environ une minute.</p>
            <CodeBlock file=".github/workflows/crenel.yml" code={SCHEDULE_YAML} />
          </div>
        </Card>

        <CiPolicyCard />

        <ToolboxCard />

        {live ? (
          <Card title="Accès">
            <Row title="Outil local, un seul utilisateur" desc={`La console de ${project} est servie par crenel serve sur cette machine; son jeton donne l'accès. Pas de comptes ni d'invitations.`} control={null} />
          </Card>
        ) : (
          <Card title="Membres" meta="démo">
            {[["Tom", "propriétaire"], ["Pierre", "admin"]].map(([n, r]) => (
              <div key={n} className="srow">
                <span className="av">{n![0]}</span>
                <span className="srow-tx">{n}</span><span className="mono faint">{r}</span>
              </div>
            ))}
          </Card>
        )}

        <Card title="Zone de danger" className="danger-card" meta="scope.allowedHosts">
          <Row title="Retirer un hôte déclaré" desc="Retire l'hôte de la config (et son autorisation permanente). Crenel ne lui enverra plus de requête; les findings et l'historique restent." control={null} />
          <HostList />
        </Card>
      </div>
    </>
  );
}
