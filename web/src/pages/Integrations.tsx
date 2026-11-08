import { useEffect, useState } from "react";
import { Github, MessageSquare, Webhook, Send, Trash2, ShieldCheck } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, CodeBlock, CopyButton, Pill, Segmented, Toggle } from "../components/ui.tsx";
import { Badge } from "../components/arc/badge/badge.tsx";
import { Input } from "../components/arc/input/input.tsx";
import { useToast } from "../components/toast.tsx";
import { cn } from "../lib/cn.ts";
import { ago, isLive, useData } from "../data/api.ts";
import {
  addWebhook, demoIntegrations, describeDelivery, getIntegrations, removeSlack, removeWebhook, saveSlack, sourceLabel, testIntegration,
  type DeliveryRecord, type IntegrationsState,
} from "../data/integrations.ts";

// The GitHub side runs in the user's repository: the Action uploads SARIF to
// code scanning and, optionally, keeps one PR comment. Nothing to switch on here.
const WORKFLOW = `permissions:
  contents: read
  security-events: write   # SARIF -> code scanning
  pull-requests: write     # only for pr-comment

steps:
  - uses: actions/checkout@<sha>
  - uses: GlamgarOnDiscord/crenel@<sha>
    with:
      config: crenel.config.yaml
      fail-on: high
      pr-comment: "true"`;

function Row({ title, desc, control }: { title: string; desc: React.ReactNode; control?: React.ReactNode }) {
  return (
    <div className="srow">
      <div className="srow-tx"><div className="srow-t">{title}</div><div className="muted srow-d">{desc}</div></div>
      {control}
    </div>
  );
}

function Status({ on, label }: { on: boolean; label: string }) {
  return <Badge size="sm" tone={on ? "success" : "neutral"}>{label}</Badge>;
}

export function Integrations() {
  const toast = useToast();
  const data = useData();
  const live = data.live;
  const [st, setSt] = useState<IntegrationsState | null>(live ? null : demoIntegrations);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [slackUrl, setSlackUrl] = useState("");
  const [hookName, setHookName] = useState("");
  const [hookUrl, setHookUrl] = useState("");
  const [newSecret, setNewSecret] = useState<{ name: string; secret: string } | null>(null);

  useEffect(() => {
    if (!live) { setSt(demoIntegrations); return; }
    const ac = new AbortController();
    getIntegrations(ac.signal).then((s) => { setSt(s); setLoadError(null); }).catch((err: Error) => { if (!ac.signal.aborted) setLoadError(err.message); });
    return () => ac.abort();
  }, [live]);

  // Every write goes through the server, which validates, stores secrets in
  // .crenel/secrets.json and answers with the new state. In demo, nothing is sent.
  async function act(key: string, fn: () => Promise<IntegrationsState>, ok: string): Promise<IntegrationsState | null> {
    if (!isLive()) { toast({ type: "info", title: "Démo", description: "Lancez crenel serve: rien n'est écrit ni envoyé ici." }); return null; }
    setBusy(key);
    try {
      const next = await fn();
      setSt(next);
      toast({ type: "success", title: ok });
      return next;
    } catch (err) {
      toast({ type: "error", title: "Non enregistré", description: (err as Error).message });
      return null;
    } finally { setBusy(null); }
  }

  async function sendTest(target: "slack" | `webhook:${string}`) {
    if (!isLive()) { toast({ type: "info", title: "Démo", description: "Lancez crenel serve pour envoyer un vrai message de test." }); return; }
    setBusy(`test:${target}`);
    try {
      const r: DeliveryRecord = await testIntegration(target);
      toast({ type: r.ok ? "success" : "error", title: r.ok ? "Message de test envoyé" : "Test non envoyé", description: describeDelivery(r) });
      setSt(await getIntegrations());
    } catch (err) {
      toast({ type: "error", title: "Test non envoyé", description: (err as Error).message });
    } finally { setBusy(null); }
  }

  if (!st) {
    return (
      <>
        <Topbar crumb="Espace" title="Intégrations" insight={<>Elles ne reçoivent que des failles prouvées, jamais des pistes.</>} />
        <div className="content"><Card title="Intégrations"><div className="pad muted">{loadError ? `Lecture impossible: ${loadError}` : "Lecture de la configuration…"}</div></Card></div>
      </>
    );
  }

  const slackOn = st.slack.enabled && st.slack.configured;
  const hooksOn = st.webhooks.filter((w) => w.enabled && w.source && !String(w.source).startsWith("error")).length;

  return (
    <>
      <Topbar crumb="Espace" title="Intégrations" insight={<>Elles ne reçoivent que des failles <b>prouvées</b>, jamais des pistes.</>} />
      <div className="content">
        {!live && <p className="muted small-p integ-demo">Démo: lancez <code>crenel serve</code> pour configurer vos vraies intégrations. Rien n'est envoyé depuis cette page.</p>}

        <section className="folders" aria-label="État des intégrations">
          <div className="folder active">
            <div className="fh">
              <span className="ichip brand" aria-hidden="true"><Github size={16} /></span>
              <div><div className="nm">GitHub</div><div className="url"><Badge size="sm" tone="neutral">via l'Action</Badge></div></div>
            </div>
            <p className="muted small-p">SARIF vers le code scanning, et un commentaire de PR qui résume les failles prouvées.</p>
          </div>
          <div className={cn("folder", slackOn && "active")}>
            <div className="fh">
              <span className={cn("ichip", slackOn && "brand")} aria-hidden="true"><MessageSquare size={16} /></span>
              <div><div className="nm">Slack</div><div className="url"><Status on={slackOn} label={slackOn ? "actif" : st.slack.configured ? "désactivé" : "non configuré"} /></div></div>
            </div>
            <p className="muted small-p">Un message par tâche, pour chaque nouvelle faille prouvée {st.slack.minSeverity === "critical" ? "critique" : "haute ou critique"}.</p>
          </div>
          <div className={cn("folder", hooksOn > 0 && "active")}>
            <div className="fh">
              <span className={cn("ichip", hooksOn > 0 && "brand")} aria-hidden="true"><Webhook size={16} /></span>
              <div><div className="nm">Webhooks</div><div className="url"><Status on={hooksOn > 0} label={hooksOn ? `${hooksOn} actif${hooksOn > 1 ? "s" : ""}` : "aucun"} /></div></div>
            </div>
            <p className="muted small-p">Un POST JSON signé (HMAC-SHA256) par faille prouvée et par tâche terminée.</p>
          </div>
        </section>

        <div className="integ-grid">
          <Card title="Slack" icon={<MessageSquare size={14} />} meta="Incoming Webhook">
            <Row title="Envoyer les nouvelles failles prouvées"
              desc={st.slack.configured ? <>Webhook {st.slack.destination}, depuis {sourceLabel(st.slack.source)}.</> : <>Aucun webhook. Collez l'URL ci-dessous ou définissez <code>{st.slack.envVar}</code>.</>}
              control={<Toggle on={st.slack.enabled} label="Slack activé" onChange={(v) => { if (!busy) void act("slack", () => saveSlack({ enabled: v }), v ? "Slack activé" : "Slack désactivé"); }} />} />
            <Row title="Seuil" desc="Seules les failles prouvées à ce niveau ou au-dessus partent."
              control={<Segmented label="Seuil Slack" value={st.slack.minSeverity} items={[{ id: "high", label: "Haute+" }, { id: "critical", label: "Critique" }]}
                onChange={(v) => { if (!busy) void act("slack", () => saveSlack({ minSeverity: v }), "Seuil enregistré"); }} />} />
            <form className="pad integ-form" onSubmit={(e) => { e.preventDefault(); if (!slackUrl.trim()) return; void act("slack", () => saveSlack({ webhookUrl: slackUrl.trim() }), "Webhook Slack enregistré").then((r) => { if (r) setSlackUrl(""); }); }}>
              <Input label="URL du webhook" type="password" autoComplete="off" spellCheck={false} placeholder="https://hooks.slack.com/services/…"
                value={slackUrl} onChange={(e) => setSlackUrl(e.target.value)}
                description="Gardée dans .crenel/secrets.json (0600), jamais affichée ni journalisée." />
              <div className="integ-actions">
                <Button size="sm" type="submit" disabled={!slackUrl.trim() || !!busy}>Enregistrer</Button>
                <Button size="sm" variant="ghost" disabled={!st.slack.configured || !!busy} onClick={() => void sendTest("slack")}><Send size={13} aria-hidden="true" /> Tester</Button>
                <Button size="sm" variant="quiet" disabled={!st.slack.configured || st.slack.source === "env" || !!busy} onClick={() => void act("slack", removeSlack, "Webhook Slack retiré")}>Retirer</Button>
              </div>
            </form>
          </Card>

          <Card title="Webhooks signés" icon={<Webhook size={14} />} meta="HMAC-SHA256">
            {st.webhooks.length === 0 && <Row title="Aucun webhook" desc="Ajoutez un endpoint: il reçoit un POST signé par faille prouvée et par tâche." />}
            {st.webhooks.map((w) => (
              <Row key={w.name} title={w.name}
                desc={<>{w.destination} · secret {sourceLabel(w.source)} · {w.events.join(", ")}</>}
                control={<div className="integ-actions">
                  <Button size="sm" variant="ghost" disabled={!!busy || !w.source} onClick={() => void sendTest(`webhook:${w.name}`)}><Send size={13} aria-hidden="true" /> Tester</Button>
                  <Button size="sm" variant="quiet" aria-label={`Supprimer ${w.name}`} disabled={!!busy} onClick={() => void act(`hook:${w.name}`, () => removeWebhook(w.name), `Webhook ${w.name} supprimé`)}><Trash2 size={13} aria-hidden="true" /></Button>
                </div>} />
            ))}
            {newSecret && (
              <div className="pad integ-secret" role="status">
                <div className="srow-t">Secret de signature de {newSecret.name}</div>
                <p className="muted small-p">Affiché une seule fois. Votre endpoint vérifie <code>X-Crenel-Signature</code> avec lui.</p>
                <div className="integ-actions"><code className="mono integ-secret-v">{newSecret.secret}</code><CopyButton text={newSecret.secret} what="le secret" /></div>
              </div>
            )}
            <form className="pad integ-form" onSubmit={(e) => {
              e.preventDefault();
              const name = hookName.trim().toLowerCase();
              void act("hook:new", () => addWebhook({ name, url: hookUrl.trim() }), `Webhook ${name} ajouté`).then((r) => {
                if (r) { if (r.secret) setNewSecret({ name, secret: r.secret }); setHookName(""); setHookUrl(""); }
              });
            }}>
              <div className="integ-row2">
                <Input label="Nom" placeholder="ops" value={hookName} onChange={(e) => setHookName(e.target.value)} autoComplete="off" />
                <Input label="URL (https)" placeholder="https://hooks.example.com/crenel" value={hookUrl} onChange={(e) => setHookUrl(e.target.value)} autoComplete="off" spellCheck={false} />
              </div>
              <div className="integ-actions"><Button size="sm" type="submit" disabled={!hookName.trim() || !hookUrl.trim() || !!busy}>Ajouter</Button></div>
            </form>
          </Card>

          <Card title="GitHub" icon={<Github size={14} />} meta="Action, SARIF, commentaire de PR">
            <div className="pad">
              <p className="muted small-p">Dans votre dépôt: le SARIF part dans le code scanning (upload-sarif épinglé par SHA) et, sur une PR, un seul commentaire est tenu à jour avec le <code>GITHUB_TOKEN</code> du workflow. Sur une PR venue d'un fork, le jeton est en lecture seule: le commentaire est sauté, le job ne casse pas.</p>
              <CodeBlock file=".github/workflows/crenel.yml" code={WORKFLOW} />
            </div>
          </Card>

          <Card title="Destinations autorisées" icon={<ShieldCheck size={14} />} meta="options.integrations.allowedHosts">
            <div className="pad">
              <p className="muted small-p">Crenel n'envoie de notification qu'à ces hôtes, en https, sans suivre de redirection. Une cible de scan ne peut pas en être une, et ces hôtes ne sont jamais scannés.</p>
              <div className="integ-hosts">
                {st.allowedHosts.length ? st.allowedHosts.map((h) => <Pill key={h}><span className="mono">{h}</span></Pill>) : <span className="muted small-p">Aucune: ajoutez Slack ou un webhook.</span>}
              </div>
              {st.scanHosts.length > 0 && <p className="muted small-p">Cibles de scan (refusées comme destinations): <span className="mono">{st.scanHosts.join(", ")}</span></p>}
            </div>
          </Card>
        </div>

        <Card title="Derniers envois" meta="journalisés dans .crenel/audit.jsonl">
          {st.recent.length === 0 ? <Row title="Aucun envoi" desc="Les envois et les refus apparaîtront ici, avec l'hôte et le statut, jamais l'URL complète." /> : st.recent.map((r, i) => (
            <Row key={`${r.at}-${i}`} title={r.integration} desc={<>{describeDelivery(r)} · {ago(r.at)}</>}
              control={<Badge size="sm" tone={r.ok ? "success" : "neutral"}>{r.ok ? "envoyé" : "échec"}</Badge>} />
          ))}
        </Card>
      </div>
    </>
  );
}
