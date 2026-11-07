import { useState } from "react";
import { Github, GitBranch, MessageSquare, Webhook, KeyRound, Boxes } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Toggle } from "../components/ui.tsx";
import { Badge } from "../components/arc/badge/badge.tsx";
import { useToast } from "../components/toast.tsx";
import { cn } from "../lib/cn.ts";

const items = [
  { icon: Github, name: "GitHub", desc: "Scanner chaque PR et commenter les failles prouvées.", on: true },
  { icon: GitBranch, name: "CI / CD", desc: "Lancer Crenel en CI, bloquer sur une régression prouvée.", on: true },
  { icon: KeyRound, name: "Clé CLI", desc: "Jeton pour crenel en local et en CI.", on: true },
  { icon: MessageSquare, name: "Slack", desc: "Alerter sur un nouveau critique prouvé.", on: false },
  { icon: Webhook, name: "Webhooks", desc: "Envoyer chaque finding à votre endpoint.", on: false },
  { icon: Boxes, name: "Jira", desc: "Ouvrir un ticket par faille prouvée.", on: false },
];

export function Integrations() {
  const toast = useToast();
  const [on, setOn] = useState<Record<string, boolean>>(Object.fromEntries(items.map((i) => [i.name, i.on])));
  return (
    <>
      <Topbar crumb="Espace" title="Intégrations" insight={<>Elles ne reçoivent que des failles prouvées, jamais des pistes.</>} />
      <div className="content">
        <section className="folders">
          {items.map((it) => (
            <div key={it.name} className={cn("folder", on[it.name] && "active")}>
              <div className="fh">
                <span className={cn("ichip", on[it.name] && "brand")} aria-hidden="true"><it.icon size={16} /></span>
                <div><div className="nm">{it.name}</div><div className="url">{on[it.name] ? <Badge size="sm" tone="success">connecté</Badge> : <Badge size="sm" tone="neutral">non connecté</Badge>}</div></div>
                <span className="sp" />
                <Toggle on={!!on[it.name]} label={`${it.name}: ${on[it.name] ? "connecté" : "non connecté"}`} onChange={(v) => { setOn((m) => ({ ...m, [it.name]: v })); toast({ type: v ? "success" : "info", title: v ? `${it.name} connecté` : `${it.name} déconnecté` }); }} />
              </div>
              <p className="muted small-p">{it.desc}</p>
            </div>
          ))}
        </section>
      </div>
    </>
  );
}
