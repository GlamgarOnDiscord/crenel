import { useState } from "react";
import { Github, GitBranch, MessageSquare, Webhook, KeyRound, Boxes } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Toggle } from "../components/ui.tsx";
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
  const [on, setOn] = useState<Record<string, boolean>>(Object.fromEntries(items.map((i) => [i.name, i.on])));
  return (
    <>
      <Topbar crumb="Espace" title="Intégrations" />
      <div className="content">
        <p className="lede">Branchez Crenel là où vous travaillez déjà. Les intégrations ne reçoivent que des failles prouvées, jamais des pistes.</p>
        <section className="folders">
          {items.map((it) => (
            <div key={it.name} className={cn("folder", on[it.name] && "active")}>
              <div className="fh">
                <span className={cn("sq", on[it.name] ? "amber" : "slate")} aria-hidden="true"><it.icon size={18} /></span>
                <div><div className="nm">{it.name}</div><div className="url">{on[it.name] ? "connecté" : "non connecté"}</div></div>
                <span className="sp" />
                <Toggle on={!!on[it.name]} label={`${it.name}: ${on[it.name] ? "connecté" : "non connecté"}`} onChange={(v) => setOn((m) => ({ ...m, [it.name]: v }))} />
              </div>
              <p className="muted small-p">{it.desc}</p>
            </div>
          ))}
        </section>
      </div>
    </>
  );
}
