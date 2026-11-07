import { Github, GitBranch, MessageSquare, Webhook, KeyRound, Boxes } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";

const items = [
  { icon: Github, name: "GitHub", desc: "Scanner les PR et commenter les findings.", on: true },
  { icon: GitBranch, name: "CI / CD", desc: "Lancer Crenel en CI, bloquer sur régression prouvée.", on: true },
  { icon: MessageSquare, name: "Slack", desc: "Alerter sur un nouveau critique prouvé.", on: false },
  { icon: Webhook, name: "Webhooks", desc: "Envoyer chaque finding à votre endpoint.", on: false },
  { icon: KeyRound, name: "Clé CLI", desc: "Jeton pour `crenel` en local et en CI.", on: true },
  { icon: Boxes, name: "Jira", desc: "Ouvrir un ticket par finding prouvé.", on: false },
];

export function Integrations() {
  return (
    <>
      <Topbar crumb="Réglages" title="Intégrations" />
      <div className="content">
        <section className="folders">
          {items.map((it) => (
            <div key={it.name} className="folder" style={{ cursor: "default" }}>
              <div className="fh">
                <span className="fi"><it.icon size={18} /></span>
                <div><div className="nm">{it.name}</div><div className="url">{it.on ? "connecté" : "non connecté"}</div></div>
              </div>
              <p className="muted" style={{ margin: 0, fontSize: 13, lineHeight: 1.5 }}>{it.desc}</p>
              <div><Button variant="ghost" size="sm">{it.on ? "Configurer" : "Connecter"}</Button></div>
            </div>
          ))}
        </section>
      </div>
    </>
  );
}
