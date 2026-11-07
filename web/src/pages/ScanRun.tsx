import { useEffect, useState } from "react";
import { ArrowUp, Sparkles, Check, Loader2, Paperclip } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Dots, ModelChip } from "../components/ui.tsx";
import { scanSteps } from "../data/mock.ts";

export function ScanRun() {
  const [shown, setShown] = useState(1);
  const running = shown < scanSteps.length;
  useEffect(() => {
    if (!running) return;
    const t = setTimeout(() => setShown((s) => s + 1), 900);
    return () => clearTimeout(t);
  }, [shown, running]);

  return (
    <>
      <Topbar crumb="acme-app · staging" title="Agent" actions={<ModelChip name="Opus 4.8" />} />
      <div className="content" style={{ maxWidth: 860 }}>
        <div className="console">
          <div className="mono faint" style={{ fontSize: 12 }}>crenel scan --target acme-app --scope staging</div>

          <div className="run">
            {scanSteps.slice(0, shown).map((s, i) => {
              const isLast = i === shown - 1;
              const stat = running && isLast ? "run" : "ok";
              return (
                <div className="step fade-up" key={i}>
                  <div className="sh">
                    <span className={`ix ${stat}`}>{stat === "run" ? <Loader2 size={12} className="spin" /> : s.kind === "assistant" ? <Sparkles size={12} /> : <Check size={12} />}</span>
                    <span>{s.label}</span>
                    {s.dur && stat === "ok" && <span className="dur">{s.dur}</span>}
                  </div>
                  {s.body && (
                    <div className="body">
                      {s.kind === "assistant"
                        ? <div className="assistant">{s.body}{running && isLast && <span className="cursor cursor-blink" />}</div>
                        : <div className="toolcall"><span className="k">{s.tool}</span>{"  "}{s.body}</div>}
                    </div>
                  )}
                </div>
              );
            })}
            {running && <div className="loader-row" style={{ paddingLeft: 4 }}><Dots /> l'agent travaille</div>}
          </div>

          <div className="prompt">
            <textarea rows={2} defaultValue="" placeholder="Demande à Crenel: scanner la cible, expliquer un finding, générer un test d'isolation…" />
            <div className="row">
              <ModelChip name="Opus 4.8" />
              <span className="chipbtn" style={{ padding: "5px 9px" }}><Paperclip size={13} /></span>
              <div className="slash"><span className="s">/scan</span><span className="s">/explain</span><span className="s">/fix</span><span className="s">/authz</span></div>
              <span className="sp" />
              <button className="send" aria-label="Envoyer"><ArrowUp size={16} /></button>
            </div>
          </div>
          <p className="note">Périmètre verrouillé au réseau. L'agent ne peut toucher que les hôtes déclarés, en lecture seule par défaut.</p>
        </div>
      </div>
    </>
  );
}
