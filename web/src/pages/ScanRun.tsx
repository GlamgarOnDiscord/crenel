import { useEffect, useRef, useState } from "react";
import { ArrowUp, Sparkles, Check, Loader2, Paperclip, User } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Dots, ModelChip } from "../components/ui.tsx";
import { scanSteps } from "../data/mock.ts";

interface Turn { q: string; a: string; done: boolean }

// Canned, deterministic replies so the console feels alive without a backend.
function reply(q: string): string {
  const s = q.toLowerCase();
  if (s.includes("stripe") || s.includes("secret")) return "La clé Stripe de dist/app.js:5 est côté client, donc publique. À traiter comme compromise: révoquez-la, déplacez l'appel côté serveur, et j'ai un test qui échoue tant que le bundle contient sk_live_.";
  if (s.includes("authz") || s.includes("autoris")) return "Je génère la matrice inter-tenant: le compte A tente chaque ressource du compte B; tout ce qui n'est pas 401/403/404 est une faille prouvée. Donne-moi une URL de staging et deux comptes de test pour lancer les sondes.";
  if (s.includes("fix") || s.includes("corrig") || s.includes("test")) return "Pour chaque finding prouvé, j'émets un test de régression et je prépare un diff. Une fois en CI, la faille ne peut plus revenir sans casser le build.";
  return "Compris. Je reste en lecture seule sur acme-app (staging), périmètre verrouillé au réseau. Dis-moi la cible ou le finding et je lance l'analyse.";
}

export function ScanRun() {
  const [shown, setShown] = useState(1);
  const running = shown < scanSteps.length;
  const [input, setInput] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const streamRef = useRef<number | null>(null);

  useEffect(() => {
    if (!running) return;
    const t = setTimeout(() => setShown((s) => s + 1), 900);
    return () => clearTimeout(t);
  }, [shown, running]);

  // Clear any in-flight stream interval on unmount, so leaving the page mid-reply
  // does not keep firing setState on an unmounted component.
  useEffect(() => () => {
    if (streamRef.current !== null) window.clearInterval(streamRef.current);
  }, []);

  function send() {
    const q = input.trim();
    if (!q || streamRef.current !== null) return;
    setInput("");
    const full = reply(q);
    setTurns((t) => [...t, { q, a: "", done: false }]);
    let i = 0;
    const id = window.setInterval(() => {
      i += 2;
      setTurns((t) => {
        const next = [...t];
        const last = next[next.length - 1];
        if (!last) return t;
        last.a = full.slice(0, i);
        if (i >= full.length) { last.done = true; window.clearInterval(id); streamRef.current = null; }
        return next;
      });
    }, 16);
    streamRef.current = id;
  }

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

            {turns.map((t, i) => (
              <div key={`turn-${i}`} className="fade-up">
                <div className="step"><div className="sh"><span className="ix"><User size={12} /></span><span>{t.q}</span></div></div>
                <div className="step"><div className="sh"><span className="ix"><Sparkles size={12} /></span><span>Crenel</span></div>
                  <div className="body"><div className="assistant">{t.a}{!t.done && <span className="cursor cursor-blink" />}</div></div>
                </div>
              </div>
            ))}
          </div>

          <div className="prompt">
            <textarea
              rows={2}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
              placeholder="Demande à Crenel: scanner la cible, expliquer un finding, générer un test d'isolation…"
            />
            <div className="row">
              <ModelChip name="Opus 4.8" />
              <span className="chipbtn" style={{ padding: "5px 9px" }}><Paperclip size={13} /></span>
              <div className="slash">{["/scan", "/explain", "/fix", "/authz"].map((s) => (
                <button key={s} className="s" onClick={() => setInput((v) => (v ? v + " " : "") + s)}>{s}</button>
              ))}</div>
              <span className="sp" />
              <button className="send" aria-label="Envoyer" onClick={send}><ArrowUp size={16} /></button>
            </div>
          </div>
          <p className="note">Périmètre verrouillé au réseau. L'agent ne peut toucher que les hôtes déclarés, en lecture seule par défaut.</p>
        </div>
      </div>
    </>
  );
}
