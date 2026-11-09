// Shared pieces for console controls that change something on the server.
// A success toast only follows a call that resolved; the demo (no server)
// says the action needs `crenel serve` instead of pretending.
import { useState } from "react";
import { Server, Trash2 } from "lucide-react";
import { Button } from "./ui.tsx";
import { Input } from "./arc/input/input.tsx";
import { SlideConfirm } from "./bencho/SlideConfirm.tsx";
import "./bencho/SlideConfirm.css";
import { useToast } from "./toast.tsx";
import { useData } from "../data/api.ts";
import { NEEDS_SERVER, ignoreFinding, removeTarget } from "../data/actions.ts";
import "../styles/console-a.css";

/** Server error messages are English; give the known ones in French. */
export function frError(err: unknown): string {
  const m = err instanceof Error ? err.message : String(err);
  if (/^no model/i.test(m)) return "Aucun modèle sur le serveur: relancez crenel serve avec claude -p disponible. Le verdict déterministe reste valable.";
  if (/^no such finding/i.test(m)) return "Ce finding n'existe plus côté serveur.";
  return m;
}

/** run(fn, ok, failTitle): live only, success toast after the call resolved, error toast otherwise. */
export function useServerAction() {
  const toast = useToast();
  const { live } = useData();
  return async function run<T>(fn: () => Promise<T>, ok: (r: T) => { title: string; description?: string } | null, failTitle: string): Promise<T | undefined> {
    if (!live) { toast({ type: "info", title: failTitle, description: NEEDS_SERVER }); return undefined; }
    try {
      const r = await fn();
      const msg = ok(r);
      if (msg) toast({ type: "success", ...msg });
      return r;
    } catch (err) {
      toast({ type: "error", title: failTitle, description: frError(err) });
      return undefined;
    }
  };
}

/** Inline "ignore" form for a finding: a short optional reason, honest about what ignoring does. */
export function IgnoreFinding({ uid, title, onClose }: { uid: string; title: string; onClose: () => void }) {
  const run = useServerAction();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    const r = await run(() => ignoreFinding(uid, true, reason.trim()),
      () => ({ title: "Finding ignoré", description: "Ignoré dans la console, il reste dans les rapports." }), "Finding non ignoré");
    setBusy(false);
    if (r) onClose();
  }
  return (
    <form className="ignore-form" onSubmit={submit} aria-label={`Ignorer ${title}`}>
      <Input label="Raison (facultatif)" description="Faux positif, risque accepté..." value={reason} maxLength={500}
        onChange={(e) => setReason(e.target.value)} autoFocus spellCheck={false} />
      <p className="ignore-note">Ignoré dans la console seulement: il reste dans les rapports, le SARIF et la CI (fail-on).</p>
      <div className="ignore-act">
        <Button type="submit" size="sm" disabled={busy}>{busy ? "Envoi..." : "Ignorer"}</Button>
        <Button size="sm" variant="quiet" onClick={onClose}>Annuler</Button>
      </div>
    </form>
  );
}

/** Declared hosts (scope.allowedHosts), each removable behind a slide confirmation. */
export function HostList({ empty = "Aucun hôte déclaré." }: { empty?: string }) {
  const { hosts, live } = useData();
  const toast = useToast();
  const run = useServerAction();
  const [asking, setAsking] = useState<string | null>(null);
  if (!hosts.length) return <div className="srow muted">{empty}</div>;
  return (
    <>
      {hosts.map((h) => (
        <div key={h} className="srow host-row">
          <span className="ichip sm" aria-hidden="true"><Server size={14} /></span>
          <span className="srow-tx mono">{h}</span>
          {asking === h ? (
            <div className="confirm-slide bencho danger-slide">
              <SlideConfirm width={240} label="Glisser pour retirer" doneLabel="Retrait..." onConfirm={async () => {
                await run(() => removeTarget(h), () => ({ title: `${h} retiré`, description: "Crenel n'enverra plus de requête à cet hôte." }), `${h} non retiré`);
                setAsking(null);
              }} />
              <Button size="sm" variant="quiet" onClick={() => setAsking(null)}>Annuler</Button>
            </div>
          ) : (
            <Button size="sm" variant="ghost" className="danger-ghost"
              onClick={() => (live ? setAsking(h) : toast({ type: "info", title: "Retrait impossible ici", description: NEEDS_SERVER }))}>
              <Trash2 size={13} /> Retirer
            </Button>
          )}
        </div>
      ))}
    </>
  );
}
