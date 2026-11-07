import { useState } from "react";
import { TerminalSquare } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, Card, CopyButton } from "../components/ui.tsx";
import { MetricCard } from "../components/arc/metric-card/metric-card.tsx";
import { Tooltip } from "../components/arc/tooltip/tooltip.tsx";
import { useData } from "../data/api.ts";
import { cn } from "../lib/cn.ts";

const leak = (code?: number) => code !== undefined && code >= 200 && code < 300;
const REPLAY = "curl -i -H 'authorization: Bearer $TOKEN_A' https://staging.acme.app/api/projects/proj_b_1";

export function Authorization() {
  const { authzActors, authzResources, authzReplay, live } = useData();
  const [sel, setSel] = useState<{ a: string; r: string }>({ a: live ? "a" : "a-member", r: "project" });
  const actor = authzActors.find((a) => a.id === sel.a) ?? authzActors[0]!;
  const res = authzResources.find((r) => r.id === sel.r) ?? authzResources[0] ?? { id: "", label: "aucune ressource déclarée", route: "" };
  const code = actor.cells[res.id];
  const replay = authzReplay[`${actor.id}:${res.id}`] ?? REPLAY;
  const fails = authzActors.reduce((n, a) => n + Object.values(a.cells).filter(leak).length, 0);
  const total = authzActors.reduce((n, a) => n + Object.values(a.cells).filter((c) => c !== undefined).length, 0);
  const leaked = authzActors.flatMap((a) => authzResources.filter((r) => leak(a.cells[r.id])).map((r) => `${a.label} lit ${r.label}`));

  return (
    <>
      <Topbar width="mid" scoped title="Autorisation" insight={live ? (leaked.length ? <><b>{leaked.join(", ")}</b> du compte B. Les {total - fails} autres requêtes sont refusées.</> : <>{total ? `Les ${total} requêtes rejouées sont refusées.` : "Matrice pas encore rejouée."}</>) : <>Le compte A <b>lit les projets du compte B</b>. Les 10 autres requêtes sont refusées.</>} actions={<Button size="sm" to="/app/agent" state={{ prompt: "/authz" }}><TerminalSquare size={14} /> Rejouer la matrice</Button>} />
      <div className="content mid">
        <div className="metrics">
          <MetricCard label="Requêtes rejouées" value={total} context={live ? authzActors.map((a) => a.label).join(", ") : "compte A, admin et anonyme"} />
          <MetricCard label="Fuites prouvées" value={fails} context="réponse 200 sur une ressource de B" />
          <MetricCard label="Refusées" value={total - fails} context="401, 403 ou 404, comme attendu" />
        </div>
        <Card title="Matrice inter-tenant" meta={<><b className="crit-ink">{fails} fuites</b>&nbsp;sur {total} requêtes</>}>
          <div className="matrix-wrap">
            <table className="matrix">
              <caption className="sr-only">Réponses obtenues par acteur et par ressource du compte B</caption>
              <thead>
                <tr>
                  <th scope="col"><span className="faint">acteur</span> <span aria-hidden="true">→</span> ressource de B</th>
                  {authzResources.map((r) => (
                    <th key={r.id} scope="col"><span className="mx-r">{r.label}</span><span className="mx-route mono">{r.route}</span></th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {authzActors.map((a) => (
                  <tr key={a.id}>
                    <th scope="row"><span className="mx-a">{a.label}</span><span className="mx-role">{a.role}</span></th>
                    {authzResources.map((r) => {
                      const c = a.cells[r.id];
                      const on = sel.a === a.id && sel.r === r.id;
                      return (
                        <td key={r.id}>
                          <Tooltip content={`${r.route} → ${c}`}><button type="button" className={cn("cell", leak(c) ? "leak" : "denied", on && "on")} aria-pressed={on}
                            aria-label={`${a.label} ${a.role}, ${r.label}: ${c ?? "non testé"}, ${c === undefined ? "non testé" : leak(c) ? "fuite" : "refusé"}`}
                            onClick={() => setSel({ a: a.id, r: r.id })}>
                            <span className="mono">{c ?? "—"}</span><span className="cell-v">{c === undefined ? "non testé" : leak(c) ? "fuite" : "refusé"}</span>
                          </button></Tooltip>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mx-legend"><span><i className="lg leak" />fuite prouvée</span><span><i className="lg denied" />refusé, comme attendu</span></div>
        </Card>

        <Card title="Requête sélectionnée" meta={`${actor.label} (${actor.role}) → ${res.label} de B`}>
          <div className="pad stack">
            {leak(code) ? (
              <>
                <div className="cmd"><code><span className="k" aria-hidden="true">$</span> {replay}</code><CopyButton text={replay} /></div>
                <div className="mono evidence bad"><span className="elbow" aria-hidden="true" />HTTP {code}, l'objet de B est renvoyé (attendu 401, 403 ou 404)</div>
              </>
            ) : (
              <div className="mono evidence"><span className="elbow" aria-hidden="true" />{code === undefined ? `${res.route}: pas encore rejoué.` : `${res.route} → HTTP ${code}. Refusé, rien à prouver ici.`}</div>
            )}
          </div>
        </Card>
      </div>
    </>
  );
}
