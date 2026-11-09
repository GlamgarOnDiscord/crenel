/* Console actions that change something on the server (crenel serve). Each
   one calls a real route of src/server/http.ts and refreshes the state, so a
   page never shows a success that did not happen. In the demo (no server)
   they throw, and callers say the action needs `crenel serve`. */
import { apiFetch, refresh } from "./api.ts";

export const NEEDS_SERVER = "Disponible avec crenel serve (la démo n'a pas de serveur).";

async function then<T>(p: Promise<T>): Promise<T> { const r = await p; await refresh(); return r; }

/** Ignore a finding in the console (accepted risk, false positive), or undo it. Never deletes it. */
export const ignoreFinding = (uid: string, ignored: boolean, reason = "") =>
  then(apiFetch<{ ignored: boolean }>(`api/findings/${encodeURIComponent(uid)}/ignore`, { method: "POST", body: { ignored, reason } }));

/** The model's advice on a finding (needs claude -p on the server). Advice only: validators decide the state. */
export const triageFinding = (uid: string, model?: string) =>
  then(apiFetch<{ advice: string; note: string }>(`api/findings/${encodeURIComponent(uid)}/triage`, { method: "POST", body: model ? { model } : {} }));

export const archiveRun = (id: string, archived: boolean) =>
  then(apiFetch<{ archived: boolean }>(`api/runs/${encodeURIComponent(id)}/archive`, { method: "POST", body: { archived } }));

export const rateRun = (id: string, useful: boolean) =>
  apiFetch<{ ok: true }>(`api/runs/${encodeURIComponent(id)}/feedback`, { method: "POST", body: { useful } });

/** Remove a host from scope.allowedHosts (and its "always" grant). */
export const removeTarget = (host: string) =>
  then(apiFetch<{ allowedHosts: string[] }>(`api/targets/${encodeURIComponent(host)}`, { method: "DELETE" }));

/** The global switch: stops every running run. */
export const killAll = () => then(apiFetch<{ stopped: number }>("api/kill", { method: "POST" }));

/** Accept the current findings as the baseline for `crenel scan --baseline` (new ones are regressions). */
export const saveBaseline = () => then(apiFetch<{ saved: boolean }>("api/baseline", { method: "POST" }));

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** The SARIF of the console's findings, as `crenel scan --sarif` writes it. */
export async function downloadSarif(project: string) {
  const sarif = await apiFetch<unknown>("api/sarif");
  download(`${project || "crenel"}.sarif`, JSON.stringify(sarif, null, 2), "application/sarif+json");
}

/** The generated regression test file (tests/crenel/regression.test.ts in a repo). */
export async function downloadRegressionFile() {
  const file = await apiFetch<string>("api/tests?format=file");
  if (!file) throw new Error("Aucun test généré pour l'instant : lancez /test dans l'agent.");
  download("crenel.regression.test.ts", file, "text/plain");
}

/** Copy to the clipboard; false when the browser refuses (no permission, insecure context). */
export async function copyText(text: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

/** A deep link to a console route (hash router), for "Copier le lien". */
export const linkTo = (route: string) => `${location.origin}${location.pathname}#${route.startsWith("/") ? route : `/${route}`}`;
