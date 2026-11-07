import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Segmented } from "../components/ui.tsx";
import { Input } from "../components/arc/input/input.tsx";
import { Progress } from "../components/arc/progress/progress.tsx";
import { Checklist } from "../components/bencho/Checklist.tsx";
import "../components/bencho/Checklist.css";
import { cn } from "../lib/cn.ts";

const CHECKS = ["Je possède cette cible", "C'est un staging, pas la production", "J'ai deux comptes de test"] as const;
const URL_RE = /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i;
const REPO_RE = /^[\w.-]+\/[\w.-]+$/;

export function Onboarding() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"url" | "repo">("url");
  const [url, setUrl] = useState("staging.acme.app");
  const [repo, setRepo] = useState("acme/acme-app");
  const [checks, setChecks] = useState<boolean[]>([false, false, false]);
  const [error, setError] = useState<string | undefined>();
  const [shake, setShake] = useState(false);
  useEffect(() => { document.title = "Ajouter une cible · Crenel"; }, []);
  const value = mode === "url" ? url : repo;
  const valid = (mode === "url" ? URL_RE : REPO_RE).test(value.trim());
  const owner = checks[0] === true;
  const done = (valid ? 1 : 0) + checks.filter(Boolean).length;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!valid) {
      setError(mode === "url" ? "Une adresse comme staging.acme.app" : "Un dépôt comme acme/acme-app");
      setShake(true); setTimeout(() => setShake(false), 300);
      return;
    }
    if (!owner) { setError("Cochez au moins « Je possède cette cible »."); setShake(true); setTimeout(() => setShake(false), 300); return; }
    navigate("/app/agent", { state: { prompt: `Premier scan de ${value.trim()}` } });
  }

  return (
    <div className="onb">
      <div className="onb-in t-reveal">
        <div className="halo"><Mascot size={104} /></div>
        <div className="onb-hd">
          <h1>Ajoutez une cible</h1>
          <p className="muted">Un premier scan, lecture seule, en moins de deux minutes.</p>
        </div>

        <Segmented items={[{ id: "url", label: "Site" }, { id: "repo", label: "Dépôt GitHub" }]} value={mode} onChange={(m) => { setMode(m); setError(undefined); }} label="Type de cible" />

        <form className="card onb-card" onSubmit={submit} noValidate>
          <div className="onb-progress"><Progress value={done} max={4} label="Prêt à scanner" showValue /></div>
          <div className={cn("t-input-wrap", error && "is-error")}>
            <div className={cn("t-input", shake && "is-shaking")}>
              <Input key={mode} label={mode === "url" ? "URL du site" : "Dépôt"} description={mode === "url" ? "Staging de préférence" : "propriétaire/nom"}
                value={value} error={error} spellCheck={false} autoComplete="off"
                onChange={(e) => { (mode === "url" ? setUrl : setRepo)(e.target.value); setError(undefined); }}
                placeholder={mode === "url" ? "staging.acme.app" : "acme/acme-app"} />
            </div>
          </div>
          <div className="bencho onb-checks">
            <Checklist tasks={CHECKS} corner={14} box={18} onChange={(d) => { setChecks(d); if (d[0]) setError(undefined); }} />
          </div>
          <button type="submit" className="btn btn-block" aria-disabled={!(valid && owner)}>Lancer le premier scan <ArrowRight size={15} /></button>
        </form>

        <Link to="/app/overview" className="muted small">Passer, voir une démo</Link>
      </div>
    </div>
  );
}
