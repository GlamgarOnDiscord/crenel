import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Github, Globe, ArrowRight } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { cn } from "../lib/cn.ts";

export function Onboarding() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"repo" | "url">("url");
  const [url, setUrl] = useState("staging.acme.app");
  const [repo, setRepo] = useState("acme/acme-app");
  const [owner, setOwner] = useState(false);
  useEffect(() => { document.title = "Ajouter une cible · Crenel"; }, []);
  const value = mode === "url" ? url : repo;
  const ok = owner && value.trim().length > 2;

  return (
    <div className="onb">
      <div className="onb-in">
        <div className="halo"><Mascot size={112} /></div>
        <div className="onb-hd">
          <h1>Ajoutez une cible</h1>
          <p className="muted">Un site ou un dépôt que vous possédez. Crenel lance un premier scan et vous montre ce qui est prouvé en moins de deux minutes.</p>
        </div>

        <div className="seg" role="tablist" aria-label="Type de cible">
          <button type="button" role="tab" aria-selected={mode === "url"} className={mode === "url" ? "on" : ""} onClick={() => setMode("url")}>Site</button>
          <button type="button" role="tab" aria-selected={mode === "repo"} className={mode === "repo" ? "on" : ""} onClick={() => setMode("repo")}>Dépôt GitHub</button>
        </div>

        <form className="card onb-card" onSubmit={(e) => { e.preventDefault(); if (ok) navigate("/app/agent", { state: { prompt: `Premier scan de ${value.trim()}` } }); }}>
          <label className="field">
            <span>{mode === "url" ? "URL du site (staging de préférence)" : "Dépôt"}</span>
            <div className="inputbox">
              {mode === "url" ? <Globe size={15} aria-hidden="true" /> : <Github size={15} aria-hidden="true" />}
              <input key={mode} value={value} onChange={(e) => (mode === "url" ? setUrl : setRepo)(e.target.value)} placeholder={mode === "url" ? "staging.acme.app" : "acme/acme-app"} />
            </div>
          </label>
          <label className={cn("checkrow", owner && "on")}>
            <input type="checkbox" checked={owner} onChange={(e) => setOwner(e.target.checked)} />
            <span>Je possède cette cible, ou je suis autorisé à la tester.</span>
          </label>
          <button type="submit" className="btn block" disabled={!ok}>Lancer le premier scan <ArrowRight size={15} /></button>
        </form>

        <Link to="/app/overview" className="muted small">Passer, voir une démo</Link>
      </div>
    </div>
  );
}
