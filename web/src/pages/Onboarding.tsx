import { useState } from "react";
import { Link } from "react-router-dom";
import { Github, Globe, ArrowRight, ShieldCheck } from "lucide-react";
import { Mascot } from "../brand/Logo.tsx";
import { Button } from "../components/ui.tsx";

export function Onboarding() {
  const [mode, setMode] = useState<"repo" | "url">("url");
  return (
    <div style={{ minHeight: "100%", display: "grid", placeItems: "center", padding: 24 }}>
      <div style={{ width: "100%", maxWidth: 520, display: "grid", gap: 20, justifyItems: "center", textAlign: "center" }}>
        <Mascot size={96} />
        <div style={{ display: "grid", gap: 8 }}>
          <h1 style={{ fontFamily: "var(--f-display)", fontSize: 28 }}>Ajoutez une cible</h1>
          <p className="muted" style={{ margin: 0, maxWidth: "44ch" }}>Un dépôt ou un site que vous possédez. Crenel lance un premier scan et vous montre ce qui est prouvé en moins de deux minutes.</p>
        </div>

        <div className="seg" role="tablist" aria-label="Type de cible">
          <button role="tab" aria-selected={mode === "url"} className={mode === "url" ? "on" : ""} onClick={() => setMode("url")}>Site</button>
          <button role="tab" aria-selected={mode === "repo"} className={mode === "repo" ? "on" : ""} onClick={() => setMode("repo")}>Dépôt GitHub</button>
        </div>

        <div className="card" style={{ width: "100%", padding: 18, display: "grid", gap: 14, textAlign: "left" }}>
          {mode === "url" ? (
            <label style={{ display: "grid", gap: 7 }}>
              <span className="muted" style={{ fontSize: 13 }}>URL du site (staging de préférence)</span>
              <div style={{ display: "flex", alignItems: "center", gap: 8, background: "var(--well)", border: "1px solid var(--line-strong)", borderRadius: "var(--r-control)", padding: "10px 12px" }}>
                <Globe size={15} className="faint" />
                <input key="url" placeholder="staging.acme.app" defaultValue="staging.acme.app" style={{ background: "transparent", border: 0, outline: "none", flex: 1, fontFamily: "var(--f-mono)", fontSize: 13 }} />
              </div>
            </label>
          ) : (
            <label style={{ display: "grid", gap: 7 }}>
              <span className="muted" style={{ fontSize: 13 }}>Dépôt</span>
              <div style={{ display: "flex", alignItems: "center", gap: 8, background: "var(--well)", border: "1px solid var(--line-strong)", borderRadius: "var(--r-control)", padding: "10px 12px" }}>
                <Github size={15} className="faint" />
                <input key="repo" placeholder="acme/acme-app" defaultValue="acme/acme-app" style={{ background: "transparent", border: 0, outline: "none", flex: 1, fontFamily: "var(--f-mono)", fontSize: 13 }} />
              </div>
            </label>
          )}
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--fg-muted)" }}>
            <ShieldCheck size={15} className="faint" /> Je déclare posséder cette cible ou être autorisé à la tester.
          </div>
          <Link to="/app/scan/run"><Button style={{ width: "100%", justifyContent: "center" }}>Lancer le premier scan <ArrowRight size={15} /></Button></Link>
        </div>

        <Link to="/app/overview" className="muted" style={{ fontSize: 13 }}>Passer, voir une démo</Link>
      </div>
    </div>
  );
}
