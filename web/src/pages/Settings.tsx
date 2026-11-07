import { Topbar } from "../components/Shell.tsx";
import { Button } from "../components/ui.tsx";

function Toggle({ on }: { on: boolean }) {
  return (
    <span style={{ width: 38, height: 22, borderRadius: 999, background: on ? "var(--brand)" : "var(--line-strong)", position: "relative", display: "inline-block", flex: "none" }}>
      <span style={{ position: "absolute", top: 3, left: on ? 19 : 3, width: 16, height: 16, borderRadius: "50%", background: on ? "#1A1204" : "var(--fg-faint)", transition: "left .15s" }} />
    </span>
  );
}

function Row({ title, desc, control }: { title: string; desc: string; control: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "14px 18px", borderBottom: "1px solid var(--line-soft)" }}>
      <div style={{ flex: 1 }}><div style={{ fontWeight: 500 }}>{title}</div><div className="muted" style={{ fontSize: 13 }}>{desc}</div></div>
      {control}
    </div>
  );
}

export function Settings() {
  return (
    <>
      <Topbar crumb="Réglages" title="Paramètres" />
      <div className="content" style={{ maxWidth: 820 }}>
        <section className="card">
          <div className="hd"><h2>Politique</h2><span className="meta">ce qui bloque la CI</span></div>
          <Row title="Bloquer sur critique prouvé" desc="Un nouveau critique prouvé fait échouer la CI." control={<Toggle on />} />
          <Row title="Bloquer sur high prouvé" desc="Un nouveau high prouvé fait échouer la CI." control={<Toggle on />} />
          <Row title="Bloquer sur les leads" desc="Déconseillé: les leads ne sont pas prouvés." control={<Toggle on={false} />} />
          <Row title="Tester les scripts d'install" desc="Installer avec --ignore-scripts en CI." control={<Toggle on />} />
        </section>

        <section className="card">
          <div className="hd"><h2>Membres</h2><span className="sp" /><Button variant="ghost" size="sm">Inviter</Button></div>
          {[["Tom", "propriétaire"], ["Pierre", "admin"]].map(([n, r]) => (
            <div key={n} style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 18px", borderBottom: "1px solid var(--line-soft)" }}>
              <span style={{ width: 28, height: 28, borderRadius: "50%", background: "var(--brand-soft)", color: "var(--brand-ink)", display: "grid", placeItems: "center", fontWeight: 600, fontSize: 13 }}>{n[0]}</span>
              <span style={{ flex: 1 }}>{n}</span><span className="mono faint" style={{ fontSize: 12 }}>{r}</span>
            </div>
          ))}
        </section>

        <section className="card" style={{ borderColor: "color-mix(in oklab, var(--crit) 35%, var(--line))" }}>
          <div className="hd"><h2 style={{ color: "var(--crit-ink)" }}>Zone de danger</h2></div>
          <Row title="Supprimer la cible" desc="Efface les scans, findings et tests de cette cible." control={<Button variant="ghost" size="sm" style={{ color: "var(--crit-ink)", borderColor: "color-mix(in oklab, var(--crit) 40%, var(--line))" }}>Supprimer</Button>} />
        </section>
      </div>
    </>
  );
}
