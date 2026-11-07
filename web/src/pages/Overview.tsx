import { Link } from "react-router-dom";
import { ShieldAlert, Clock, CheckCheck, Timer, Plus, AlertTriangle, Check, CircleDot } from "lucide-react";
import { Topbar } from "../components/Shell.tsx";
import { Button, Sparkline, Bars, SeverityChip, StateBadge } from "../components/ui.tsx";
import { activity, chartLeads, chartProven, findings } from "../data/mock.ts";
import { SEV_RANK } from "../lib/types.ts";

const sorted = [...findings].sort((a, b) =>
  (a.state === "proven" ? 0 : 1) - (b.state === "proven" ? 0 : 1) || SEV_RANK[a.sev] - SEV_RANK[b.sev],
);

export function Overview() {
  const actIcon = { bad: AlertTriangle, good: Check, brand: Plus, info: CircleDot };
  return (
    <>
      <Topbar crumb="acme-app · staging" title="Vue d'ensemble" actions={
        <>
          <span className="chipbtn">Cible <b>acme-app</b> ▾</span>
          <Link to="/app/scan/run"><Button><Plus size={15} /> Nouveau scan</Button></Link>
        </>
      } />
      <div className="content">
        <section className="grid4">
          <div className="kpi alive">
            <div className="top"><span className="ic32"><ShieldAlert size={16} /></span><span className="dp flat">stable</span></div>
            <span className="lab">Critiques prouvés</span><span className="fig crit">3</span>
            <div className="spark"><Sparkline points={[1,2,2,3,2,3,3]} color="var(--crit)" /></div>
          </div>
          <div className="kpi">
            <div className="top"><span className="ic32"><Clock size={16} /></span><span className="dp down">+2</span></div>
            <span className="lab">Findings ouverts</span><span className="fig">7</span>
            <div className="spark"><Sparkline points={[4,5,5,6,6,7,7]} /></div>
          </div>
          <div className="kpi">
            <div className="top"><span className="ic32"><CheckCheck size={16} /></span><span className="dp up">▼ 0,4 j</span></div>
            <span className="lab">Délai médian de correctif</span><span className="fig">1,8 j</span>
            <div className="spark"><Sparkline points={[3,2.6,2.4,2.1,2,1.9,1.8]} color="var(--low)" /></div>
          </div>
          <div className="kpi">
            <div className="top"><span className="ic32"><Timer size={16} /></span><span className="dp flat">1m 12s</span></div>
            <span className="lab">Dernier scan</span><span className="fig sm">il y a 12 min</span>
            <div className="spark"><Sparkline points={[1,1,1,1,1,1,1]} color="var(--fg-ghost)" glow={false} /></div>
          </div>
        </section>

        <section className="cols">
          <section className="card">
            <div className="hd"><h2>Findings dans le temps</h2><span className="meta">14 derniers jours</span><span className="sp" />
              <div className="seg"><button>7 j</button><button className="on">14 j</button><button>30 j</button></div>
            </div>
            <div style={{ padding: 18 }}>
              <div className="loader-row" style={{ gap: 16, marginBottom: 10 }}>
                <span style={{ color: "var(--fg-muted)", fontSize: 12 }}><i style={{ display: "inline-block", width: 9, height: 9, borderRadius: 2, background: "var(--crit)", marginRight: 6 }} />Prouvés</span>
                <span style={{ color: "var(--fg-muted)", fontSize: 12 }}><i style={{ display: "inline-block", width: 9, height: 9, borderRadius: 2, background: "var(--brand)", marginRight: 6 }} />Leads</span>
              </div>
              <Bars proven={chartProven} leads={chartLeads} />
            </div>
          </section>

          <section className="card">
            <div className="hd"><h2>Activité</h2><span className="sp" /><span className="meta"><span className="live" /> en direct</span></div>
            <div className="feed">
              {activity.map((a, i) => {
                const Ic = actIcon[a.kind];
                return (
                  <div className="ev" key={i}>
                    <span className={`ic ${a.kind === "bad" ? "bad" : a.kind === "good" ? "good" : a.kind === "brand" ? "brand" : ""}`}><Ic size={13} /></span>
                    <div className="tx" style={{ fontWeight: 500 }}>{a.title}<small style={{ fontWeight: 400 }}>{a.meta}</small></div>
                  </div>
                );
              })}
            </div>
          </section>
        </section>

        <section className="card">
          <div className="hd"><h2>Findings</h2><span className="meta">triés par sévérité, prouvés d'abord</span><span className="sp" /><Button variant="ghost" size="sm">Exporter</Button></div>
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead><tr><th>Sév.</th><th>Intitulé</th><th className="hide-sm">Emplacement</th><th>État</th><th className="hide-sm">Vu</th><th /></tr></thead>
              <tbody>
                {sorted.map((f) => (
                  <tr key={f.id}>
                    <td><SeverityChip sev={f.sev} /></td>
                    <td className="t-title">{f.title}</td>
                    <td className="hide-sm mono faint">{f.location}</td>
                    <td><StateBadge state={f.state} /></td>
                    <td className="hide-sm mono faint">{f.seen}</td>
                    <td><Link className="linkish" to={`/app/findings/${f.id}`}>Voir</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="note">Un finding ne bloque la CI que s'il est prouvé et de sévérité haute ou critique.</p>
        </section>
      </div>
    </>
  );
}
