# Nuit du 07/11/2026 — récap pour Tom

Tout est en local dans `/root/work/bastion`, commité, rien poussé, rien touché côté Scenivia.

## Fait

**Identité (Crenel).** Nom proposé Crenel (Bastion est pris). Concept de mascotte: le choucas de la tour, perché sur un créneau, qui tient une clé (il collectionne les objets brillants = il trouve vos secrets exposés). Accent or-ambre sur encre bleu-noir, pas de vert/cyan. Polices Mona Sans (titrage), Instrument Sans (UI), JetBrains Mono (code), toutes libres. Icônes Lucide. Détail: `docs/IDENTITY.md`.

**App web v1 puis v2 auto-revue.** Vraie app React + Vite dans `web/`, 12 pages: landing, vue d'ensemble, console Agent (type Claude Code: prompt, étapes, appels d'outils, loaders), findings + détail (preuve, remédiation, test de régression), scans, cibles (dossiers), secrets, autorisation (matrice + preuve rejouable), tests générés, intégrations, paramètres. Design system maison (3 couches, hairlines, 4 niveaux de texte, chiffres tabulaires, graphe en barres empilées). v2: relecture Opus indépendante (`web/REVIEW-v2.md`), puis correctifs (liens morts, tri par sévérité, a11y clavier, responsive 390 px, contraste, mascotte qui tient vraiment une clé, Mona Sans).

**Moteur (le coeur).** 3 vérifications déterministes (secrets, dependency-risk avec denylist @tanstack, authz-matrix), scope guard, baseline/diff (nouveau/corrigé/persistant + blocage CI sur régression), tests unitaires, CI GitHub Actions. Nouveau: triage LLM expérimental via `claude -p` (le modèle conseille, il ne marque jamais "prouvé").

**Test en conditions réelles.** `claude -p --model opus` (Opus 4.8) a trié des findings sans refus, à travers le moteur. Détail: `research_notes/Bastion identite et app/test_reel_claude_p.md`.

**Recherche.** 5 nouvelles recherches web (branding, typo, UX agent, concurrents, backlog technique de 18 items), plus les précédentes. Tout dans `research_notes/`.

## À décider par toi

- Le nom (Crenel, ou une alternative), et la licence de la mascotte.
- Logos de modèles: j'ai mis une pastille neutre, car les logos des fournisseurs sont des marques déposées (Anthropic demande une autorisation). À trancher avant de publier.

## Reste à faire (priorisé, dans le backlog)

- Durcissement moteur P0: client HTTP à périmètre réseau (refus des IP privées, revalidation des redirections), sorties d'outils plafonnées, journal rejouable. Voir `research_notes/Bastion identite et app/backlog_harnais.md`.
- Onboarding (connecter un dépôt/site, premier scan), auto-PR de correctif, rapports PDF/CSV/SARIF.
- Auto-héberger Commit Mono, enrichir la mascotte en illustration.

## Lancer en local

- App: `cd web && pnpm install && pnpm dev` (ou `pnpm build` puis servir `web/dist`).
- CLI: `cd .. && pnpm demo` ; triage: `pnpm bastion triage --config examples/bastion.config.yaml --max 1`.
