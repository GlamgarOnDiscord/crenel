# Nuit du 07/11/2026 — récap pour Tom

Tout est en local dans `/root/work/bastion`, commité, rien poussé.

## Fait

**Identité (Crenel).** Nom proposé Crenel (Bastion est pris). Concept de mascotte: le choucas de la tour, perché sur un créneau, qui tient une clé (il collectionne les objets brillants = il trouve vos secrets exposés). Accent or-ambre sur encre bleu-noir, pas de vert/cyan. Polices Mona Sans (titrage), Instrument Sans (UI), JetBrains Mono (code), toutes libres. Icônes Lucide. Détail: `docs/IDENTITY.md`.

**App web v1 puis v2 auto-revue.** Vraie app React + Vite dans `web/`, 12 pages: landing, vue d'ensemble, console Agent (type Claude Code: prompt, étapes, appels d'outils, loaders), findings + détail (preuve, remédiation, test de régression), scans, cibles (dossiers), secrets, autorisation (matrice + preuve rejouable), tests générés, intégrations, paramètres. Design system maison (3 couches, hairlines, 4 niveaux de texte, chiffres tabulaires, graphe en barres empilées). v2: relecture Opus indépendante (`web/REVIEW-v2.md`), puis correctifs (liens morts, tri par sévérité, a11y clavier, responsive 390 px, contraste, mascotte qui tient vraiment une clé, Mona Sans).

**Moteur (le coeur).** 5 vérifications déterministes (secrets, dependency-risk avec denylist OSV de 84 versions @tanstack, ci-hardening, headers, authz-matrix), scope guard + client HTTP à périmètre (pas d'IP privée, redirections revalidées, corps plafonné), baseline/diff (blocage CI sur régression), export JSON + SARIF 2.1.0, journal d'audit JSONL, `generate-tests` (un test de régression par finding), `sync-denylist` (rafraîchit la denylist depuis OSV). 22 tests unitaires, CI GitHub Actions. Triage LLM via `claude -p` (le modèle conseille, ne marque jamais "prouvé"). Docs: `docs/ARCHITECTURE.md`, `CONTRIBUTING.md`.

**Test en conditions réelles.** `claude -p --model opus` (Opus 4.8) a trié des findings sans refus, à travers le moteur. Détail: `research_notes/Bastion identite et app/test_reel_claude_p.md`.

**Recherche.** 5 nouvelles recherches web (branding, typo, UX agent, concurrents, backlog technique de 18 items), plus les précédentes. Tout dans `research_notes/`.

## À décider par toi

- Le nom (Crenel, ou une alternative), et la licence de la mascotte.
- Logos de modèles: j'ai mis une pastille neutre, car les logos des fournisseurs sont des marques déposées (Anthropic demande une autorisation). À trancher avant de publier.

## Reste à faire (demande ton intervention)

Ces items sortent du périmètre sûr (identifiants, décision, action sortante) et ne sont pas faits exprès:
- Auto-PR des tests et correctifs vers GitHub ; scan hébergé/continu.
- Intégration de cloudflare/security-audit-skill (licence à valider).
- Enrichir la mascotte en illustration, auto-héberger Commit Mono.

Le reste du backlog technique self-contained est fait cette nuit (client HTTP à périmètre, SARIF, audit, generate-tests, ci-hardening, headers, denylist OSV, docs).

## Lancer en local

- App: `cd web && pnpm install && pnpm dev` (ou `pnpm build` puis servir `web/dist`).
- CLI: `cd .. && pnpm demo` ; triage: `pnpm bastion triage --config examples/bastion.config.yaml --max 1`.

## Session de fin de nuit (07/11, ~3 h 30-4 h Paris)

Passe d'auto-review sur la v2, tout local, 4 commits:

- **Captures de chaque page** en desktop (1440), mobile (390) et tablette (834), dans `web/shots/`. Planches contact envoyées à Tom.
- **Bug responsive corrigé** (086d54f): sur mobile la nav se repliait en colonnes désalignées (les liens étaient groupés dans des `<div>` par section). Aplati avec `display:contents`, nav en barre horizontale défilante.
- **Accessibilité** (59674bd): audit contraste WCAG de toute la palette. 15/16 paires en AA; `--fg-ghost` était à 2,15:1 (sous AA) alors qu'il porte les étiquettes d'axe du graphe et le hint ⌘K. Remonté à #6B7183 (~3,8:1, AA-large). Focus clavier (`*:focus-visible`, halo ambre) et `prefers-reduced-motion` déjà présents.
- **README illustré** (97d86a3) et **clarification du demo** (9f9c5ae): l'exit non-zéro du `pnpm demo` est le gate CI, pas un plantage.
- **Moteur revérifié de bout en bout**: `pnpm demo` sort 2 critical + 1 high prouvés (clé Stripe, paquet malveillant, clé Google) et 9 leads; SARIF 2.1.0 valide; `bastion init` écrit bien sa config. 24 tests verts, builds propres.

Responsive validé à 390 / 834 / 1440px. Rien de ceci n'est poussé: en attente de ta relecture et de tes décisions ci-dessus.

## Recherche web de contexte (07/11, fin de nuit)

Trois recherches web à jour (Sonnet en parallèle, synthèse Opus), dans `/root/research_notes/Etat art defensif IA nov 2026/` (3 notes sourcées + SYNTHESE.md). À retenir:

- Le marché a basculé en fév./mars 2026: Anthropic (Claude Security) et OpenAI (Codex Security) sont entrés sur le créneau « agent qui lit le code et valide ». Fait structurant de l'année.
- Trois constats mesurés qui valident notre conception: un LLM seul fait 82 à 86 % de faux positifs (Semgrep, sept. 2025); l'autorisation inter-tenant répartie est l'angle mort (0 vrai positif, nov. 2025); tout ce qui tient a un oracle déterministe, et le LLM-juge se laisse manipuler (32/33, ICSE 2027).
- Différenciation la plus solide pour Crenel: l'axe autorisation inter-tenant à preuve rejouable, le moins couvert par les gros et raté par les LLM nus. Le plancher de prix est zéro (Aikido, Semgrep, Socket gratuits), donc la valeur est « gratuit, local, sans compte, sortie lisible par un agent ».
- Les garde-fous sont tous justifiés par des incidents 2026 (TanStack pour la supply chain, série de CVE SSRF d'agents pour le client HTTP à périmètre). J'ai ancré dans les tests les IP de métadonnées cloud exactes visées par ces CVE (déjà bloquées).

Pistes concrètes dans la synthèse: pousser l'authz inter-tenant comme coeur produit, ajouter un contrôle d'âge/éditeur des dépendances (slopsquatting), ne pas concurrencer la détection de secrets, soigner la sortie SARIF/JSON pour les agents de code.

## Trois revues indépendantes + corrections (07/11, fin de nuit)

Trois reviewers Sonnet ont tourné: mon diff, l'app web, puis le coeur du moteur. Toutes les vraies trouvailles sont corrigées (28 commits au total).

Correctifs marquants:
- **Fail-open corrigé (le plus important)**: un check qui plantait faisait sortir le scan en 0 avec un SARIF vide. Désormais exit non-zéro, erreurs affichées, SARIF `executionSuccessful=false`, et la baseline ne classe plus « corrigé » un finding dont le check a planté.
- **App web**: bug React de l'onboarding (input gardant l'ancienne valeur), fuite d'intervalle de la console agent, palette de commandes rendue réellement modale, `<button>` dans `<a>` éliminés, données mock rendues cohérentes, interrupteurs Settings nommés.
- **CLI**: parseur robuste (flag booléen n'avale plus la commande, `--key=value`, flags inconnus signalés); erreurs de périmètre/config rapportées proprement au lieu d'un « Fatal: ».
- **Sécurité**: garde SSRF élargi (6to4, NAT64, site-local, multicast, v4-compatible, IPv4 réservées; hex v4-mapped); config stricte (faute de frappe de clé rejetée, hôtes vides refusés); triage qui clôture le contenu des findings comme donnée non fiable.
- **Robustesse**: baseline corrompue → échec propre au lieu d'écrasement; SARIF ne découpe plus les URL, empreintes stables; audit consigne le scope.

Deux points de conception laissés en suivi assumé (notés en roadmap): fenêtre résiduelle de rebinding DNS, et gating baseline « seulement les nouveaux ».

État: 44 tests moteur verts, typecheck et builds propres, demo inchangé, self-scan sans fuite réelle.

## Trois nouveaux checks (07/11, après les revues)

En réponse à l'invitation « aller plus loin », trois checks déterministes, hors ligne, en leads (faible faux positif), testés et dogfoodés (6 -> 9 checks, 44 -> 56 tests):
- **mcp-surface**: configs d'agents/MCP commitées (surface d'attaque 2026; justifié par la recherche de la nuit). Item de roadmap livré.
- **dockerfile**: durcissement conteneur (root, image non épinglée, secrets cuits dans une couche, ADD d'URL, curl|sh).
- **committed-env**: fichiers .env commités (secrets qu'aucun scanner de format de clé ne voit), hors .env.example.

Au-delà de ça, ajouter encore des checks relève de la direction produit (ton choix), tout comme l'oracle authz, l'âge des dépendances et les tests web.
