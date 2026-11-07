import type { AgentEvent, Finding, Severity, Target, Task } from "../lib/types.ts";

export const targets: Target[] = [
  { id: "acme-app", name: "acme-app", url: "staging.acme.app", kind: "site", env: "staging", findings: 13, proven: 4, lastScan: "il y a 12 min" },
  { id: "inboxly", name: "inboxly", url: "github.com/inboxly/app", kind: "repo", env: "production", findings: 3, proven: 0, lastScan: "il y a 3 h" },
  { id: "pagefold", name: "pagefold", url: "staging.pagefold.dev", kind: "site", env: "staging", findings: 7, proven: 1, lastScan: "hier" },
];

export const findings: Finding[] = [
  {
    id: "f-stripe", sev: "crit", title: "Clé secrète Stripe dans le bundle client", location: "dist/app.js:5",
    state: "proven", seen: "12 min", check: "exposed-secrets", guarded: true,
    description: "Une clé secrète Stripe (sk_live_...) est présente dans le bundle servi au navigateur. N'importe quel visiteur peut la lire dans le code source.",
    remediation: "Révoquer la clé immédiatement (la considérer comme compromise), puis la déplacer côté serveur. Le client ne doit porter que des clés publiables.",
    proof: { method: "match déterministe sur un format de clé connu", replay: "grep -nE 'sk_(live|test)_[A-Za-z0-9]{16,}' dist/app.js", evidence: "sk_live_...demo (29 car.)" },
    regression: "test('le bundle ne contient pas sk_live_', () => {\n  expect(read('dist/app.js')).not.toMatch(/sk_live_/);\n});",
  },
  {
    id: "f-authz", sev: "high", title: "Le compte A lit le projet du compte B", location: "GET /api/projects/:id",
    state: "proven", seen: "11 min", check: "authz-matrix",
    description: "Avec le jeton du compte A, la route renvoie 200 et le contenu du projet appartenant au compte B. L'identifiant suffit: aucune vérification de propriétaire côté serveur.",
    remediation: "Filtrer la requête par compte (where owner_id = session.account_id) et renvoyer 404 sinon. Garder le test inter-tenant en CI.",
    proof: { method: "requête rejouée avec le jeton du compte A", replay: "curl -i -H 'authorization: Bearer $TOKEN_A' https://staging.acme.app/api/projects/proj_b_1", evidence: "HTTP 200 (attendu 401, 403 ou 404)" },
    regression: "test('A ne peut pas lire le projet de B', async () => {\n  const res = await as(A).get('/api/projects/' + B.project);\n  expect([401, 403, 404]).toContain(res.status);\n});",
  },
  {
    id: "f-pem", sev: "crit", title: "Clé privée PEM commitée", location: "infra/key.pem:1",
    state: "proven", seen: "12 min", check: "committed-credentials",
    description: "Un bloc BEGIN PRIVATE KEY est commité dans le dépôt.",
    remediation: "Révoquer la clé, la retirer de l'historique git, et la stocker dans un gestionnaire de secrets.",
    proof: { method: "match déterministe", replay: "grep -n 'BEGIN .*PRIVATE KEY' infra/key.pem" },
  },
  {
    id: "f-tanstack", sev: "crit", title: "Paquet malveillant verrouillé: @tanstack/react-router@1.169.5", location: "pnpm-lock.yaml",
    state: "proven", seen: "12 min", check: "dependency-risk", guarded: true,
    description: "Cette version exacte figure sur la denylist (GHSA-g7cv-rxg3-hmpx): malware exfiltrant des identifiants.",
    remediation: "Mettre à jour au-delà de la version affectée, purger node_modules et le store, et faire tourner les secrets des machines de build.",
    proof: { method: "match nom@version contre la denylist", replay: "grep -n '@tanstack/react-router@1.169.5' pnpm-lock.yaml", evidence: "GHSA-g7cv-rxg3-hmpx" },
    regression: "test('le lockfile ne contient pas @tanstack/react-router@1.169.5', () => {\n  expect(read('pnpm-lock.yaml')).not.toContain('1.169.5');\n});",
  },
  {
    id: "f-google", sev: "high", title: "Clé API Google exposée", location: "dist/app.js:7",
    state: "lead", seen: "12 min", check: "exposed-secrets",
    description: "Une clé API Google (AIza...) apparaît dans le bundle. À confirmer: restreinte par domaine ou non.",
    remediation: "Restreindre la clé par référent/domaine, ou la déplacer côté serveur.",
    proof: { method: "match déterministe", replay: "grep -nE 'AIza[0-9A-Za-z_-]{35}' dist/app.js" },
  },
  {
    id: "f-publicenv", sev: "high", title: "Secret derrière un préfixe public: NEXT_PUBLIC_STRIPE_SECRET", location: ".env:4",
    state: "lead", seen: "12 min", check: "public-env", guarded: true,
    description: "NEXT_PUBLIC_STRIPE_SECRET porte un préfixe que le framework inline dans le bundle navigateur: sa valeur fuite côté client.",
    remediation: "Retirer le préfixe public et ne lire ce secret que côté serveur.",
    regression: "test('aucune variable NEXT_PUBLIC_ nommée comme un secret', () => { ... });",
  },
  {
    id: "f-csp", sev: "med", title: "En-tête CSP absent sur la réponse HTML", location: "staging.acme.app",
    state: "lead", seen: "1 h", check: "headers",
    description: "La réponse HTML ne pose pas de Content-Security-Policy.",
    remediation: "Ajouter une CSP restrictive et la tester en mode report-only d'abord.",
  },
  {
    id: "f-dockerfile", sev: "med", title: "Conteneur lancé en root (pas de USER)", location: "Dockerfile",
    state: "lead", seen: "12 min", check: "dockerfile",
    description: "Aucune instruction USER: le conteneur tourne en root. Une évasion de process a alors root dans le conteneur.",
    remediation: "Ajouter un USER non-root avant l'entrypoint.",
  },
  {
    id: "f-env", sev: "med", title: "Fichier .env commité", location: ".env",
    state: "lead", seen: "12 min", check: "committed-env", guarded: true,
    description: "Un .env commité contient souvent des secrets (URLs de base, jetons) qu'aucun scanner de format de clé ne verrait.",
    remediation: "L'ajouter au .gitignore, le retirer de l'historique, et faire tourner ce qu'il contenait.",
    regression: "test('aucun fichier .env commité', () => { ... });",
  },
  {
    id: "f-cookie", sev: "low", title: "Cookie de session sans attribut SameSite", location: "set-cookie",
    state: "lead", seen: "1 h", check: "headers",
    description: "Le cookie de session ne fixe pas SameSite, ce qui élargit la surface CSRF.",
    remediation: "Poser SameSite=Lax ou Strict et Secure sur le cookie de session.",
  },
  {
    id: "f-mcp", sev: "low", title: "Config MCP commitée: .mcp.json (1 serveur)", location: ".mcp.json",
    state: "lead", seen: "12 min", check: "mcp-surface",
    description: "Un serveur MCP local déclaré exécute une commande: exécution arbitraire si la config est altérée.",
    remediation: "Épingler et revoir chaque serveur; garder les secrets hors du fichier commité.",
  },
  {
    id: "f-sourcemap", sev: "low", title: "Source map livrée dans le bundle: app.js.map", location: "dist/app.js.map",
    state: "lead", seen: "12 min", check: "sourcemaps", guarded: true,
    description: "Une source map servie au navigateur laisse reconstruire le code source original.",
    remediation: "Ne pas déployer les .map publiquement; les envoyer au tracker d'erreurs au build.",
    regression: "test('aucune source map dans le bundle', () => { ... });",
  },
  {
    id: "f-cors", sev: "high", title: "CORS reflétait n'importe quelle origine avec credentials", location: "/api/*",
    state: "fixed", seen: "2 j", check: "headers", guarded: true,
    description: "L'API renvoyait Access-Control-Allow-Origin égal à l'origine de la requête, avec Allow-Credentials: true.",
    remediation: "Liste blanche d'origines explicite. Corrigé dans le commit 4f2c1a.",
    proof: { method: "requête rejouée avec Origin: https://evil.example", replay: "curl -i -H 'Origin: https://evil.example' https://staging.acme.app/api/me" },
    regression: "test('CORS refuse une origine inconnue', async () => { ... });",
  },
];

export const tasks: Task[] = [
  { id: "t-live", title: "Scan complet de acme-app: secrets, dépendances et autorisation entre comptes", target: "acme-app", when: "à l'instant", trigger: "manuel", status: "waiting", proven: 3, leads: 5 },
  { id: "t-recheck", title: "Rejouer la matrice d'autorisation après le correctif CORS", target: "acme-app", when: "il y a 2 h", trigger: "manuel", dur: "48 s", status: "done", fixed: 1, guarded: 4 },
  { id: "t-google", title: "Vérifier si la clé Google du bundle est restreinte par domaine", target: "acme-app", when: "il y a 3 h", trigger: "manuel", dur: "21 s", status: "done", leads: 1 },
  { id: "t-push", title: "Scan sur push: inboxly main@4f2c1a", target: "inboxly", when: "il y a 3 h", trigger: "sur push", dur: "1 min 04", status: "done", guarded: 2 },
  { id: "t-sched", title: "Scan planifié de pagefold", target: "pagefold", when: "hier 23:30", trigger: "planifié", dur: "1 min 20", status: "done", proven: 1, guarded: 3 },
  { id: "t-cf", title: "Audit Cloudflare de inboxly", target: "inboxly", when: "hier 18:02", trigger: "manuel", dur: "12 s", status: "stopped" },
  { id: "t-first", title: "Premier scan de pagefold", target: "pagefold", when: "il y a 3 j", trigger: "onboarding", dur: "1 min 31", status: "done", proven: 2, leads: 4, archived: true },
  { id: "t-old", title: "Chercher des secrets dans l'historique git de acme-app", target: "acme-app", when: "il y a 6 j", trigger: "manuel", dur: "2 min 10", status: "done", proven: 1, archived: true },
];

export const tests = [
  { name: "A ne peut pas lire le projet de B", check: "authz-matrix", status: "draft" as const, when: "il y a 11 min", finding: "f-authz" },
  { name: "Le bundle ne contient pas sk_live_", check: "exposed-secrets", status: "ci" as const, when: "il y a 2 h", finding: "f-stripe" },
  { name: "Le lockfile ne contient pas @tanstack/react-router@1.169.5", check: "dependency-risk", status: "ci" as const, when: "il y a 12 min", finding: "f-tanstack" },
  { name: "Aucune variable NEXT_PUBLIC_ nommée comme un secret", check: "public-env", status: "ci" as const, when: "il y a 12 min", finding: "f-publicenv" },
  { name: "Aucun fichier .env commité", check: "committed-env", status: "ci" as const, when: "il y a 12 min", finding: "f-env" },
  { name: "Aucune source map dans le bundle", check: "sourcemaps", status: "ci" as const, when: "il y a 12 min", finding: "f-sourcemap" },
  { name: "CORS refuse une origine inconnue", check: "headers", status: "ci" as const, when: "il y a 2 j", finding: "f-cors" },
];

export const secrets = [
  { kind: "Clé secrète Stripe", masked: "sk_live_••••••••3f9a", loc: "dist/app.js:5", valid: "active", sev: "crit" as Severity, finding: "f-stripe" },
  { kind: "Clé privée (PEM)", masked: "-----BEGIN PRIVATE KEY----- ••••", loc: "infra/key.pem:1", valid: "inconnue", sev: "crit" as Severity, finding: "f-pem" },
  { kind: "Clé API Google", masked: "AIzaSy••••••••••••Qk2", loc: "dist/app.js:7", valid: "à vérifier", sev: "high" as Severity, finding: "f-google" },
];

// Authorization matrix: who (rows) tries to reach account B's resources (cols).
export const authzResources = [
  { id: "project", label: "Projet", route: "GET /api/projects/:id" },
  { id: "render", label: "Rendu", route: "GET /api/renders/:id" },
  { id: "asset", label: "Fichier", route: "GET /api/assets/:id" },
  { id: "credits", label: "Crédits", route: "POST /api/credits" },
];
export const authzActors = [
  { id: "a-member", label: "Compte A", role: "membre", cells: { project: 200, render: 403, asset: 404, credits: 403 } as Record<string, number> },
  { id: "a-admin", label: "Compte A", role: "admin", cells: { project: 200, render: 403, asset: 404, credits: 403 } as Record<string, number> },
  { id: "anon", label: "Anonyme", role: "sans jeton", cells: { project: 401, render: 401, asset: 401, credits: 401 } as Record<string, number> },
];

export const CHECKS = [
  { id: "exposed-secrets", group: "Secrets", desc: "Clés serveur dans le bundle client et le dépôt." },
  { id: "committed-credentials", group: "Secrets", desc: ".npmrc, .pypirc, config Docker avec jetons." },
  { id: "committed-env", group: "Secrets", desc: "Fichiers .env poussés dans git." },
  { id: "public-env", group: "Secrets", desc: "Secrets derrière un préfixe exposé au client." },
  { id: "authz-matrix", group: "Autorisation", desc: "Le compte A tente les ressources du compte B." },
  { id: "jwt-config", group: "Autorisation", desc: "alg none, secret faible, pas d'expiration." },
  { id: "dependency-risk", group: "Chaîne d'appro.", desc: "Paquets malveillants ou vulnérables verrouillés." },
  { id: "ci-hardening", group: "Chaîne d'appro.", desc: "Permissions de workflow, actions non épinglées." },
  { id: "mcp-surface", group: "Chaîne d'appro.", desc: "Serveurs MCP commités qui lancent des commandes." },
  { id: "dockerfile", group: "Infra", desc: "Conteneur en root, image non épinglée." },
  { id: "cloudflare-audit", group: "Infra", desc: "Zone: TLS, WAF, règles de cache." },
  { id: "headers", group: "Web", desc: "CSP, HSTS, cookies de session, CORS." },
  { id: "tls-verification", group: "Web", desc: "Vérification TLS désactivée dans le code." },
  { id: "sourcemaps", group: "Web", desc: "Source maps servies en production." },
];

// The scripted run the Agent console replays. The permission step pauses it.
export const PLAN_STEPS = [
  { tool: "scan.secrets", label: "Chercher des secrets dans le bundle" },
  { tool: "scan.repo", label: "Fouiller le dépôt" },
  { tool: "scan.deps", label: "Auditer les dépendances" },
  { tool: "authz.matrix", label: "Prouver l'isolation entre comptes" },
  { tool: "tests.generate", label: "Générer les tests de régression" },
];

export const agentScript: AgentEvent[] = [
  { kind: "think", dur: "2 s", text: "La cible est un site en staging avec un dépôt lié. Le plus rentable d'abord: ce qui est lisible sans envoyer de requête (bundle, dépôt, lockfile). Ensuite seulement l'autorisation entre comptes, qui demande des requêtes réelles: il faudra l'accord de l'utilisateur." },
  { kind: "plan", steps: PLAN_STEPS },
  {
    kind: "tool", tool: "scan.secrets", args: "dist/ · 12 motifs", dur: "1,1 s",
    input: '{\n  "dir": "dist/",\n  "patterns": ["sk_live_", "AIza", "BEGIN PRIVATE KEY", "+9"]\n}',
    lines: ["3 fichiers lus, 1,2 Mo", "2 correspondances"],
    findings: [
      { sev: "crit", text: "sk_live_ dans dist/app.js:5", state: "proven", id: "f-stripe" },
      { sev: "high", text: "AIza… dans dist/app.js:7, restriction inconnue", state: "lead", id: "f-google" },
    ],
  },
  {
    kind: "tool", tool: "scan.repo", args: "credentials, env, sourcemaps", dur: "0,7 s",
    input: '{\n  "checks": ["committed-credentials", "committed-env", "sourcemaps"]\n}',
    lines: ["412 fichiers suivis par git"],
    findings: [
      { sev: "crit", text: "Clé privée PEM dans infra/key.pem:1", state: "proven", id: "f-pem" },
      { sev: "med", text: ".env commité à la racine", state: "lead", id: "f-env" },
    ],
  },
  {
    kind: "tool", tool: "scan.deps", args: "pnpm-lock.yaml · 842 paquets", dur: "0,8 s",
    input: '{\n  "lockfile": "pnpm-lock.yaml",\n  "denylist": "à jour (il y a 2 h)"\n}',
    lines: ["842 paquets comparés à la denylist"],
    findings: [{ sev: "crit", text: "@tanstack/react-router@1.169.5 (GHSA-g7cv-rxg3-hmpx)", state: "proven", id: "f-tanstack" }],
  },
  { kind: "say", text: "Pour prouver l'isolation entre comptes, je dois rejouer quatre requêtes avec le jeton du compte A sur les ressources du compte B." },
  {
    kind: "permission", tool: "authz.matrix", host: "staging.acme.app",
    requests: ["GET  /api/projects/proj_b_1", "GET  /api/renders/rnd_b_7", "GET  /api/assets/ast_b_3", "POST /api/credits"],
  },
];

export const agentAfterAllow: AgentEvent[] = [
  {
    kind: "tool", tool: "authz.matrix", args: "compte A → ressources de B", dur: "0,6 s",
    input: '{\n  "as": "compte A (membre)",\n  "target": "ressources du compte B",\n  "requests": 4\n}',
    lines: ["GET  /api/projects/proj_b_1  → 200", "GET  /api/renders/rnd_b_7   → 403", "GET  /api/assets/ast_b_3    → 404", "POST /api/credits            → 403"],
    findings: [{ sev: "high", text: "A lit le projet de B: GET /api/projects/:id → 200", state: "proven", id: "f-authz" }],
  },
  {
    kind: "tool", tool: "tests.generate", args: "4 failles prouvées", dur: "0,4 s",
    input: '{\n  "findings": ["f-stripe", "f-pem", "f-tanstack", "f-authz"]\n}',
    lines: ["1 nouveau test en brouillon, 2 déjà gardés en CI"],
    code: {
      file: "tests/crenel/authz.projects.test.ts",
      body: "import { as } from './harness';\n\ntest('A ne peut pas lire le projet de B', async () => {\n  const res = await as('A').get('/api/projects/proj_b_1');\n  expect([401, 403, 404]).toContain(res.status);\n});",
    },
  },
  {
    kind: "say",
    text: "4 failles prouvées, 5 pistes. À faire maintenant: révoquer la clé Stripe et la clé PEM, sortir @tanstack/react-router@1.169.5 du lockfile, filtrer /api/projects/:id par compte. Le test est prêt: une fois en CI, la faille ne revient plus sans casser le build.",
    sources: [
      { label: "GHSA-g7cv-rxg3-hmpx", kind: "Avis de sécurité", href: "https://github.com/advisories" },
      { label: "API1:2023 Broken Object Level Authorization", kind: "OWASP", href: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/" },
      { label: "Clés API et rotation", kind: "Docs Stripe", href: "https://docs.stripe.com/keys" },
    ],
  },
];

export const agentAfterDeny: AgentEvent[] = [
  { kind: "note", text: "Requêtes refusées. Rien n'a été envoyé à staging.acme.app.", tone: "muted" },
  { kind: "say", text: "Compris. L'autorisation entre comptes reste une piste, non prouvée. Bilan statique: 3 failles prouvées (clé Stripe, clé PEM, paquet malveillant) et 4 pistes. Tapez /authz quand vous voulez lancer la matrice." },
];

// Daily series over 90 days (oldest first), deterministic, for the KPI blocks.
function series(seed: number, base: number, amp: number, trend = 0): number[] {
  let x = seed;
  return Array.from({ length: 90 }, (_, i) => {
    x = (x * 9301 + 49297) % 233280;
    const noise = x / 233280;
    return Math.max(0, Math.round(base + trend * i + (noise - 0.5) * amp));
  });
}
export const daily = {
  detected: series(7, 6, 8, 0.03),
  proven: series(11, 0.6, 2.2, 0.01),
  guarded: series(13, 0.4, 1.6, 0.012),
  leads: series(17, 4, 6, 0.02),
  fixed: series(19, 0.3, 1.2, 0.006),
  tasks: series(23, 3, 4, 0.03),
  minutes: series(29, 70, 40, -0.2),
};

export const activity = [
  { kind: "proven" as const, title: "Clé Stripe prouvée dans le bundle", meta: "il y a 12 min · acme-app" },
  { kind: "guard" as const, title: "Test « aucune source map » passé en CI", meta: "il y a 40 min · acme-app" },
  { kind: "task" as const, title: "Scan sur push terminé sur inboxly", meta: "il y a 3 h · main@4f2c1a" },
  { kind: "fixed" as const, title: "CORS corrigé, le test reste gardé", meta: "il y a 2 j · acme-app" },
  { kind: "lead" as const, title: "Nouvelle piste: CSP absente", meta: "il y a 1 h · staging.acme.app" },
];

export const onboarding = [
  { id: "target", title: "Ajouter une cible", desc: "Un site ou un dépôt à vous", done: true, to: "/app/onboarding" },
  { id: "github", title: "Connecter GitHub", desc: "Scanner chaque pull request", done: true, to: "/app/integrations" },
  { id: "ci", title: "Brancher la CI", desc: "Garder les failles prouvées", done: false, to: "/app/integrations" },
  { id: "slack", title: "Alertes Slack", desc: "Prévenir sur un critique prouvé", done: false, to: "/app/integrations" },
];

export const provenCount = findings.filter((f) => f.state === "proven").length;
export const guardedCount = tests.filter((t) => t.status === "ci").length;
