import type { Activity, Finding, ScanStep, Target } from "../lib/types.ts";

export const targets: Target[] = [
  { id: "acme-app", name: "acme-app", url: "staging.acme.app", env: "staging", findings: 7, proven: 3, lastScan: "il y a 12 min" },
  { id: "inboxly", name: "inboxly", url: "app.inboxly.io", env: "production", findings: 3, proven: 0, lastScan: "il y a 3 h" },
  { id: "pagefold", name: "pagefold", url: "staging.pagefold.dev", env: "staging", findings: 7, proven: 1, lastScan: "hier" },
];

export const findings: Finding[] = [
  {
    id: "f-stripe", sev: "crit", title: "Clé secrète Stripe dans le bundle client", location: "dist/app.js:5",
    state: "proven", seen: "12 min", check: "exposed-secrets",
    description: "Une clé secrète Stripe (sk_live_...) est présente dans le bundle servi au navigateur. N'importe quel visiteur peut la lire dans le code source.",
    remediation: "Révoquer la clé immédiatement (la considérer comme compromise), puis la déplacer côté serveur. Le client ne doit porter que des clés publiables.",
    proof: { method: "match déterministe sur un format de clé connu", replay: "grep -nE 'sk_(live|test)_[A-Za-z0-9]{16,}' dist/app.js", evidence: "sk_live_...demo (29 car.)" },
    regression: "Étape CI qui échoue si le build contient un motif sk_live_.",
  },
  {
    id: "f-pem", sev: "crit", title: "Clé privée PEM commitée", location: "infra/key.pem:1",
    state: "proven", seen: "12 min", check: "exposed-secrets",
    description: "Un bloc BEGIN PRIVATE KEY est commité dans le dépôt.",
    remediation: "Révoquer la clé, la retirer de l'historique git, et la stocker dans un gestionnaire de secrets.",
    proof: { method: "match déterministe", replay: "grep -n 'BEGIN .*PRIVATE KEY' infra/key.pem" },
  },
  {
    id: "f-tanstack", sev: "crit", title: "Paquet malveillant verrouillé: @tanstack/react-router@1.169.5", location: "pnpm-lock.yaml",
    state: "proven", seen: "12 min", check: "dependency-risk",
    description: "Cette version exacte figure sur la denylist (GHSA-g7cv-rxg3-hmpx): malware exfiltrant des identifiants.",
    remediation: "Mettre à jour au-delà de la version affectée, purger node_modules et le store, et faire tourner les secrets des machines de build.",
    proof: { method: "match nom@version contre la denylist", replay: "grep -n '@tanstack/react-router@1.169.5' pnpm-lock.yaml", evidence: "GHSA-g7cv-rxg3-hmpx" },
  },
  {
    id: "f-google", sev: "high", title: "Clé API Google exposée", location: "dist/app.js:7",
    state: "lead", seen: "12 min", check: "exposed-secrets",
    description: "Une clé API Google (AIza...) apparaît dans le bundle. À confirmer: restreinte par domaine ou non.",
    remediation: "Restreindre la clé par référent/domaine, ou la déplacer côté serveur.",
    proof: { method: "match déterministe", replay: "grep -nE 'AIza[0-9A-Za-z_-]{35}' dist/app.js" },
  },
  {
    id: "f-authz", sev: "high", title: "Autorisation inter-tenant non testée", location: "/api/projects/:id",
    state: "lead", seen: "12 min", check: "authz-matrix",
    description: "Aucun test n'assure qu'un compte ne peut pas lire le projet d'un autre compte. Les LLM sont aveugles à ce bug: il faut un test déterministe.",
    remediation: "Lancer la matrice d'autorisation sur staging avec deux comptes de test, puis garder le test généré en CI.",
    proof: { method: "matrice générée (non exécutée)", replay: "crenel scan --check authz-matrix --staging-url ..." },
  },
  {
    id: "f-csp", sev: "med", title: "En-tête CSP absent sur la réponse HTML", location: "staging.acme.app",
    state: "lead", seen: "1 h", check: "headers",
    description: "La réponse HTML ne pose pas de Content-Security-Policy.",
    remediation: "Ajouter une CSP restrictive et la tester en mode report-only d'abord.",
  },
  {
    id: "f-cookie", sev: "low", title: "Cookie de session sans attribut SameSite", location: "set-cookie",
    state: "lead", seen: "1 h", check: "headers",
    description: "Le cookie de session ne fixe pas SameSite, ce qui élargit la surface CSRF.",
    remediation: "Poser SameSite=Lax ou Strict et Secure sur le cookie de session.",
  },
];

export const activity: Activity[] = [
  { kind: "bad", title: "Clé Stripe prouvée dans le bundle", meta: "dist/app.js:5 · critique" },
  { kind: "brand", title: "Test de régression généré pour l'isolation projet", meta: "authz-matrix · il y a 11 min" },
  { kind: "info", title: "Clé API Google à vérifier (lead)", meta: "dist/app.js:7 · high" },
  { kind: "info", title: "Scan planifié lancé sur acme-app", meta: "7 findings · il y a 12 min" },
];

// Barres empilées: prouvés (bas) + leads (haut), 14 jours.
export const chartProven = [1, 1, 0, 1, 2, 1, 1, 0, 1, 2, 2, 1, 2, 2];
export const chartLeads = [7, 6, 8, 5, 9, 7, 8, 6, 10, 8, 9, 7, 11, 12];

// Agent run: a scripted scan the console replays with streaming.
export const scanSteps: ScanStep[] = [
  { kind: "think", label: "Planifie le scan pour acme-app (staging), périmètre verrouillé au réseau", dur: "0,4 s", status: "ok" },
  { kind: "tool", label: "Analyse du bundle client", tool: "scan.secrets", body: "dir=dist  patterns=12\n→ 2 correspondances (sk_live, AIza)", dur: "1,1 s", status: "ok" },
  { kind: "tool", label: "Audit de la chaîne de dépendances", tool: "scan.deps", body: "lockfile=pnpm-lock.yaml  packages=842\n→ 1 paquet sur denylist (@tanstack/react-router@1.169.5)", dur: "0,8 s", status: "ok" },
  { kind: "tool", label: "Génère la matrice d'autorisation inter-tenant", tool: "authz.matrix", body: "resources=[project, render]  accounts=[A, B]\n→ 4 cas, test de régression émis", dur: "0,6 s", status: "ok" },
  { kind: "assistant", label: "Synthèse", body: "J'ai trouvé 3 problèmes prouvés et 4 pistes. Les deux critiques (clé Stripe et paquet malveillant) demandent une rotation immédiate. J'ai généré un test d'isolation inter-tenant à brancher en CI.", status: "ok" },
];

export const secrets = [
  { kind: "Stripe secret key", loc: "dist/app.js:5", valid: "active", sev: "crit" as const },
  { kind: "Google API key", loc: "dist/app.js:7", valid: "à vérifier", sev: "high" as const },
  { kind: "Private key (PEM)", loc: "infra/key.pem:1", valid: "inconnu", sev: "crit" as const },
];

export const authzRows = [
  { resource: "project", route: "/api/projects/:id", method: "GET", result: "200", verdict: "fail" as const },
  { resource: "render", route: "/api/renders/:id", method: "GET", result: "403", verdict: "pass" as const },
  { resource: "asset", route: "/api/assets/:id", method: "GET", result: "404", verdict: "pass" as const },
  { resource: "credits", route: "/api/credits", method: "POST", result: "403", verdict: "pass" as const },
];
