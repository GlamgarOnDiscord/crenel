# BENCHMARK-AXIS (branche `bench/auth-session`)

Mémoire durable de l'axe benchmark. Ouvert le 2026-11-11, base `origin/main` (12 PR #38 à #49 mergées).

## Cible : orchestration de session authentifiée

**Lacune** : `authz-matrix` (et les checks qui reprennent ses comptes) exige un `token` ou un `cookie` déjà obtenu dans la config. Toute API derrière un login à jeton court ou à session cookie reste hors de portée : le run tombe sur le plan hors ligne (`authz-matrix:offline-plan`, une piste) au lieu de sondes réelles.

**Constat mesuré sur VAmPI (`localhost:5014`)** : `POST /users/v1/login {"username","password"}` renvoie `{"auth_token": "<JWT>"}` avec `exp - iat = 60 s`. Un jeton collé dans la config est périmé avant le run. BOLA connu : `GET /books/v1/<titre>` renvoie le `secret` du livre d'un autre utilisateur. Les titres changent à chaque `/createdb`.

## Conception (piste 1 de CLAUDE.md : la preuve ne change pas)

- **Nouveau module** `src/checks/session.ts` :
  - `extractSession(res, tokenPath?)` : **oracle pur**. Réponse 2xx ou 3xx de login vers `{ token?, cookie? }` ou `null`. Jeton : `tokenPath` déclaré, sinon une chaîne de forme JWT (en-tête base64url décodable avec `alg`) n'importe où dans le JSON, sinon une clé conventionnelle (`access_token`, `token`, `auth_token`, `accessToken`, `jwt`, `id_token`). Cookie : les `Set-Cookie` (`name=value`), sauf ceux qui effacent (`Max-Age=0`, valeur vide). Aucune signature de cible.
  - `login(ctx, spec)` : un `POST` (JSON ou formulaire) via `safeFetch`, sans suivre les redirections (pour garder le `Set-Cookie` d'un 302).
  - `resolveAccounts(ctx, accounts)` : pour chaque compte qui a un `login`, remplit `token` / `cookie`. Un `token` / `cookie` déclaré l'emporte.
- **Config** (sous `options.authz-matrix.accounts.<a|b|c>.login`) : `{ url, username | usernameEnv, passwordEnv, usernameField?, passwordField?, format?: "json"|"form", tokenPath? }`. **Mot de passe uniquement par nom de variable d'environnement**, lu à l'appel (règle des secrets).
- **Branchement** : `authz-matrix` appelle `resolveAccounts` avant de décider « hors ligne ou sondes ». Le login est un `POST` : il passe par la porte active (`assertActiveAllowed`), exactement comme les sondes live d'authz-matrix l'exigent déjà. Pas de changement du périmètre.
- **Zéro faux positif inchangé** : la session ne prouve rien. La preuve reste `authzOracle` (B lit son objet, A le lit aussi, contrôle id inexistant, garde route publique en anonyme, `stableLeak`) et le garde `sameIdentity` (même `sub` JWT ou même cookie refusés). Un login raté ne fait que réduire les sondes.

## Mesure (à faire avant d'affirmer)

- Avant : config VAmPI sans jeton : attendu `offline-plan` (piste), 0 prouvé.
- Après : même config + `login` pour A (`name1`) et B (`name2`), ids de B déclarés (son propre livre lu au moment de la config, usage prévu : le propriétaire connaît ses objets de staging). Attendu : BOLA `books` prouvé.
- Limite honnête : les ids de B restent déclarés. La découverte automatique des objets de B via une liste authentifiée est une étape suivante distincte.

## État au 2026-11-11 (avant compactage)

- **Fait, PR #51** (branche `bench/auth-session`, commit `814e0b7`) : `src/checks/session.ts` (login déclaré, extraction JWT/clé/cookie), branchement opt-in dans `authz-matrix` (sans `login`, rien ne change : `resolveAccounts` n'est appelé que si un compte déclare `login`), 9 tests, doc ARCHITECTURE, mesure positive VAmPI.
- **Fait** : contrôle négatif réel sur VAmPI `vulnerable=0` (conteneur séparé `vampi-safe`, port 5015) : 0 finding. #51 déclarée finale.
- **Ensuite (accord de l'utilisateur)** : suite n°1, découverte des ids de B via une liste authentifiée (supprime `owns` déclaré). Idée : option de ressource `list: "/books/v1"` ; B lit la liste avec sa session, on garde les ids présents dans la réponse de B (champ id de la ressource ou valeur placée dans `:id`), puis même chemin que les ids découverts existants (B doit lire l'objet en 2xx, l'anonyme ne doit pas avoir le même corps, `authzOracle` + `stableLeak`). Attention : une liste globale (VAmPI `/books/v1` liste les livres de tout le monde) ne prouve pas que l'objet est à B ; la propriété doit venir d'un champ propriétaire égal à l'identité de B ou du marqueur de B dans le corps de l'objet lu par B.
- VAmPI : bench local jetable, réinitialisable librement (`GET /createdb`), accord donné.

## Résultat mesuré (2026-11-11, VAmPI local, `checks: [authz-matrix]`, une ressource `book` `/books/v1/:id`)

| Config | Findings |
|---|---|
| Avant : comptes A/B sans jeton (le JWT de 60 s ne peut pas vivre dans la config) | 1 piste `authz-matrix:offline-plan`, **0 prouvé** |
| Après : même config + `login` A (`name1`) et B (`name2`), mots de passe via `VAMPI_PW_A` / `VAMPI_PW_B` | **1 prouvé** : `authz-matrix:book:GET:bookTitle86` (A lit le livre de B) |

Le jeton a été trouvé par sa forme JWT (aucune clé ni chemin propre à VAmPI). Id de B déclaré (lu dans `/books/v1` au moment d'écrire la config). Rejoué après `/createdb` : prouvé de nouveau (`bookTitle23`).

| Contrôle négatif : même config `login`, VAmPI `vulnerable=0` (`vampi-safe`, port 5015) | **0 finding** |
|---|---|

La sonde a réellement tourné sur la cible sécurisée : pas de plan hors ligne (donc A s'est connecté), et vérification manuelle B lit son livre (200), A est refusé (404). Le serveur stub qui vérifie la propriété donne aussi 0 prouvé. Suite complète : 695 tests, 694 réussis, 0 échec (1 non exécuté, préexistant).

## Suite n°1 : objets de B découverts depuis une liste (branche `bench/auth-discover`, empilée sur #51)

- Ressource : `list: <chemin>`, `idField` (défaut `id`). B lit la liste avec sa session ; un id n'est gardé que si B lit l'objet (2xx) ET que le corps nomme B comme mot entier (`marker` de B, sinon `sub` de son JWT ; `mentions` refuse « name2 » dans « name20 ») ET ne nomme pas A. Plafond 25 ids par liste. Ensuite, matrice inchangée.
- Tests : `session.test.ts` (+3) : pièces pures, stub à liste GLOBALE avec leurres (`bobbie2`, note de A qui mentionne B) : seul l'objet de B est prouvé ; stub sécurisé : 0.
- **Mesure live (VAmPI, sans `owns` ni `marker`)** : vulnérable 5014 : **1 prouvé** (`book:GET:bookTitle3`, le livre de name2 uniquement, alors que `/books/v1` liste les 3 livres) ; sécurisé 5015 : **0 finding**, sans plan hors ligne (la découverte a trouvé `bookTitle17` et la sonde a tourné). Suite complète 697/698, 0 échec.
- Incident : le conteneur `vampi` (5014) s'est arrêté (code 0) pendant une mesure, pas de mon fait ; relancé avec `docker start vampi` (accord donné).

## Suites possibles

1. ~~Découverte des ids de B via une liste authentifiée~~ : faite (voir plus haut).
2. Brancher `resolveAccounts` dans les autres consommateurs des comptes (`active-common.activeOptions` : authz-write, mass-assignment, race ; nested-authz, function-authz).
3. Ajouter un cas `bench/cases/` login-gated neutre (jeton court) pour que le scorer le mesure en continu.

## Avancement

- [x] Conception, mesure du jeton VAmPI (60 s)
- [x] `session.ts` + tests unitaires de l'oracle (JWT, clé conventionnelle, cookie, échec, cookie effacé)
- [x] Branchement authz-matrix + test d'intégration (serveur stub login + objets, BOLA prouvé, contrôle : serveur sain non prouvé)
- [x] Mesure VAmPI avant/après (voir Résultat)
- [x] Doc `ARCHITECTURE.md` (paragraphe « Sessions behind a login »), PR

- Fichiers : `src/checks/session.ts`, `src/checks/session.test.ts` (9 tests : oracle pur + stub login JWT et cookie, BOLA prouvé, serveur sain non prouvé, login raté, porte active), branchement `src/checks/authz-matrix.ts` (champ `login`, `resolveAccounts` avant la décision hors ligne/live). tsc vert.

## Questions d'arbitrage

- (aucune pour l'instant ; le login sous `allowActiveTesting` suit la règle existante des sondes live)
