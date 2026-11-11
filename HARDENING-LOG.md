# HARDENING-LOG (branche `security/hardening`)

Audit défensif du code de Crenel lui-même. Base : `065cef4` (origin/main). Ouvert le 2026-11-11.

Légende statut : `ouvert` · `en cours` · `corrigé (commit)` · `arbitrage` (décision attendue de Tom) · `accepté` (risque assumé, documenté).

## Synthèse priorisée

| # | Sévérité | Zone | Fichier:ligne | Statut |
|---|---|---|---|---|
| H1 | Élevée | Porte lecture seule : lexing GraphQL contournable | `src/core/net.ts:110-117` | corrigé (`fb744f9`) |
| H2 | Élevée | DNS rebinding : la résolution vérifiée n'est pas celle utilisée | `src/core/net.ts:79-95`, `:181` | **arbitrage Tom** (doc corrigée `8e90cdc`) |
| H3 | Moyenne | En-têtes d'authentification transmis à travers les redirections | `src/core/net.ts:178`, `:197-200` | corrigé (`b4e2b15`) |
| M4 | Moyenne | Clé du fournisseur LLM transmise en suivant une redirection | `src/agent/llm.ts:124` | corrigé (`d6b5058`) |
| M5 | Moyenne | Clés JSON dupliquées : différentiel de parseur sur `readOnlyPost` | `src/core/net.ts:129-134` | corrigé (`2acbe53`) |
| M6 | Faible | Mutation GraphQL en GET acceptée comme lecture | `src/core/net.ts:148` | corrigé (`2acbe53`) |
| L7 | Faible | Corps d'une réponse 3xx non consommé avant le saut suivant | `src/core/net.ts:197-200` | corrigé (`b4e2b15`) |
| L8 | Faible | Proxy : en-têtes nommés dans `Connection` non retirés | `src/core/egress-proxy.ts:103`, `:210` | ouvert |
| I9 | Info | `cmd /c start` sous Windows : échappement partiel de l'URL | `src/cli.ts:586` | accepté (URL interne) |

## Pour Tom : décision H2 (DNS rebinding)

Aucune mitigation partielle à la fois petite et saine : le `fetch` de Node n'expose pas l'adresse réellement contactée, donc on ne peut ni la vérifier après coup ni l'épingler sans changer de transport. En attendant, la doc (`net.ts` en-tête, `ARCHITECTURE.md`) dit la vérité sur la lacune (`8e90cdc`).

| Option | Ce que c'est | Coût estimé | Pour | Contre |
|---|---|---|---|---|
| (a) recommandée | Transport de `safeFetch` réécrit sur `node:http`/`node:https`, option `lookup` qui vérifie chaque adresse à la connexion (comme `egress-proxy.ts`) | ~150 à 200 lignes dans `net.ts` + ~80 lignes de tests (résolveur injectable, décompression gzip/deflate/br via `node:zlib`, conversion des en-têtes en `Headers`, plafond, abort) | zéro dépendance, testable sans réseau, même modèle que le proxy | gros diff sur le cœur du périmètre ; HTTP/1.1 uniquement (déjà le cas de fait) |
| (b) | Dépendance `undici` épinglée, `dispatcher: new Agent({ connect: { lookup } })` passé à `fetch` | ~15 lignes + 1 dépendance runtime | diff minimal, comportement `fetch` inchangé | casse la promesse « dependency-free », version d'undici à aligner avec celle embarquée par Node |

Avis relayé par l'utilisateur : (a), la plus alignée avec le principe zéro dépendance ; Tom tranche.

## Détail

### H1. Lexing GraphQL contournable : une mutation passe la porte lecture seule (Élevée)

- **Où** : `isGraphqlQueryOnly` (`src/core/net.ts:110-117`), utilisé par `readOnlyPost` puis par la porte de `safeFetch` (`:148`).
- **Problème** : le document est nettoyé en trois passes successives (blocs `"""`, puis chaînes `"..."`, puis commentaires `#`). L'ordre n'est pas celui d'un lexer : un `"""` placé dans un commentaire ouvre un « bloc » que la première passe efface jusqu'au `"""` suivant, mot-clé `mutation` compris.
- **Scénario concret (reproduit)** : corps `{"query":"query R { a } # \"\"\"\nmutation Del { deleteAll } # \"\"\"","operationName":"Del"}`. `isGraphqlQueryOnly` renvoie `true`, `readOnlyPost` renvoie `"graphql-query"`, donc le POST part **sans `allowActiveTesting`**. Le serveur GraphQL ignore les commentaires, voit deux opérations et exécute `Del` (désignée par `operationName`). Le modèle d'exploration (dont l'entrée contient des réponses de la cible, donc potentiellement une injection de prompt) peut ainsi déclencher une écriture sur une cible où le mode actif est désactivé.
- **Correctif** : un seul passage gauche-droite avec une alternance ordonnée (`"""…"""` avec échappement `\"""`, `"…"`, `#…`), exactement comme le lexer GraphQL ; tout ce qui reste est du code. Conservateur : en cas de doute, refus.
- **Test** : le PoC ci-dessus doit renvoyer `false` / `null` ; les requêtes légitimes existantes (`net.test.ts`) restent acceptées.

### H2. DNS rebinding : vérification et connexion résolvent séparément (Élevée, arbitrage)

- **Où** : `assertResolvesPublic` (`src/core/net.ts:79-95`) fait un `lookup`, puis `fetch` (`:181`) résout **à nouveau** le nom.
- **Problème** : le commentaire d'en-tête (point 2) annonce une protection contre le DNS rebinding qui n'existe pas : c'est un TOCTOU. Le proxy `egress-proxy.ts` épingle bien l'adresse vérifiée, pas `safeFetch`.
- **Scénario** : un hôte déclaré (ou un sous-domaine compromis / une entrée DNS contrôlée par un tiers) répond avec un TTL 0, d'abord une IP publique puis `169.254.169.254` ou `127.0.0.1`. Le GET d'un check ou du modèle atteint alors le service de métadonnées cloud ou un service local de la machine qui lance Crenel ; le corps revient dans le journal et dans le contexte du modèle.
- **Correctif proposé (décision requise)** :
  - (a) réécrire le transport de `safeFetch` sur `node:http`/`node:https` avec l'option `lookup` qui vérifie chaque adresse au moment de la connexion (sans dépendance, même approche que le proxy ; il faut gérer la décompression gzip/br/deflate et garder le SNI/Host) ;
  - (b) ajouter `undici` en dépendance et passer un `Agent({ connect: { lookup } })` comme `dispatcher` (diff minimal, mais une dépendance runtime de plus alors que l'outil se veut « dependency-free »).
  - Recommandation : (a), car il garde la promesse « sans dépendance » et le comportement est testable avec un résolveur injecté.

### H3. En-têtes d'authentification conservés sur une redirection cross-origin ou en clair (Moyenne)

- **Où** : `src/core/net.ts:178` réutilise `init.headers` à chaque saut ; `:197-200` suit le `Location`.
- **Problème** : `Authorization`, `Cookie` (jetons des comptes A/B/C de l'authz-matrix et de l'exploration) sont renvoyés tels quels vers un autre hôte déclaré et après un passage `https:` vers `http:`. La spec fetch les retire sur changement d'origine ; ici `redirect: "manual"` contourne ce comportement.
- **Scénario** : `https://app.example.com/x` répond `302 Location: http://app.example.com/y` (ou vers `legacy.example.com`, aussi déclaré) : le jeton Bearer du compte de test part en clair ou vers un service qui n'aurait pas dû le recevoir.
- **Correctif** : à chaque saut, si l'origine change ou si le protocole descend vers `http:`, retirer `authorization`, `cookie`, `proxy-authorization` (insensible à la casse). Le jeton Cloudflare Access est déjà recalculé par saut.
- **Test** : serveur local à deux origines, vérifier que le second saut ne reçoit pas les en-têtes.

### M4. Clé du fournisseur LLM transmise sur redirection (Moyenne)

- **Où** : `postJson` (`src/agent/llm.ts:124`) : `fetch` suit les redirections par défaut.
- **Problème** : undici retire `authorization` sur changement d'origine, mais **pas** `x-api-key` (fournisseur `anthropic-api`), et n'empêche pas une descente vers `http:` sur la même origine.
- **Scénario** : un `baseUrl` de passerelle (OpenRouter, LiteLLM, proxy d'entreprise) mal configuré ou compromis répond `307 Location: https://autre-hote/…` : la clé `x-api-key` part vers cet hôte.
- **Correctif** : `redirect: "error"` dans `postJson` (une API de modèle ne redirige pas légitimement un POST ; `deliver.ts` fait déjà le même choix avec `manual`).
- **Test** : serveur local qui renvoie 307 vers un second serveur ; le second ne doit recevoir aucune requête.

### M5. Clés JSON dupliquées dans `readOnlyPost` (Moyenne)

- **Où** : `src/core/net.ts:129-134`.
- **Problème** : `JSON.parse` garde la **dernière** occurrence d'une clé. Un serveur dont le parseur garde la première (ou refuse autrement) voit une autre opération.
- **Scénario** : `{"jsonrpc":"2.0","method":"tools/call","method":"tools/list",…}` est classé `mcp-list` par Crenel alors qu'un serveur « first-wins » exécute `tools/call`. Idem pour `query`.
- **Correctif** : refuser (retour `null`) tout corps dont l'objet de premier niveau contient une clé en double ; détection par un petit balayage des clés de premier niveau (décodage des échappements via `JSON.parse` de la chaîne de clé).
- **Test** : les deux corps ci-dessus renvoient `null`.

### M6. Mutation GraphQL en GET (Faible)

- **Où** : `src/core/net.ts:148` : tout GET est une lecture.
- **Problème** : certains serveurs GraphQL exécutent une mutation passée en `?query=mutation{…}`.
- **Correctif** : si un paramètre `query` d'un GET ressemble à un document GraphQL (`{`, `query`, `mutation`, `subscription` en tête) et que `isGraphqlQueryOnly` le refuse, exiger `allowActiveTesting`. Ne fait que refuser davantage ; aucun impact sur les preuves.
- **Test** : GET `?query=mutation{x}` refusé sans mode actif ; `?query={me{id}}` accepté.

### L7. Corps 3xx non consommé (Faible)

- `src/core/net.ts:197-200` : le corps de la réponse de redirection n'est ni lu ni annulé ; la socket reste occupée jusqu'au GC. Correctif : `await res.body?.cancel().catch(() => {})` avant `continue`.

### L8. Proxy : en-têtes hop-by-hop nommés (Faible)

- `src/core/egress-proxy.ts:103`, `:210` : la liste est statique ; les en-têtes listés dans `Connection: x-foo` ne sont pas retirés (RFC 9110 §7.6.1). Impact limité (les outils sont non intrusifs) ; correctif : retirer aussi les noms listés dans `Connection`.

### I9. `cmd /c start` (Info, accepté)

- `src/cli.ts:586` : seul `&` est échappé, mais l'URL est construite par Crenel (`http://127.0.0.1:<port>/?token=<base64url>`), jamais par une entrée externe. Pas de correctif ; à revoir si l'URL devient paramétrable.

## Vérifié sans problème (pour mémoire)

- Console locale `src/server/http.ts` : jeton aléatoire comparé en temps constant, contrôle du `Host` (anti DNS rebinding), contrôle d'`Origin` sur les écritures, cookie `HttpOnly; SameSite=Strict`, redirection post-jeton limitée aux chemins locaux, service statique confiné à `web/dist` (`resolve` + préfixe `root + sep`).
- `explore.file-match` : `insideProject` résout les liens symboliques (`realpathSync`) et refuse chemins absolus, octet nul et sortie du projet.
- `src/generate/tests.ts` : toutes les valeurs issues d'un finding passent par `JSON.stringify` ou `esc` (backslash, backtick, `$`).
- Secrets LLM : noms de variables validés (`ENV_NAME`), valeur lue à l'appel, jamais en argv ; `baseUrl` sans identifiants, https obligatoire hors loopback, refus d'un hôte cible.
- Proxy d'egress : adresse épinglée après vérification, jeton par exécution comparé en temps constant, ports CONNECT restreints.
- Lancement de processus : `spawn` sans shell, argv en tableau (toolbox, docker, wsl).
- Dépendances runtime : 3, versions exactes épinglées (`picocolors`, `yaml`, `zod`).

## Reste à auditer

- `src/toolbox/free-args.ts` (liste de refus des options des outils : complétude, formes `--flag=valeur`, alias courts).
- `src/toolbox/docker.ts` / `wsl.ts` (montages, réseau du conteneur, variables d'environnement transmises).
- `src/integrations/*` (stockage des secrets de webhook, signature, Slack).
- Regex des checks `src/checks/*` (ReDoS sur corps de 2 Mo).
- `pnpm audit` (réseau requis).

## Journal

- 2026-11-11 : audit initial (v1). PoC H1 reproduit localement (`isGraphqlQueryOnly` renvoie `true` sur un document contenant une mutation).
- 2026-11-11 : H1, H3 (+L7), M4, M5, M6 corrigés, chacun avec test de non-régression ; `tsc --noEmit` vert ; suite complète 633/634 (1 test non exécuté, préexistant), 0 échec. H3 retire aussi `apikey` / `x-api-key` (en-têtes BaaS utilisés par les checks Supabase) sur changement d'origine ; une montée `http:` vers `https:` du même hôte les conserve. M5 ne regarde que les clés de premier niveau (celles qui décident de l'opération). H2 : doc corrigée, décision pour Tom.
