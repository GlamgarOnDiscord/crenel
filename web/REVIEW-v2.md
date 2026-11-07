# Revue v2 — Crenel (web/src)

Revue en lecture seule. Rien n'a été modifié. Lignes approximatives.
Routeur : `createHashRouter` (main.tsx), choix volontaire pour l'hébergement statique et les captures, donc le hash routing n'est pas en soi un défaut. Le problème est l'usage incohérent de `<a href="#/...">`, `location.hash = ...` et `<Link>`.

---

## P0 — Bugs

1. **Lien Documentation cassé.** `components/Shell.tsx:46` — `<a href="#/app/docs">` : la route `/app/docs` n'existe pas (App.tsx), le catch-all `*` renvoie vers la landing. Correctif : créer la page docs ou retirer l'entrée ; utiliser `<NavLink>`.
2. **Lien « Docs » mort.** `pages/Landing.tsx:12` — `<a href="#">` ramène au hash vide donc à `/`. Correctif : pointer vers une vraie cible ou retirer.
3. **Bouton GitHub mort.** `pages/Landing.tsx:25` — `<Button><Github/> GitHub</Button>` sans `onClick` ni lien. Correctif : envelopper dans `<a href="…dépôt…" target="_blank" rel="noreferrer">`.
4. **Cartes cibles toutes identiques.** `pages/Targets.tsx:14` — chaque carte fait `href="#/app/overview"`, l'`id` de la cible est ignoré : cliquer « inboxly » affiche l'overview codé en dur d'acme-app. Correctif : lier vers `/app/overview?target=${t.id}` (ou route par cible) et passer l'id partout.
5. **Lignes de l'historique de scans trompeuses.** `pages/Scans.tsx:24` — `onClick` renvoie vers `/app/scan/run` (console « nouveau scan ») au lieu du détail du run cliqué. Correctif : route `/app/scans/:id` de détail, ou retirer le clic.
6. **Code mort + tri non appliqué.** `lib/types.ts:44-47` — `SEV_LABEL` et `SEV_RANK` ne sont utilisés nulle part ; l'overview affiche « triés par sévérité, prouvés d'abord » (Overview.tsx:72) mais l'ordre vient seulement de l'ordre manuel du mock. Correctif : trier `findings` avec `SEV_RANK` (+ état) ou retirer la mention.

## P1 — UX / interactions / accessibilité / responsive

7. **Lignes de tableau cliquables non accessibles au clavier.** `pages/Overview.tsx:78`, `pages/Findings.tsx:20`, `pages/Scans.tsx:24` — `<tr onClick>` sans `tabIndex`, `role`, ni `onKeyDown` ; non focalisable, non activable au clavier. De plus un `<Link>Voir</Link>` est imbriqué dans la ligne cliquable (double navigation, antipattern). Correctif : faire de la cellule principale un `<Link>` couvrant, ou `useNavigate` + `role="link"`/`tabIndex=0`/`onKeyDown` Enter, et supprimer le lien « Voir » redondant.
8. **Toggles non fonctionnels.** `pages/Settings.tsx:4` — `Toggle` est un `<span>` purement visuel : pas de `role="switch"`, pas d'`aria-checked`, non focalisable, aucun handler. Les réglages de politique ne se modifient pas. Correctif : `<button role="switch" aria-checked>` focalisable avec état.
9. **Filtres segmentés inertes.** `pages/Overview.tsx:44` (7j/14j/30j) et `pages/Findings.tsx:12` (Tous/Prouvés/Leads/Corrigés) — `<button>` sans `onClick`, état « on » statique, pas d'`aria-pressed`. Les filtres ne filtrent rien. Correctif : état réel + `aria-pressed`, et vider la liste → `EmptyState` pour « Corrigés ».
10. **Recherche ⌘K non interactive.** `components/Shell.tsx:32` — `<div className="search">` : pas de bouton/champ, non focalisable, aucun handler. Correctif : `<button>` qui ouvre une palette, raccourci clavier réel.
11. **« Révoquer » n'est pas un bouton.** `pages/Secrets.tsx:22` — `<span className="linkish">Révoquer</span>` non cliquable ni accessible (action destructive). Correctif : `<button>` avec confirmation.
12. **Affordances factices.** `pages/Overview.tsx:13` — `<span className="chipbtn">Cible acme-app ▾</span>` ressemble à un menu déroulant mais n'en est pas un. Correctif : vrai `<button>`/menu ou retirer le chevron.
13. **Sidebar en rangée peu maniable à 390 px.** `styles/base.css:205-213` — sous 720 px la `.side` passe en `flex-wrap` : 9 entilles de nav s'empilent sur plusieurs rangées, encombrant. Correctif : barre d'onglets basse ou menu « hamburger ».
14. **Topbar sans retour à la ligne.** `styles/base.css:64` — `.topbar` est `display:flex` sans `flex-wrap` ; à 390 px le titre + actions (ex. chipbtn + « Nouveau scan » sur Overview) peuvent déborder horizontalement. Correctif : `flex-wrap: wrap` et actions qui passent dessous.
15. **Barre d'action du prompt sans wrap.** `styles/base.css:154` + `pages/ScanRun.tsx:49` — `.prompt .row` est `flex` sans wrap ; modelchip + trombone + 4 chips `/slash` + envoi risquent de déborder à 390 px (seul `.slash` wrap en interne). Correctif : `flex-wrap: wrap` sur `.row`.
16. **Pages très courtes = grand vide en capture.** Secrets (3 lignes), Tests (4), Autorisation, Intégrations : contenu correctement calé en haut (`align-content:start`) mais la page paraît vide sous le pli. Correctif : bandeau de synthèse / compteurs en tête, ou largeur de contenu bornée + état vide quand pertinent.
17. **Contraste du texte estompé limite.** `styles/tokens.css:25` — `--fg-faint #767C8E` ≈ 4,2:1 sur `--panel`, en dessous du 4,5:1 AA pour le petit texte mono (11–12 px) très présent (emplacements, dates, `.note`, `.url`). Correctif : éclaircir `--fg-faint` (~#8A90A2) ou passer ce texte à 13 px.

## P2 — Finitions / cohérence / « générique »

18. **Mise en gras arbitraire du flux d'activité.** `pages/Overview.tsx:63` — `title.split(" ").slice(0,3)` met en gras les 3 premiers mots au hasard. Correctif : stocker `title`/`detail` séparés dans `data/mock.ts`.
19. **Puces de delta KPI incohérentes.** `pages/Overview.tsx:20-37` — même emplacement mélange compteur (« 1 corrigé »), delta (« +3 »), variation (« ▼ 0,4 j ») et durée (« 1m 12s »). Correctif : format unique (tendance +/− colorée) et déplacer la durée ailleurs.
20. **Mélange FR / EN dans les libellés.** `components/ui.tsx:34` — `SeverityChip` affiche `crit/high/med/low/info` bruts dans une UI française ; `StateBadge` garde « lead ». Correctif : libellés FR cohérents.
21. **Import redondant.** `pages/Overview.tsx:2` — `Plus` importé puis réimporté en alias `Plus as PlusIc`. Correctif : réutiliser le même symbole.
22. **Navigation incohérente.** `<a href="#/...">` (Targets), `location.hash=…` (tables), `<Link>` ailleurs. Correctif : tout en `<Link>`/`useNavigate`.
23. **Sparkline fragile.** `components/ui.tsx:68` — `i/(points.length-1)` donne `NaN` si un seul point. Correctif : garder `length>1`.
24. **Beaucoup de styles inline dispersés** (Landing, Overview, Settings…) → espacements incohérents, rendu « assemblé à la main ». Correctif : remonter dans des classes du design system (tokens d'espacement).
25. **Sémantique HTML.** `pages/Landing.tsx:49` — `<footer>` imbriqué dans `<header>`. Correctif : sortir le footer du header.
26. **Contraste des étiquettes de graphe.** `components/ui.tsx:93,97` — axes en `--fg-ghost #474C5D`, très peu lisibles pour des libellés de données. Correctif : `--fg-faint` au minimum.

## Contraste des boutons ambre — vérifié : OK

`.btn` = `#1A1204` sur `--brand #F2B01E` ≈ 9:1, bien au-dessus du 4,5:1 AA. Idem `.send` et la pastille du toggle. Aucun correctif nécessaire ; c'est `--fg-faint` (point 17) le vrai sujet de contraste.

## Mascotte SVG (brand/Logo.tsx)

Identité distinctive et volontairement hors du vert/cyan habituel : bon point. Mais la lecture « choucas sur un créneau tenant une clé » est partielle.

- **`Mark` (petit, 30 px) : pas de clé.** `brand/Logo.tsx:6-21` — seuls tête + bec + créneau + patte. À petite taille on lit « tête d'oiseau ambre sur un mur crénelé » ; l'idée de clé (le cœur du concept) est absente, donc la marque principale ne raconte pas l'histoire. Deux ambres proches (`--brand` / `--brand-deep`) se séparent mal à 30 px. Suggestion : ajouter une petite clé stylisée au bec, et augmenter le contraste tête/mur.
- **`Mascot` : clé illisible, silhouette d'oiseau vague.** `brand/Logo.tsx:48-50` — la panne de clé `M137 50l10 8…` est un enchevêtrement de fins traits qui se lit comme un gribouillis, pas comme une clé. Tête + corps sont deux ovales qui se chevauchent sans cou, queue ni pattes agrippant le créneau ; l'aile (`opacity 0.18`, ligne 55) est quasi invisible. Résultat : plutôt un blob ambre qu'un choucas. Suggestions concrètes : clé à anneau net + tige rectangulaire + 2 ou 3 dents carrées, tenue sous le bec avec un point de contact visible ; ajouter queue et pattes posées sur un merlon ; aile plus foncée et dessinée ; léger cou reliant tête et corps ; envisager un aplat 2 tons plutôt qu'un dégradé pour la netteté aux petites tailles ; faire du bec une forme bien raccordée à la tête.

## Pour s'éloigner du rendu « générique / IA »

Câbler les interactions qui font aujourd'hui semblant (recherche, filtres, toggles, menu cible), unifier la sémantique des deltas KPI, réduire les styles inline au profit de classes, et soigner la clé de la mascotte. La carte terminal de la landing et l'identité ambre sont de vrais partis pris à conserver.
