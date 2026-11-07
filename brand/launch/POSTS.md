# Crenel : textes de lancement

À compléter avant publication : `[lien]` (dépôt GitHub ou site). Aucun chiffre, client ni citation n'a été ajouté ; les exemples de sortie reprennent le format réel de `crenel scan`.

Visuels : `x-announce.png`, `linkedin.png`, `ph-1-hero.png` à `ph-5-open-source.png`, `ph-thumbnail.png`, `open-source-card.png` (versions anglaises dans `en/`).

---

## Français

### X

Attaquez votre app avant qu'on le fasse.

Crenel est open source : il trouve les secrets exposés (clés dans le bundle, .env commités, paquets malveillants) et les failles d'autorisation entre comptes.

Chaque faille prouvée vient avec une requête rejouable. Puis Crenel écrit le test qui la garde hors de votre CI.

Gratuit, local, sans compte.
`npx crenel scan`

[lien]

### LinkedIn

Quand on lance un SaaS seul, la sécurité passe souvent après le reste. Une clé Stripe qui finit dans le bundle client, un .env commité un soir de fatigue, une route qui laisse un compte lire les données d'un autre : ce sont des erreurs banales, et ce sont les premières qu'un attaquant cherche.

J'ai construit Crenel pour attaquer sa propre app avant que quelqu'un d'autre le fasse.

Ce qu'il fait :
• 14 checks : secrets exposés, paquets malveillants connus, workflows CI, en-têtes, JWT, source maps, autorisation entre comptes, et d'autres.
• Il distingue les pistes des failles prouvées. Une faille prouvée vient avec la requête ou la commande pour la rejouer vous-même.
• Il transforme chaque faille en test de régression, pour que la CI échoue si elle revient.

C'est gratuit, open source (MIT), ça tourne en local et ça ne demande aucun compte :
`npx crenel scan`

Vos retours m'intéressent, surtout sur les faux positifs.
[lien]

### Product Hunt

**Tagline** (53 caractères)
Attaquez votre app avant qu'on le fasse. Open source.

**Description**
Crenel est un outil de sécurité open source pour fondateurs de SaaS. Il trouve les secrets exposés (clés dans le bundle, .env commités, paquets malveillants) et les failles d'autorisation entre comptes, prouve chacune par une requête rejouable, puis écrit le test qui la garde en CI. Gratuit, local, sans compte : `npx crenel scan`.

**Premier commentaire du fondateur**
Bonjour Product Hunt,

Je construis un SaaS en petite équipe, et je me suis rendu compte que les failles qui me faisaient peur n'étaient pas exotiques : une clé secrète dans le bundle client, un .env commité, une route où le compte A peut lire les objets du compte B.

Crenel est l'outil que je voulais pour ça :
1. `npx crenel scan` lance 14 checks sur votre projet, en local.
2. Il sépare les pistes (à vérifier) des failles prouvées. Chaque faille prouvée vient avec la commande pour la rejouer.
3. `crenel generate-tests` écrit un test par faille. Si elle revient, la pull request échoue.

Le contrôle d'autorisation entre comptes est volontairement déterministe, pas confié à un LLM. Il ne touche qu'aux hôtes que vous déclarez vous appartenir, et les requêtes actives sont désactivées par défaut.

C'est gratuit, sous licence MIT, et ça ne demande aucun compte. Je lis tous les commentaires : dites-moi ce qui manque ou ce qui sonne faux.

---

## English

### X

Attack your app before they do.

Crenel is open source: it finds exposed secrets (keys in your bundle, committed .env files, malicious packages) and cross-account authorization flaws.

Every proven flaw ships with a replayable request. Then Crenel writes the test that keeps it out of your CI.

Free, local, no account.
`npx crenel scan`

[link]

### LinkedIn

When you build a SaaS on your own, security often comes after everything else. A Stripe key that ends up in the client bundle, a .env committed late at night, a route that lets one account read another's data: these are ordinary mistakes, and they are the first things an attacker looks for.

I built Crenel to attack my own app before someone else does.

What it does:
• 14 checks: exposed secrets, known malicious packages, CI workflows, headers, JWT, source maps, cross-account authorization, and more.
• It separates leads from proven flaws. A proven flaw comes with the request or command to replay it yourself.
• It turns each flaw into a regression test, so CI fails if it comes back.

It is free, open source (MIT), runs locally and needs no account:
`npx crenel scan`

I would love your feedback, especially on false positives.
[link]

### Product Hunt

**Tagline** (44 characters)
Attack your app before they do. Open source.

**Description**
Crenel is an open source security tool for SaaS founders. It finds exposed secrets (keys in your bundle, committed .env files, malicious packages) and cross-account authorization flaws, proves each one with a replayable request, then writes the test that keeps it out in CI. Free, local, no account: `npx crenel scan`.

**Maker's first comment**
Hi Product Hunt,

I am building a SaaS with a tiny team, and I realised the flaws that scared me were not exotic: a secret key in the client bundle, a committed .env, a route where account A can read account B's objects.

Crenel is the tool I wanted for that:
1. `npx crenel scan` runs 14 checks on your project, locally.
2. It separates leads (to review) from proven flaws. Every proven flaw comes with the command to replay it.
3. `crenel generate-tests` writes one test per flaw. If it comes back, the pull request fails.

The cross-account check is deliberately deterministic, not left to an LLM. It only touches hosts you declare you own, and active requests are off by default.

It is free, MIT licensed, and needs no account. I read every comment: tell me what is missing or what feels off.
