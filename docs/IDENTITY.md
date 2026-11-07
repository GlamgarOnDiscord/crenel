# Crenel, identité de marque

Document de travail, nuit du 07/11/2026. Fondé sur la recherche dans
`/root/research_notes/Bastion identite et app/`.

## Nom

**Crenel** (le créneau d'un rempart). Court, international, prononçable, évoque la
fortification sans le cliché du bouclier. « Bastion » est déjà pris (jeu, projets).
Alternatives gardées en réserve : Choucas, Poterne, Barbican, Guérite. À valider
(disponibilité du nom et du domaine) avant de graver.

## Concept et mascotte

Le **choucas de la tour** : un petit corvidé perché sur un créneau. Pourquoi ça
veut dire quelque chose, au lieu d'un bouclier générique :

- le choucas **collectionne les objets brillants** → Crenel trouve les clés et
  secrets que votre app laisse traîner ;
- il est perché sur un **créneau** → la fortification que vous gardez ;
- c'est une **vigie** → la surveillance continue.

Un seul personnage, muet, remixable (comme Octocat, le gopher, Ferris). Il tient
une clé dans le bec. Jamais de cadenas, de capuche de hacker, de globe.

### Icône (07/11, après-midi)

Version retenue par défaut : choucas indigo à **nuque argentée** (le signe de
l'espèce), **yeux et clé dorés**, qui surgit du coin bas-gauche sur un fond
pervenche uni. Fichier maître `web/public/crenel-icon-1024.png`, exports 512, 180,
64 et 32. Méthode : skill `s1dashu/ip-as-logo-skill` (MIT) : une silhouette ronde,
peu de formes, pas de pointes, perso dominant, rendu graphique doux ; générée en
GPT Image 2. Les dessins SVG codés à la main ont été écartés (jugés moches ou
inquiétants). Alternative gardée : la même clé avec une houppe à la place de la
nuque. Reste à faire : une version vectorielle propre.

## Couleur

- Accent **or-ambre** `#F2B01E` (la clé volée, un trésor), encre `#F7C84E` pour le
  texte sur fond sombre, profond `#B5810C`.
- Fond **bleu-noir** `#0B0C10`, panneaux plus clairs, hairlines.
- Choix délibéré : **ni vert ni cyan** (le défaut de tout outil de sécurité), et on
  s'écarte de l'orange déjà pris par GitLab, Rust, Mozilla.
- Sévérités (rouge/orange/jaune/vert/bleu) tenues distinctes de l'accent et
  toujours accompagnées d'une puce étiquetée, pour ne pas confondre « low » et
  « sélectionné ».

## Typographie

- **Display / wordmark** : Mona Sans (OFL, GitHub). Logotype en Mona Sans **Wide 900**
  (axe `wdth` 125), minuscules, suivi d'un petit carré ambre.
- **UI** : Instrument Sans (OFL).
- **Mono** (code, chemins, preuves) : JetBrains Mono (OFL). Upgrade possible :
  Commit Mono (OFL), à auto-héberger.
- Les icônes : **Lucide** (ISC, libre).

## Wordmark

`crenel` en minuscules, suivi d'un petit carré ambre : le créneau, qui sert aussi
de curseur de terminal. Toujours testé en monochrome et à 16 px.

## Ton de voix

Calme et rassurant, jamais anxiogène. On nomme le risque, on donne la preuve, et
on propose toujours la prochaine action. Pas de jargon gratuit, pas d'alarme.

## À éviter

Cadenas, bouclier plat à visage, hacker à capuche, globe, « 100 % sécurisé »,
dégradés violet-bleu génériques, Inter partout.
