# Bastion, notes de conception

Journal des décisions. Indépendant de tout SaaS : aucune dépendance ni code propre à un produit privé ne doit entrer ici.

## Décisions prises

- **Langage** : TypeScript partout (coeur + CLI), app desktop via Tauri plus tard. Le scan lourd est délégué à des outils externes.
- **Sécurité par conception** : le scope guard (`src/core/scope.ts`) ne teste que des hôtes déclarés, lecture seule par défaut, aucune action destructrice. C'est la condition pour que l'outil soit publiable.
- **Preuve obligatoire** : chaque finding est `proven` (preuve rejouable ou match déterministe) ou `unproven` (lead). La CI ne bloque que sur `proven` high/critical.
- **Autorisation lisible, pas de contournement** : pour le travail sur ses propres systèmes, on rend l'intention légitime claire (propriété, périmètre, but défensif). Jamais d'évasion de garde-fou.

## Intégrations à ajouter (obligatoire)

- **cloudflare/security-audit-skill** : https://github.com/cloudflare/security-audit-skill
  - À intégrer comme brique du harnais (audit de sécurité de code et de domaine). Demande de l'utilisateur, le 07/11/2026.
  - À faire : lire le skill, comprendre ce qu'il produit (format de findings, périmètre, dépendances), et l'exposer dans Bastion soit comme un check (`cloudflare-audit`) qui l'invoque et normalise sa sortie vers notre type `Finding`, soit comme un mode d'exécution. Vérifier la licence avant de l'embarquer ou de le lister comme dépendance.

## Pistes issues de la recherche (à transformer en code)

- Masquer les vieilles sorties d'outils plutôt que tout garder (coût divisé par 2 environ).
- Replanification adaptative + condition d'arrêt vérifiable + détecteur de répétition (pas seulement un plafond de pas).
- Actions de haut niveau plutôt que shell brut (effet majeur mesuré).
- Sous-agents en lecture seule, un seul fil qui décide et écrit.
- Validation déterministe séparée de la découverte ; ne jamais laisser un LLM-juge décider seul qu'une faille est prouvée.
- Sorties d'outils plafonnées et typées ; chargement différé des définitions d'outils (coût en tokens).
