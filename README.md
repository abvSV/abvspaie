# ABVSPAIE

```
abvspaie/
├── vercel.json          réglages Vercel (publie uniquement le dossier site/)
├── .gitignore
├── README.md
├── supabase/            SQL à lancer dans Supabase (non publié sur le web)
│   ├── schema.sql
│   └── schema_paiements.sql
└── site/                tout ce qui est publié sur Vercel
    ├── index.html
    ├── assets/          abvs-config.js (URL + clé publique Supabase), abvs-auth.js
    ├── public/          connexion, mot de passe oublié, paiement, pages légales
    └── compte/          tableau de bord et pages protégées
```

## Mise en route
1. Supabase > SQL Editor : lancer `supabase/schema_paiements.sql`, puis `supabase/schema.sql`.
2. `site/assets/abvs-config.js` : renseigner l'URL et la clé publique (`anon` / publishable) du projet (Settings > Data API). Ne jamais y placer la clé `service_role`.
3. Supabase > Authentication > URL Configuration : Site URL = adresse Vercel ; Redirect URLs = `.../public/inscription-connexion.html` et `.../public/mot-de-passe-oublie.html`.
4. Vercel : importer le dépôt GitHub, Framework « Other », aucune commande de build.
5. Test local : VS Code + extension Live Server, en ouvrant le dossier `site/`.

## Avant la mise en production
- Appliquer et vérifier les deux scripts SQL d'abord sur un projet Supabase de test.
- Le mode test confirme automatiquement les paiements : ne pas le présenter comme un encaissement réel.
- Aucun prestataire de paiement ni webhook opérateur n'est intégré ici. Ne pas activer `test_mode = false`, `live_enabled` ou des liens `mode = 'live'` avant l'intégration et les tests de bout en bout du prestataire.
- La page Sécurité affiche la session courante et permet de fermer toutes les sessions ; la liste des autres appareils nécessite un service serveur et n'est pas disponible via le client public.
- La MFA par application TOTP utilise Supabase Auth ; la MFA par e-mail reste désactivée jusqu'à l'intégration d'un flux serveur vérifié. Appliquer `schema_paiements.sql` pour synchroniser les changements du nom d'entreprise du compte marchand. La recherche du tableau de bord porte sur les transactions et liens chargés par la page.
- Les écrans de gestion des API/webhooks, de l'équipe, des notifications, des décaissements et du KYC restent indisponibles tant que leurs services serveur ne sont pas implémentés.
- Vérifier les politiques RLS, les URL de redirection Auth et le parcours de paiement avec de vrais comptes de test avant le déploiement.
