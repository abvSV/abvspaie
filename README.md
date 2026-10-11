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
1. Supabase > SQL Editor : lancer `supabase/schema.sql`, puis `supabase/schema_paiements.sql`.
2. `site/assets/abvs-config.js` : remplacer `VOTRE-PROJET` par l'URL du projet (Settings > Data API).
3. Supabase > Authentication > URL Configuration : Site URL = adresse Vercel ; Redirect URLs = `.../public/inscription-connexion.html` et `.../public/mot-de-passe-oublie.html`.
4. Vercel : importer le dépôt GitHub, Framework « Other », aucune commande de build.
5. Test local : VS Code + extension Live Server, en ouvrant le dossier `site/`.
