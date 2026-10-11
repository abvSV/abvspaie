# ABVSPAIE

```
abvspaie/
├── api/                 fonctions Vercel : création et réception des webhooks
├── server/              utilitaires serveur (signature et chiffrement)
├── vercel.json          réglages Vercel (site statique + fonctions API)
├── .gitignore
├── README.md
├── supabase/            SQL à lancer dans Supabase (non publié sur le web)
│   ├── schema.sql
│   ├── schema_paiements.sql
│   └── schema_webhooks.sql
└── site/                tout ce qui est publié sur Vercel
    ├── index.html
    ├── assets/          abvs-config.js (URL + clé publique Supabase), abvs-auth.js
    ├── public/          connexion, mot de passe oublié, paiement, pages légales
    └── compte/          tableau de bord et pages protégées
```

## Mise en route
1. Supabase > SQL Editor : lancer `supabase/schema_paiements.sql`, puis `supabase/schema.sql`, `supabase/schema_webhooks.sql` et `supabase/schema_clients.sql`. Le dernier script active les fiches clients et modifie la fonction `create_payment` ; il est requis pour utiliser **Clients** et les nouvelles coordonnées du formulaire de paiement.
2. `site/assets/abvs-config.js` : renseigner l'URL et la clé publique (`anon` / publishable) du projet (Settings > Data API). Ne jamais y placer la clé `service_role`.
3. Supabase > Authentication > URL Configuration : Site URL = adresse Vercel ; Redirect URLs = `.../public/inscription-connexion.html` et `.../public/mot-de-passe-oublie.html`.
4. Vercel : importer le dépôt GitHub, Framework « Other », aucune commande de build. Les fonctions de `api/` sont déployées avec le site.
5. Test local : VS Code + extension Live Server, en ouvrant le dossier `site/`.

Les coordonnées recueillies au paiement servent à créer ou retrouver une fiche dans **Clients** ; le téléphone et l'e-mail ne sont jamais publiés. Les transactions antérieures à cette migration ne seront pas automatiquement rattachées : l'ancien flux ne conservait que le téléphone masqué.

## Webhooks entrants

Le tableau de bord crée une URL de réception par endpoint. Le récepteur accepte les POST JSON de taille maximale 256 Ko, authentifiés par HMAC-SHA256, avec un horodatage de ±5 minutes. Les livraisons répétées avec le même `X-ABVS-Delivery` ne sont enregistrées qu'une fois. Les événements valides sont conservés dans Supabase et consultables dans **Webhooks > Données reçues**. Les secrets sont chiffrés avec AES-256-GCM côté serveur ; la clé de chiffrement n'est jamais publiée au navigateur.

### Configuration de production

Dans Vercel > Project > Settings > Environment Variables, définir pour Production (et Preview si nécessaire) :

- `SUPABASE_URL` : URL du projet Supabase.
- `SUPABASE_ANON_KEY` : clé publique `anon` / publishable.
- `SUPABASE_SERVICE_ROLE_KEY` : clé `service_role` du projet ; **secret serveur, jamais dans `site/` ni dans le navigateur**.
- `PUBLIC_APP_URL` : URL HTTPS publique du site, par exemple `https://abvspaie.example`.
- `WEBHOOK_ENCRYPTION_KEY` : clé aléatoire de 32 octets encodée en base64. La générer une seule fois avec `node -p "require('node:crypto').randomBytes(32).toString('base64')"` et la conserver dans un gestionnaire de secrets. Ne pas la régénérer après création des endpoints, sinon leurs secrets déjà chiffrés ne pourront plus être déchiffrés.

Après avoir appliqué `supabase/schema_webhooks.sql` et défini ces variables, redéployer le projet. Dans le compte marchand, ouvrir **Webhooks > Configuration**, nommer l'endpoint puis le créer. Copier l'URL et le secret affiché une seule fois. Le secret doit rester dans le serveur de l'application émettrice. Le bouton **Envoyer un test fictif** permet de vérifier l'installation ; le JSON apparaît dans **Données reçues**.

### Format de signature envoyé par l'application

Envoyer ces en-têtes avec chaque POST : `Content-Type: application/json`, `X-ABVS-Timestamp` (secondes Unix), `X-ABVS-Signature: sha256=<HMAC hexadécimal>` et `X-ABVS-Delivery` (identifiant stable unique pour les tentatives d'une même livraison). Cet identifiant est obligatoire : il assure l'idempotence et empêche de traiter plusieurs fois une requête rejouée. La signature est calculée sur les octets exacts du corps avec la chaîne `timestamp.corps`.

Exemple Node.js avec des données fictives :

```js
const crypto = require("node:crypto");

(async () => {
  const url = process.env.ABVS_WEBHOOK_URL;
  const secret = process.env.ABVS_WEBHOOK_SECRET;
  const timestamp = String(Math.floor(Date.now() / 1000));
  const deliveryId = crypto.randomUUID();
  const body = JSON.stringify({
    event: "test.webhook",
    data: { message: "Test ABVSPAIE", amount: 12500, currency: "XOF" },
    test: true
  });
  const signature = crypto.createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-ABVS-Timestamp": timestamp,
      "X-ABVS-Signature": `sha256=${signature}`,
      "X-ABVS-Delivery": deliveryId
    },
    body
  });
  console.log(response.status, await response.json());
})().catch(console.error);
```

Une livraison acceptée renvoie `202` avec son `delivery_id`. Les erreurs utilisent notamment `400` (JSON/en-têtes invalides), `401` (horodatage ou signature invalides), `404` (endpoint inconnu/désactivé), `413` (corps trop grand) et `415` (type de contenu incorrect). Désactiver un endpoint dans le tableau de bord invalide immédiatement son secret. Ne transmettez pas de mots de passe, de données de carte bancaire ou d'autres informations sensibles dans le corps du webhook.

Lancer les tests unitaires du récepteur avec `node --test tests/webhooks.test.js`.

## Avant la mise en production
- Appliquer et vérifier les trois scripts SQL d'abord sur un projet Supabase de test.
- Le mode test confirme automatiquement les paiements : ne pas le présenter comme un encaissement réel.
- Aucun prestataire de paiement ni webhook opérateur sortant n'est intégré ici. Le récepteur décrit ci-dessus traite uniquement les webhooks entrants vers ABVSPAIE. Ne pas activer `test_mode = false`, `live_enabled` ou des liens `mode = 'live'` avant l'intégration et les tests de bout en bout du prestataire.
- La page Sécurité affiche la session courante et permet de fermer toutes les sessions ; la liste des autres appareils nécessite un service serveur et n'est pas disponible via le client public.
- La MFA par application TOTP utilise Supabase Auth ; la MFA par e-mail reste désactivée jusqu'à l'intégration d'un flux serveur vérifié. Appliquer `schema_paiements.sql` pour synchroniser les changements du nom d'entreprise du compte marchand. La recherche du tableau de bord porte sur les transactions et liens chargés par la page.
- Les clés API, l'envoi de webhooks sortants, l'équipe, les notifications, les décaissements et le KYC restent indisponibles tant que leurs services serveur ne sont pas implémentés.
- Vérifier les politiques RLS, les URL de redirection Auth et le parcours de paiement avec de vrais comptes de test avant le déploiement.
