# ABVSPAIE

```
abvspaie/
├── api/                 fonctions Vercel : auth, KYC et webhooks
├── server/              utilitaires serveur (signature et chiffrement)
├── vercel.json          réglages Vercel (site statique + fonctions API)
├── .gitignore
├── README.md
├── supabase/            SQL à lancer dans Supabase (non publié sur le web)
│   ├── schema.sql
│   ├── schema_paiements.sql
│   ├── schema_webhooks.sql
│   ├── schema_kyc.sql
│   └── remove_email_mfa.sql
└── site/                tout ce qui est publié sur Vercel
    ├── index.html
    ├── assets/          abvs-config.js (URL + clé publique Supabase), abvs-auth.js
    ├── public/          connexion, mot de passe oublié, paiement, pages légales
    └── compte/          tableau de bord, examen KYC et pages protégées
```

## Mise en route
1. Supabase > SQL Editor : lancer `supabase/schema_paiements.sql`, puis `supabase/schema.sql`, `supabase/schema_webhooks.sql`, `supabase/schema_clients.sql` et enfin `supabase/schema_kyc.sql`. Cette dernière migration crée le bucket privé, les règles d'accès et le dépôt des justificatifs.
2. `site/assets/abvs-config.js` : renseigner l'URL et la clé publique (`anon` / publishable) du projet (Settings > Data API). Ne jamais y placer la clé `service_role`.
3. Supabase > Authentication > URL Configuration : Site URL = adresse Vercel ; Redirect URLs = `.../public/inscription-connexion.html` et `.../public/mot-de-passe-oublie.html`.
4. Vercel : importer le dépôt GitHub, Framework « Other », aucune commande de build. Les fonctions de `api/` sont déployées avec le site.
5. Prévisualisation locale : VS Code + extension Live Server, en ouvrant le dossier `site/`. Le serveur statique local ne fournit pas les fonctions KYC de `api/` ; pour tester les dépôts, utiliser le domaine Vercel déployé ou démarrer l'environnement Vercel Functions avec `vercel dev`.

Si un compte existant n'a pas de profil KYC, exécuter `supabase/repair_merchant_profiles.sql` dans le SQL Editor. Cette réparation idempotente crée uniquement les profils manquants et affiche le nombre restant. La page KYC récupère et initialise ensuite le profil du compte connecté via les fonctions sécurisées `ensure_merchant_profile` et `get_kyc_profile` définies dans `schema.sql`.

Les coordonnées recueillies au paiement servent à créer ou retrouver une fiche dans **Clients** ; le téléphone et l'e-mail ne sont jamais publiés. Les transactions antérieures à cette migration ne seront pas automatiquement rattachées : l'ancien flux ne conservait que le téléphone masqué.

## Vérification d'identité (KYC)

Dans **Paramètres > KYC**, tout marchand peut démarrer sa vérification de sa propre initiative après activation de la MFA. Ce formulaire couvre uniquement les personnes physiques ; les profils d'entreprise et les structures complexes ne sont pas encore pris en charge. Le parcours se fait en trois étapes : informations légales et choix de la pièce, dépôt des faces requises et d'un selfie, puis vérification et soumission explicite du dossier. La règle technique actuelle demande recto et verso pour une carte nationale d'identité ou un permis, et la page d'identité pour un passeport. Un selfie JPG ou PNG est également obligatoire. Elle est identique pour les pays proposés dans le formulaire et ne constitue pas une validation réglementaire pays par pays ; vérifier les obligations locales avant la mise en production. Le marchand renseigne aussi son nom légal et son pays de résidence. Huit fichiers PDF, JPG ou PNG de 4 Mo maximum chacun sont acceptés. La fonction Vercel valide la signature binaire avant l'envoi au bucket privé `merchant-kyc-documents`, sous un chemin aléatoire ne contenant pas le nom d'origine. La consultation, le dépôt et la soumission exigent une session MFA AAL2 ; RLS limite l'accès au compte propriétaire. Pendant l'examen, le dossier et ses justificatifs ne peuvent pas être modifiés ; après un refus, le marchand peut déposer des pièces et soumettre à nouveau. Le marchand ne peut ni modifier son statut ni supprimer un justificatif enregistré. Une insertion incomplète autorise uniquement le nettoyage de son objet orphelin.

La validation est manuelle. L'espace `site/compte/kyc-admin.html` et `/api/kyc/admin` permettent aux seuls utilisateurs dont `app_metadata.kyc_admin` vaut `true` d'examiner les dossiers en attente. L'API exige une session MFA AAL2, émet des liens de consultation des pièces valables 60 secondes, interdit l'auto-examen et consigne chaque dépôt, soumission et décision dans `kyc_audit_logs`. Une approbation exige les faces requises de la pièce d'identité, le selfie, les informations du profil et une trace de soumission. Le refus exige un motif ; après un refus, le marchand peut remplacer les faces de sa pièce et son selfie : les anciennes versions restent conservées et marquées comme remplacées, et seules les versions actuelles sont présentées pour une nouvelle décision. La limite de huit fichiers s'applique à l'ensemble des versions. L'approbation KYC ne met pas Live en service.

Si le dépôt indique que le dossier est déjà soumis ou que la limite est atteinte, vérifie le statut du profil et le nombre de justificatifs. Si l'API signale une configuration KYC incomplète, réapplique `supabase/schema_kyc.sql` dans Supabase, puis redéploie les fonctions Vercel. Réapplique également ce schéma pour activer le suivi des versions remplacées et réparer les anciens statuts vérifiés qui ne satisfont pas les preuves KYC requises.

Pour utiliser la **méthode 1** et traiter les dossiers directement dans Supabase, réapplique d'abord `supabase/schema_kyc.sql` depuis le SQL Editor. Dans le SQL Editor, cette requête liste les dossiers en attente et les chemins de leurs documents :

```sql
select p.user_id, p.kyc_full_name, p.kyc_country, p.kyc_document_type,
       p.kyc_submitted_at, d.document_type, d.document_side, d.storage_path
from public.merchant_profiles p
left join public.merchant_kyc_documents d
  on d.merchant_id = p.user_id and d.is_current
where p.kyc_status = 'pending'
order by p.kyc_submitted_at, d.created_at;
```

Ouvre ensuite **Storage > merchant-kyc-documents** et retrouve les fichiers par leur chemin `storage_path` (dossier `user_id` puis nom de fichier aléatoire). Après examen, prends la décision dans le SQL Editor en appelant `public.decide_kyc` ; n'édite jamais directement `kyc_status`. Remplace les UUID d'exemple par l'identifiant du marchand et celui d'un compte administrateur autorisé (`auth.users.raw_app_meta_data.kyc_admin = true`) :

```sql
-- Lister les identifiants des administrateurs KYC autorisés
select id
from auth.users
where raw_app_meta_data ->> 'kyc_admin' = 'true';

-- Approuver après examen des pièces et du selfie
select public.decide_kyc(
  'UUID_DU_MARCHAND'::uuid, 'verified', null, 'UUID_ADMIN_KYC'::uuid
);

-- Refuser avec un motif de 10 à 1000 caractères
select public.decide_kyc(
  'UUID_DU_MARCHAND'::uuid, 'rejected', 'Motif détaillé du refus', 'UUID_ADMIN_KYC'::uuid
);
```

Cette fonction vérifie que l'identifiant fourni appartient à un compte administrateur KYC, interdit l'auto-examen, confirme que le dossier est en attente et que les documents requis sont présents, puis met à jour le statut et écrit la décision dans `kyc_audit_logs` dans la même transaction. Le SQL Editor donne des privilèges élevés et ne transmet pas automatiquement l'identité de la personne qui exécute la requête : limite son accès aux personnes de confiance et utilise l'UUID de l'administrateur qui a réellement examiné le dossier pour l'audit. Le panneau KYC existant reste disponible comme alternative.

Depuis l'espace d'examen KYC, **Dépendances techniques** récapitule les bibliothèques et services utilisés ainsi que les rubriques qui en dépendent. La page est réservée aux administrateurs KYC ayant une session MFA AAL2 ; les éléments sont affichés dans un ordre aléatoire.

Pour corriger les anciens comptes éventuellement marqués « vérifiés » sans soumission, pièce d'identité et décision auditée, réexécute `supabase/schema_kyc.sql` dans Supabase. La migration remet ces statuts incohérents à `none` et désactive Live ; elle conserve l'historique d'audit. Seuls les dossiers avec les preuves complètes du flux manuel restent vérifiés. Ne marque jamais directement un profil comme vérifié dans SQL.

Pour corriger uniquement ces statuts après que la migration KYC est déjà installée, exécute `supabase/repair_kyc_legacy_status.sql` dans Supabase SQL Editor. Le script affiche le nombre de profils réinitialisés ; il conserve les journaux et les justificatifs.

Pour autoriser un administrateur, active d'abord la MFA sur son compte, puis définis `app_metadata.kyc_admin: true` depuis une opération administrative de confiance dans Supabase Auth (dashboard/Auth Admin API). Ne place jamais ce rôle dans `user_metadata` ni dans un champ modifiable par le navigateur. Configurer les variables serveur `SUPABASE_URL`, `SUPABASE_ANON_KEY` et `SUPABASE_SERVICE_ROLE_KEY` dans Vercel ; la clé de service ne doit jamais être publiée côté client. La signature binaire est contrôlée, mais aucun antivirus, outil de suppression/rétention automatisé ni prestataire KYC n'est intégré. Définir ces processus, les durées légales et les responsabilités de traitement avant production ; ne collecte pas de justificatifs réels avant cette validation.

## Retrait du code de sécurité par e-mail

La vérification par code e-mail a été retirée. La MFA reste disponible via une application d'authentification (TOTP), gérée par Supabase Auth.

Si `schema_email_mfa.sql` a déjà été appliqué dans Supabase, désactive d'abord le hook **Customize Access Token (JWT)** dans Supabase > Authentication > Hooks, puis exécute `supabase/remove_email_mfa.sql` dans Supabase SQL Editor. Cette migration supprime les politiques RLS ajoutées par cette fonction et ses tables et fonctions. Supprime aussi de Vercel les variables `EMAIL_MFA_TOKEN_HOOK_CONFIGURED`, `EMAIL_MFA_SECRET`, `BREVO_API_KEY`, `BREVO_SENDER_EMAIL` et `BREVO_SENDER_NAME` si elles ne servent à aucun autre usage, puis redéploie le site.

La rubrique **Statistiques** s'appuie sur les transactions du compte des 30 derniers jours. Le volume et la répartition par moyen de paiement ne comptent que les transactions réussies ; le taux de réussite compare celles-ci à toutes les transactions de la période.

L'intégration marchande actuellement disponible se fait via les liens de paiement hébergés. Aucune clé API serveur n'est fournie ; les webhooks configurés par un marchand reçoivent les événements envoyés par son application, et ne remplacent pas les notifications de paiement d'un prestataire.

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

Lancer les tests KYC et webhook avec `node --test tests/kyc-upload.test.js tests/kyc-admin.test.js tests/webhooks.test.js`.

## Avant la mise en production
- Appliquer et vérifier les scripts SQL d'abord sur un projet Supabase de test.
- Le mode test confirme automatiquement les paiements : ne pas le présenter comme un encaissement réel.
- Aucun prestataire de paiement ni webhook opérateur sortant n'est intégré ici. Le récepteur décrit ci-dessus traite uniquement les webhooks entrants vers ABVSPAIE. Ne pas activer `test_mode = false`, `live_enabled` ou des liens `mode = 'live'` avant l'intégration et les tests de bout en bout du prestataire.
- La page Sécurité affiche la session courante et permet de fermer toutes les sessions ; la liste des autres appareils nécessite un service serveur et n'est pas disponible via le client public.
- La MFA par application TOTP utilise Supabase Auth. Appliquer `schema_paiements.sql` pour synchroniser les changements du nom d'entreprise du compte marchand. La recherche du tableau de bord porte sur les transactions et liens chargés par la page.
- Les clés API, l'envoi de webhooks sortants, l'équipe, les notifications et les décaissements restent indisponibles tant que leurs services serveur ne sont pas implémentés. Le dépôt KYC existe, mais la vérification reste manuelle et requiert un processus de conservation conforme.
- Vérifier les politiques RLS, les URL de redirection Auth et le parcours de paiement avec de vrais comptes de test avant le déploiement.
