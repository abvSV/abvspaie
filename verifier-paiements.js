
require("dotenv").config();

const db = require("./src/config/database");

async function verifier() {
  try {
    const result = await db.query(
      `SELECT reference, merchant_id, mode, provider, status
       FROM public.transactions
       WHERE mode = $1 AND provider = $2
       ORDER BY created_at DESC
       LIMIT 10`,
      ["test", "abvs_test"]
    );

    console.log("Paiements de test :");
    console.table(result.rows);
  } catch (error) {
    console.error("Erreur :", error.message);
  } finally {
    await db.end();
  }
}

verifier();
