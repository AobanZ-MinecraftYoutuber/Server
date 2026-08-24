const Database = require("better-sqlite3");

const db = new Database("dse.db");

const accounts = db.prepare(`
    SELECT user_id, username, created_at
    FROM accounts
`).all();

console.table(accounts);

db.close();