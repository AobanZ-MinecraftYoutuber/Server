const WebSocket = require("ws");
const Database = require("better-sqlite3");
const argon2 = require("argon2");
const { randomUUID } = require("crypto");

const PORT = 8080;

// ===============================
// DATABASE
// ===============================

const db = new Database("dse.db");

// Add password_hash to new databases.
// If you're upgrading an older database, the migration below
// adds the column if it doesn't already exist.
db.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        created_at TEXT NOT NULL
    )
`);

try {
    db.exec(`
        ALTER TABLE accounts
        ADD COLUMN password_hash TEXT
    `);
} catch {
    // Column already exists. Nothing to do.
}

// ===============================
// DATABASE QUERIES
// ===============================

const findAccount = db.prepare(`
    SELECT user_id, username, password_hash, created_at
    FROM accounts
    WHERE username = ?
`);

const createAccount = db.prepare(`
    INSERT INTO accounts (
        user_id,
        username,
        password_hash,
        created_at
    )
    VALUES (?, ?, ?, ?)
`);

// ===============================
// ONLINE USERS
// ===============================

const users = new Map();

// ===============================
// WEBSOCKET SERVER
// ===============================

const server = new WebSocket.Server({
    port: PORT
});

console.log(`DSE server running on port ${PORT}`);

// ===============================
// SEND ERROR
// ===============================

function sendError(socket, type, code, message) {
    socket.send(JSON.stringify({
        type,
        code,
        message
    }));
}

// ===============================
// BROADCAST ONLINE USERS
// ===============================

function broadcastUserList() {
    const onlineUsers = [...users.values()].map(user => ({
        username: user.username,
        userId: user.userId
    }));

    const message = JSON.stringify({
        type: "user_list",
        users: onlineUsers
    });

    for (const socket of users.keys()) {
        if (socket.readyState === WebSocket.OPEN) {
            socket.send(message);
        }
    }
}

// ===============================
// CONNECTION
// ===============================

server.on("connection", (socket) => {
    console.log("A player connected.");

    // ===============================
    // MESSAGE
    // ===============================

    socket.on("message", async (data) => {
        try {
            const message = JSON.parse(data.toString());

            // ==========================================
            // CREATE ACCOUNT
            // ==========================================

            if (message.type === "create_account") {

                const username = String(message.username || "").trim();
                const password = String(message.password || "");

                if (!username || !password) {
                    sendError(
                        socket,
                        "account_error",
                        404,
                        "Username and password are required."
                    );

                    return;
                }

                // Check if username already exists
                const existingAccount = findAccount.get(username);

                if (existingAccount) {
                    sendError(
                        socket,
                        "account_error",
                        404,
                        "Account already exists."
                    );

                    return;
                }

                // Generate permanent UUID
                const userId = randomUUID();

                // Hash password using Argon2id
                const passwordHash = await argon2.hash(password, {
                    type: argon2.argon2id
                });

                // Save account
                createAccount.run(
                    userId,
                    username,
                    passwordHash,
                    new Date().toISOString()
                );

                console.log(`Created account for ${username}`);
                console.log(`User ID: ${userId}`);

                // Prevent logging in twice on the same connection
                if (users.has(socket)) {
                    sendError(
                        socket,
                        "account_error",
                        400,
                        "Already logged in."
                    );

                    return;
                }

                // Add player to online users (creation now also logs them in)
                users.set(socket, {
                    username,
                    userId
                });

                socket.send(JSON.stringify({
                    type: "account_created",
                    code: 200,
                    username,
                    userId
                }));

                // Update online players
                broadcastUserList();

                return;
            }
            // ==========================================
            // LOGIN
            // ==========================================

            if (message.type === "login") {

                const username = String(message.username || "").trim();
                const password = String(message.password || "");

                if (!username || !password) {
                    sendError(
                        socket,
                        "login_error",
                        404,
                        "Invalid username or password."
                    );

                    return;
                }

                // Find account
                const account = findAccount.get(username);

                // Don't reveal whether the username exists
                if (!account || !account.password_hash) {
                    sendError(
                        socket,
                        "login_error",
                        404,
                        "Invalid username or password."
                    );

                    return;
                }

                // Verify Argon2id password
                let passwordCorrect = false;

                try {
                    passwordCorrect = await argon2.verify(
                        account.password_hash,
                        password
                    );
                } catch {
                    passwordCorrect = false;
                }

                if (!passwordCorrect) {
                    console.log(`Failed login for ${username}`);

                    sendError(
                        socket,
                        "login_error",
                        404,
                        "Invalid username or password."
                    );

                    return;
                }

                // Prevent logging in twice on the same connection
                if (users.has(socket)) {
                    sendError(
                        socket,
                        "login_error",
                        400,
                        "Already logged in."
                    );

                    return;
                }

                // Prevent the same account being online twice
                for (const user of users.values()) {
                    if (user.userId === account.user_id) {

                        sendError(
                            socket,
                            "login_error",
                            409,
                            "Account is already online."
                        );

                        return;
                    }
                }

                // Add player to online users
                users.set(socket, {
                    username: account.username,
                    userId: account.user_id
                });

                console.log(`${account.username} joined DSE SMP`);
                console.log(`User ID: ${account.user_id}`);

                // Tell client login succeeded
                socket.send(JSON.stringify({
                    type: "login_ok",
                    code: 200,
                    username: account.username,
                    userId: account.user_id
                }));

                // Update online players
                broadcastUserList();

                return;
            }

            // ==========================================
            // UNKNOWN MESSAGE
            // ==========================================

            sendError(
                socket,
                "error",
                404,
                "Unknown request."
            );

        } catch (error) {

            console.log("Invalid data lol");
            console.log(error.message);

            sendError(
                socket,
                "error",
                400,
                "Invalid request."
            );
        }
    });

    // ===============================
    // DISCONNECT
    // ===============================

    socket.on("close", () => {

        const user = users.get(socket);

        if (user) {

            console.log(`${user.username} left DSE SMP`);
            console.log(`User ID: ${user.userId}`);

            users.delete(socket);

            broadcastUserList();
        }
    });

    // ===============================
    // ERROR
    // ===============================

    socket.on("error", (error) => {
        console.log("WebSocket error:", error.message);
    });
});

