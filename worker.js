const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=UTF-8"
};

/* =========================================================
   SHIT.BLEJ PRO
   Cloudflare Workers + D1 + Assets
   NON-DESTRUCTIVE BACKEND
========================================================= */

const APP_NAME = "SHIT.BLEJ PRO";
const DEFAULT_COMMISSION = 5;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS
  });
}

function clean(v) {
  return String(v ?? "").trim();
}

function num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function getToken(request) {
  const h = request.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  return h.slice(7).trim();
}

function randomToken(length = 64) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map(b => chars[b % chars.length])
    .join("");
}

function hex(bytes) {
  return Array.from(bytes)
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(value) {
  const bytes = new Uint8Array(value.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(
      value.substring(i * 2, i * 2 + 2),
      16
    );
  }

  return bytes;
}

async function passwordHash(password, saltHex = null) {
  const salt = saltHex
    ? fromHex(saltHex)
    : crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    hash: hex(new Uint8Array(bits)),
    salt: hex(salt)
  };
}

/* =========================================================
   DATABASE HELPERS
========================================================= */

async function safeColumn(env, table, column, definition) {
  try {
    await env.DB.prepare(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    ).run();
  } catch (_) {}
}

async function setupDatabase(env) {

  /* USERS */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS auth_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT DEFAULT '',
      email TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      identifier TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      role TEXT DEFAULT 'customer',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await safeColumn(env, "auth_accounts", "name", "TEXT DEFAULT ''");
  await safeColumn(env, "auth_accounts", "email", "TEXT DEFAULT ''");
  await safeColumn(env, "auth_accounts", "phone", "TEXT DEFAULT ''");
  await safeColumn(env, "auth_accounts", "identifier", "TEXT DEFAULT ''");
  await safeColumn(env, "auth_accounts", "role", "TEXT DEFAULT 'customer'");
  await safeColumn(
    env,
    "auth_accounts",
    "created_at",
    "TEXT DEFAULT CURRENT_TIMESTAMP"
  );

  /* SESSIONS */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  /* FAVORITES */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS saved_listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, product_id)
    )
  `).run();

  /* BLOCKED USERS */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS blocked_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      blocked_by INTEGER NOT NULL,
      reason TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  /* BLOCKED PRODUCTS */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS blocked_listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      blocked_by INTEGER NOT NULL,
      reason TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  /* SETTINGS */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS marketplace_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT UNIQUE NOT NULL,
      setting_value TEXT DEFAULT ''
    )
  `).run();

  /* PRODUCTS */

  await safeColumn(env, "products", "name", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "title", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "description", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "price", "REAL DEFAULT 0");
  await safeColumn(env, "products", "image", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "image_url", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "seller_id", "INTEGER");
  await safeColumn(env, "products", "seller", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "sellerName", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "sellerPhone", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "sellerEmail", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "category", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "stock", "INTEGER DEFAULT 0");
  await safeColumn(env, "products", "city", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "condition", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "phone", "TEXT DEFAULT ''");
  await safeColumn(env, "products", "negotiable", "INTEGER DEFAULT 0");
  await safeColumn(
    env,
    "products",
    "created_at",
    "TEXT DEFAULT CURRENT_TIMESTAMP"
  );

  /* ORDERS */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      buyer_id INTEGER,
      quantity INTEGER DEFAULT 1,
      total_price REAL DEFAULT 0,
      status TEXT DEFAULT 'pending',
      customer_name TEXT DEFAULT '',
      customer_phone TEXT DEFAULT '',
      customer_city TEXT DEFAULT '',
      customer_address TEXT DEFAULT '',
      payment_method TEXT DEFAULT 'cash_on_delivery',
      order_code TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await safeColumn(env, "orders", "product_id", "INTEGER");
  await safeColumn(env, "orders", "buyer_id", "INTEGER");
  await safeColumn(env, "orders", "quantity", "INTEGER DEFAULT 1");
  await safeColumn(env, "orders", "total_price", "REAL DEFAULT 0");
  await safeColumn(env, "orders", "status", "TEXT DEFAULT 'pending'");
  await safeColumn(env, "orders", "customer_name", "TEXT DEFAULT ''");
  await safeColumn(env, "orders", "customer_phone", "TEXT DEFAULT ''");
  await safeColumn(env, "orders", "customer_city", "TEXT DEFAULT ''");
  await safeColumn(env, "orders", "customer_address", "TEXT DEFAULT ''");
  await safeColumn(
    env,
    "orders",
    "payment_method",
    "TEXT DEFAULT 'cash_on_delivery'"
  );
  await safeColumn(env, "orders", "order_code", "TEXT DEFAULT ''");
  await safeColumn(
    env,
    "orders",
    "created_at",
    "TEXT DEFAULT CURRENT_TIMESTAMP"
  );

  /* MONETIZATION */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS promotions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      seller_id INTEGER NOT NULL,
      type TEXT DEFAULT 'promoted',
      plan TEXT DEFAULT '',
      price REAL DEFAULT 0,
      starts_at TEXT DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT,
      active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      product_id INTEGER,
      order_id INTEGER,
      type TEXT DEFAULT '',
      amount REAL DEFAULT 0,
      platform_fee REAL DEFAULT 0,
      seller_earnings REAL DEFAULT 0,
      status TEXT DEFAULT 'pending',
      description TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS platform_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT UNIQUE NOT NULL,
      setting_value TEXT DEFAULT ''
    )
  `).run();

  /* DEFAULT SETTINGS */

  const defaults = {
    commission_rate: "5",
    promo_1_day: "100",
    promo_7_day: "300",
    promo_30_day: "700",
    vip_7_day: "500",
    platform_name: "SHIT.BLEJ",
    admin_email: "admin@shitblej.al"
  };

  for (const [key, value] of Object.entries(defaults)) {
    await env.DB.prepare(`
      INSERT OR IGNORE INTO platform_settings
      (setting_key, setting_value)
      VALUES (?, ?)
    `)
      .bind(key, value)
      .run();
  }
}

/* =========================================================
   SETTINGS
========================================================= */

async function getSetting(env, key, fallback = "") {
  const row = await env.DB.prepare(`
    SELECT setting_value
    FROM platform_settings
    WHERE setting_key = ?
    LIMIT 1
  `)
    .bind(key)
    .first();

  return row
    ? row.setting_value
    : fallback;
}

async function getCommission(env) {
  const value = await getSetting(
    env,
    "commission_rate",
    String(DEFAULT_COMMISSION)
  );

  const n = Number(value);

  if (!Number.isFinite(n)) {
    return DEFAULT_COMMISSION;
  }

  return Math.max(0, Math.min(100, n));
}

/* =========================================================
   AUTH
========================================================= */

async function currentUser(request, env) {
  const token = getToken(request);

  if (!token) return null;

  const user = await env.DB.prepare(`
    SELECT
      a.id,
      a.name,
      a.email,
      a.phone,
      a.role
    FROM sessions s
    JOIN auth_accounts a
      ON a.id = s.user_id
    LEFT JOIN blocked_users b
      ON b.user_id = a.id
    WHERE s.token = ?
      AND b.id IS NULL
    LIMIT 1
  `)
    .bind(token)
    .first();

  return user || null;
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    throw new Error("UNAUTHORIZED");
  }

  return user;
}

async function requireAdmin(request, env) {
  const user = await requireUser(request, env);

  if (
    user.role !== "admin" &&
    user.role !== "owner"
  ) {
    throw new Error("FORBIDDEN");
  }

  return user;
}

/* =========================================================
   PRODUCT FORMAT
========================================================= */

function formatProduct(p) {
  if (!p) return null;

  return {
    ...p,

    id: Number(p.id),

    title:
      p.title ||
      p.name ||
      "",

    name:
      p.name ||
      p.title ||
      "",

    description:
      p.description || "",

    price:
      num(p.price),

    stock:
      num(p.stock),

    seller_id:
      p.seller_id == null
        ? null
        : Number(p.seller_id),

    image:
      p.image ||
      p.image_url ||
      "",

    image_url:
      p.image_url ||
      p.image ||
      "",

    seller:
      p.seller ||
      p.sellerName ||
      p.seller_account_name ||
      "",

    sellerName:
      p.sellerName ||
      p.seller ||
      p.seller_account_name ||
      "",

    sellerPhone:
      p.sellerPhone ||
      p.sellerPhone ||
      p.seller_account_phone ||
      p.phone ||
      "",

    sellerEmail:
      p.sellerEmail ||
      p.seller_account_email ||
      "",

    city:
      p.city || "",

    condition:
      p.condition || "",

    phone:
      p.phone || "",

    negotiable:
      Number(p.negotiable || 0),

    promoted:
      Number(p.promoted || 0) === 1,

    is_promoted:
      Number(p.promoted || 0) === 1
  };
}

async function findProduct(env, id) {
  const p = await env.DB.prepare(`
    SELECT
      p.*,

      a.name AS seller_account_name,
      a.email AS seller_account_email,
      a.phone AS seller_account_phone,

      CASE
        WHEN pr.id IS NOT NULL
         AND pr.active = 1
         AND datetime(pr.expires_at) > datetime('now')
        THEN 1
        ELSE 0
      END AS promoted

    FROM products p

    LEFT JOIN auth_accounts a
      ON a.id = p.seller_id

    LEFT JOIN promotions pr
      ON pr.product_id = p.id
     AND pr.active = 1
     AND datetime(pr.expires_at) > datetime('now')

    WHERE p.id = ?

    ORDER BY pr.id DESC

    LIMIT 1
  `)
    .bind(id)
    .first();

  return p ? formatProduct(p) : null;
}

/* =========================================================
   ORDER FORMAT
========================================================= */

function formatOrder(o) {
  return {
    ...o,

    id: Number(o.id),

    product_id:
      o.product_id == null
        ? null
        : Number(o.product_id),

    buyer_id:
      o.buyer_id == null
        ? null
        : Number(o.buyer_id),

    seller_id:
      o.seller_id == null
        ? null
        : Number(o.seller_id),

    quantity:
      num(o.quantity, 1),

    total_price:
      num(o.total_price),

    platform_fee:
      num(o.platform_fee),

    seller_earnings:
      num(o.seller_earnings),

    product_title:
      o.product_title ||
      o.product_name ||
      "Produkt",

    product_name:
      o.product_name ||
      o.product_title ||
      "Produkt",

    product_image:
      o.product_image ||
      o.image_url ||
      "",

    status:
      o.status || "pending"
  };
}

/* =========================================================
   MAIN
========================================================= */

export default {

  async fetch(request, env) {

    const url = new URL(request.url);
    const path = url.pathname;

    try {

      /* OPTIONS */

      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: CORS
        });
      }

      /* DATABASE */

      await setupDatabase(env);

      /* =====================================================
         API HEALTH
      ===================================================== */

      if (
        path === "/api" ||
        path === "/api/"
      ) {
        return json({
          success: true,
          app: APP_NAME,
          status: "online"
        });
      }

      /* =====================================================
         REGISTER
      ===================================================== */

      if (
        path === "/api/auth/register" &&
        request.method === "POST"
      ) {

        const body = await request.json();

        const name = clean(body.name);
        const email = clean(body.email).toLowerCase();
        const phone = clean(body.phone);
        const password = String(body.password || "");

        const requestedRole =
          clean(body.role).toLowerCase();

        const role =
          requestedRole === "seller"
            ? "seller"
            : "customer";

        if (!name) {
          return json({
            success: false,
            error: "Vendos emrin."
          }, 400);
        }

        if (!email || !email.includes("@")) {
          return json({
            success: false,
            error: "Email nuk është i vlefshëm."
          }, 400);
        }

        if (password.length < 4) {
          return json({
            success: false,
            error: "Password duhet të ketë të paktën 4 karaktere."
          }, 400);
        }

        const existing = await env.DB.prepare(`
          SELECT id
          FROM auth_accounts
          WHERE LOWER(email) = ?
             OR LOWER(identifier) = ?
          LIMIT 1
        `)
          .bind(email, email)
          .first();

        if (existing) {
          return json({
            success: false,
            error: "Ky email ekziston."
          }, 409);
        }

        const { hash, salt } =
          await passwordHash(password);

        const result = await env.DB.prepare(`
          INSERT INTO auth_accounts
          (
            name,
            email,
            phone,
            identifier,
            password_hash,
            password_salt,
            role
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
          .bind(
            name,
            email,
            phone,
            email,
            hash,
            salt,
            role
          )
          .run();

        return json({
          success: true,
          message: "Llogaria u krijua.",
          user: {
            id: result.meta.last_row_id,
            name,
            email,
            phone,
            role
          }
        }, 201);
      }

      /* =====================================================
         LOGIN
      ===================================================== */

      if (
        path === "/api/auth/login" &&
        request.method === "POST"
      ) {

        const body = await request.json();

        const identifier =
          clean(
            body.identifier ||
            body.email
          ).toLowerCase();

        const password =
          String(body.password || "");

        if (!identifier || !password) {
          return json({
            success: false,
            error: "Plotëso të gjitha fushat."
          }, 400);
        }

        const account = await env.DB.prepare(`
          SELECT *
          FROM auth_accounts
          WHERE LOWER(email) = ?
             OR LOWER(identifier) = ?
          LIMIT 1
        `)
          .bind(identifier, identifier)
          .first();

        if (!account) {
          return json({
            success: false,
            error: "Email ose password i gabuar."
          }, 401);
        }

        const blocked = await env.DB.prepare(`
          SELECT id
          FROM blocked_users
          WHERE user_id = ?
          LIMIT 1
        `)
          .bind(account.id)
          .first();

        if (blocked) {
          return json({
            success: false,
            error: "Kjo llogari është bllokuar."
          }, 403);
        }

        const { hash } =
          await passwordHash(
            password,
            account.password_salt
          );

        if (hash !== account.password_hash) {
          return json({
            success: false,
            error: "Email ose password i gabuar."
          }, 401);
        }

        const token = randomToken(64);

        await env.DB.prepare(`
          INSERT INTO sessions
          (
            user_id,
            token
          )
          VALUES (?, ?)
        `)
          .bind(account.id, token)
          .run();

        return json({
          success: true,
          token,

          user: {
            id: account.id,
            name: account.name || "",
            email: account.email || "",
            phone: account.phone || "",
            role: account.role || "customer"
          }
        });
      }

      /* =====================================================
         ME
      ===================================================== */

      if (
        path === "/api/auth/me" &&
        request.method === "GET"
      ) {

        const user =
          await currentUser(request, env);

        if (!user) {
          return json({
            success: false,
            error: "Nuk jeni i loguar."
          }, 401);
        }

        return json({
          success: true,
          user
        });
      }

      /* =====================================================
         LOGOUT
      ===================================================== */

      if (
        path === "/api/auth/logout" &&
        request.method === "POST"
      ) {

        const token = getToken(request);

        if (token) {
          await env.DB.prepare(`
            DELETE FROM sessions
            WHERE token = ?
          `)
            .bind(token)
            .run();
        }

        return json({
          success: true
        });
      }

      /* =====================================================
         PRODUCTS SEARCH
      ===================================================== */

      if (
        path === "/api/products/search" &&
        request.method === "GET"
      ) {

        const q =
          clean(url.searchParams.get("q"));

        const category =
          clean(url.searchParams.get("category"));

        let sql = `
          SELECT
            p.*,

            a.name AS seller_account_name,
            a.email AS seller_account_email,
            a.phone AS seller_account_phone,

            CASE
              WHEN pr.id IS NOT NULL
               AND pr.active = 1
               AND datetime(pr.expires_at) > datetime('now')
              THEN 1
              ELSE 0
            END AS promoted

          FROM products p

          LEFT JOIN auth_accounts a
            ON a.id = p.seller_id

          LEFT JOIN promotions pr
            ON pr.product_id = p.id
           AND pr.active = 1
           AND datetime(pr.expires_at) > datetime('now')

          LEFT JOIN blocked_listings bl
            ON bl.product_id = p.id

          WHERE bl.id IS NULL
        `;

        const params = [];

        if (q) {
          sql += `
            AND (
              LOWER(COALESCE(p.title,'')) LIKE ?
              OR LOWER(COALESCE(p.name,'')) LIKE ?
              OR LOWER(COALESCE(p.description,'')) LIKE ?
              OR LOWER(COALESCE(p.category,'')) LIKE ?
              OR LOWER(COALESCE(p.city,'')) LIKE ?
            )
          `;

          const s = `%${q.toLowerCase()}%`;

          params.push(
            s,
            s,
            s,
            s,
            s
          );
        }

        if (category) {
          sql += `
            AND LOWER(COALESCE(p.category,'')) =
                LOWER(?)
          `;

          params.push(category);
        }

        const min =
          url.searchParams.get("min");

        const max =
          url.searchParams.get("max");

        if (min !== null && min !== "") {
          sql += `
            AND CAST(p.price AS REAL) >= ?
          `;

          params.push(num(min));
        }

        if (max !== null && max !== "") {
          sql += `
            AND CAST(p.price AS REAL) <= ?
          `;

          params.push(num(max));
        }

        sql += `
          GROUP BY p.id
          ORDER BY promoted DESC, p.id DESC
          LIMIT 300
        `;

        const result =
          await env.DB.prepare(sql)
            .bind(...params)
            .all();

        return json(
          (result.results || [])
            .map(formatProduct)
        );
      }

      /* =====================================================
         ALL PRODUCTS
      ===================================================== */

      if (
        path === "/api/products" &&
        request.method === "GET"
      ) {

        const category =
          clean(url.searchParams.get("category"));

        let sql = `
          SELECT
            p.*,

            a.name AS seller_account_name,
            a.email AS seller_account_email,
            a.phone AS seller_account_phone,

            CASE
              WHEN pr.id IS NOT NULL
               AND pr.active = 1
               AND datetime(pr.expires_at) > datetime('now')
              THEN 1
              ELSE 0
            END AS promoted

          FROM products p

          LEFT JOIN auth_accounts a
            ON a.id = p.seller_id

          LEFT JOIN promotions pr
            ON pr.product_id = p.id
           AND pr.active = 1
           AND datetime(pr.expires_at) > datetime('now')

          LEFT JOIN blocked_listings bl
            ON bl.product_id = p.id

          WHERE bl.id IS NULL
        `;

        const params = [];

        if (category) {
          sql += `
            AND LOWER(COALESCE(p.category,'')) =
                LOWER(?)
          `;

          params.push(category);
        }

        sql += `
          GROUP BY p.id
          ORDER BY promoted DESC, p.id DESC
          LIMIT 500
        `;

        const result =
          await env.DB.prepare(sql)
            .bind(...params)
            .all();

        return json(
          (result.results || [])
            .map(formatProduct)
        );
      }

      /* =====================================================
         SAVED PRODUCTS
      ===================================================== */

      if (
        path === "/api/products/saved" &&
        request.method === "GET"
      ) {

        const user =
          await requireUser(request, env);

        const result =
          await env.DB.prepare(`
            SELECT p.*
            FROM saved_listings s

            JOIN products p
              ON p.id = s.product_id

            LEFT JOIN blocked_listings bl
              ON bl.product_id = p.id

            WHERE s.user_id = ?
              AND bl.id IS NULL

            ORDER BY s.id DESC
          `)
            .bind(user.id)
            .all();

        return json({
          success: true,
          products:
            (result.results || [])
              .map(formatProduct)
        });
      }

      /* =====================================================
         SINGLE PRODUCT
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+$/.test(path) &&
        request.method === "GET"
      ) {

        const id =
          Number(path.split("/").pop());

        const blocked =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_listings
            WHERE product_id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (blocked) {
          return json({
            success: false,
            error: "Ky produkt nuk është i disponueshëm."
          }, 404);
        }

        const product =
          await findProduct(env, id);

        if (!product) {
          return json({
            success: false,
            error: "Produkti nuk u gjet."
          }, 404);
        }

        return json({
          success: true,
          product
        });
      }

      /* =====================================================
         SAVE / UNSAVE
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+\/save$/.test(path) &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(request, env);

        const id =
          Number(path.split("/")[3]);

        const product =
          await env.DB.prepare(`
            SELECT id
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (!product) {
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);
        }

        const saved =
          await env.DB.prepare(`
            SELECT id
            FROM saved_listings
            WHERE user_id = ?
              AND product_id = ?
            LIMIT 1
          `)
            .bind(user.id, id)
            .first();

        if (saved) {

          await env.DB.prepare(`
            DELETE FROM saved_listings
            WHERE user_id = ?
              AND product_id = ?
          `)
            .bind(user.id, id)
            .run();

          return json({
            success: true,
            saved: false
          });
        }

        await env.DB.prepare(`
          INSERT OR IGNORE INTO saved_listings
          (user_id, product_id)
          VALUES (?, ?)
        `)
          .bind(user.id, id)
          .run();

        return json({
          success: true,
          saved: true
        });
      }

      /* =====================================================
         CREATE PRODUCT
      ===================================================== */

      if (
        path === "/api/products" &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(request, env);

        if (
          user.role !== "seller" &&
          user.role !== "admin" &&
          user.role !== "owner"
        ) {
          return json({
            success: false,
            error: "Vetëm shitësit mund të publikojnë produkte."
          }, 403);
        }

        const body =
          await request.json();

        const title =
          clean(
            body.title ||
            body.name
          );

        const description =
          clean(body.description);

        const price =
          num(body.price);

        const image =
          clean(
            body.image_url ||
            body.image
          );

        const category =
          clean(
            body.category ||
            "Të tjera"
          );

        const stock =
          Math.max(
            0,
            Math.floor(
              num(body.stock, 1)
            )
          );

        const city =
          clean(body.city);

        const condition =
          clean(body.condition);

        const phone =
          clean(
            body.phone ||
            user.phone
          );

        const negotiable =
          body.negotiable
            ? 1
            : 0;

        if (!title) {
          return json({
            success: false,
            error: "Titulli mungon."
          }, 400);
        }

        if (price < 0) {
          return json({
            success: false,
            error: "Çmimi nuk është i vlefshëm."
          }, 400);
        }

        const result =
          await env.DB.prepare(`
            INSERT INTO products
            (
              name,
              title,
              description,
              price,
              image,
              image_url,
              seller_id,
              seller,
              sellerName,
              sellerPhone,
              sellerEmail,
              category,
              stock,
              city,
              condition,
              phone,
              negotiable,
              created_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          `)
            .bind(
              title,
              title,
              description,
              price,
              image,
              image,
              user.id,
              user.name || "",
              user.name || "",
              phone,
              user.email || "",
              category,
              stock,
              city,
              condition,
              phone,
              negotiable
            )
            .run();

        const product =
          await findProduct(
            env,
            result.meta.last_row_id
          );

        return json({
          success: true,
          product
        }, 201);
      }

      /* =====================================================
         UPDATE PRODUCT
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+$/.test(path) &&
        request.method === "PUT"
      ) {

        const user =
          await requireUser(request, env);

        const id =
          Number(path.split("/").pop());

        const existing =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (!existing) {
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);
        }

        if (
          user.role !== "admin" &&
          user.role !== "owner" &&
          Number(existing.seller_id) !== Number(user.id)
        ) {
          return json({
            success: false,
            error: "Nuk keni akses."
          }, 403);
        }

        const body =
          await request.json();

        const title =
          clean(
            body.title ??
            body.name ??
            existing.title ??
            existing.name
          );

        const description =
          clean(
            body.description ??
            existing.description
          );

        const price =
          num(
            body.price ??
            existing.price
          );

        const image =
          clean(
            body.image_url ??
            body.image ??
            existing.image_url ??
            existing.image
          );

        const category =
          clean(
            body.category ??
            existing.category ??
            "Të tjera"
          );

        const stock =
          Math.max(
            0,
            Math.floor(
              num(
                body.stock ??
                existing.stock
              )
            )
          );

        const city =
          clean(
            body.city ??
            existing.city
          );

        const condition =
          clean(
            body.condition ??
            existing.condition
          );

        const phone =
          clean(
            body.phone ??
            existing.phone
          );

        const negotiable =
          body.negotiable === undefined
            ? Number(existing.negotiable || 0)
            : body.negotiable
              ? 1
              : 0;

        await env.DB.prepare(`
          UPDATE products
          SET
            name = ?,
            title = ?,
            description = ?,
            price = ?,
            image = ?,
            image_url = ?,
            category = ?,
            stock = ?,
            city = ?,
            condition = ?,
            phone = ?,
            negotiable = ?
          WHERE id = ?
        `)
          .bind(
            title,
            title,
            description,
            price,
            image,
            image,
            category,
            stock,
            city,
            condition,
            phone,
            negotiable,
            id
          )
          .run();

        return json({
          success: true,
          product:
            await findProduct(env, id)
        });
      }

      /* =====================================================
         DELETE PRODUCT
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+$/.test(path) &&
        request.method === "DELETE"
      ) {

        const user =
          await requireUser(request, env);

        const id =
          Number(path.split("/").pop());

        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (!product) {
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);
        }

        if (
          user.role !== "admin" &&
          user.role !== "owner" &&
          Number(product.seller_id) !== Number(user.id)
        ) {
          return json({
            success: false,
            error: "Nuk keni akses."
          }, 403);
        }

        await env.DB.prepare(`
          DELETE FROM saved_listings
          WHERE product_id = ?
        `)
          .bind(id)
          .run();

        await env.DB.prepare(`
          DELETE FROM promotions
          WHERE product_id = ?
        `)
          .bind(id)
          .run();

        await env.DB.prepare(`
          DELETE FROM blocked_listings
          WHERE product_id = ?
        `)
          .bind(id)
          .run();

        await env.DB.prepare(`
          DELETE FROM products
          WHERE id = ?
        `)
          .bind(id)
          .run();

        return json({
          success: true,
          message: "Produkti u fshi."
        });
      }

      /* =====================================================
         CREATE ORDER
      ===================================================== */

      if (
        path === "/api/orders" &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(request, env);

        const body =
          await request.json();

        const productId =
          num(
            body.product_id ||
            body.productId
          );

        const quantity =
          Math.max(
            1,
            Math.floor(
              num(body.quantity, 1)
            )
          );

        if (!productId) {
          return json({
            success: false,
            error: "Produkti mungon."
          }, 400);
        }

        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(productId)
            .first();

        if (!product) {
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);
        }

        const blocked =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_listings
            WHERE product_id = ?
            LIMIT 1
          `)
            .bind(productId)
            .first();

        if (blocked) {
          return json({
            success: false,
            error: "Ky produkt nuk është i disponueshëm."
          }, 400);
        }

        if (
          Number(product.seller_id) ===
          Number(user.id)
        ) {
          return json({
            success: false,
            error: "Nuk mund të blesh produktin tënd."
          }, 400);
        }

        if (
          Number(product.stock) > 0 &&
          quantity > Number(product.stock)
        ) {
          return json({
            success: false,
            error:
              `Ka vetëm ${product.stock} copë në stok.`
          }, 400);
        }

        const total =
          Number(product.price || 0) *
          quantity;

        const code =
          "SABI-" +
          new Date()
            .toISOString()
            .slice(0, 10)
            .replaceAll("-", "") +
          "-" +
          randomToken(4).toUpperCase();

        const result =
          await env.DB.prepare(`
            INSERT INTO orders
            (
              product_id,
              buyer_id,
              quantity,
              total_price,
              status,
              customer_name,
              customer_phone,
              customer_city,
              customer_address,
              payment_method,
              order_code,
              created_at
            )
            VALUES
            (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          `)
            .bind(
              productId,
              user.id,
              quantity,
              total,
              clean(
                body.customer_name ||
                user.name
              ),
              clean(
                body.customer_phone ||
                user.phone
              ),
              clean(body.customer_city),
              clean(body.customer_address),
              clean(
                body.payment_method ||
                "cash_on_delivery"
              ),
              code
            )
            .run();

        if (Number(product.stock) > 0) {
          await env.DB.prepare(`
            UPDATE products
            SET stock = stock - ?
            WHERE id = ?
              AND stock >= ?
          `)
            .bind(
              quantity,
              productId,
              quantity
            )
            .run();
        }

        return json({
          success: true,

          order: {
            id: result.meta.last_row_id,
            order_code: code,
            product_id: productId,
            quantity,
            total_price: total,
            status: "pending"
          }
        }, 201);
      }

      /* =====================================================
         ORDERS
      ===================================================== */

      if (
        path === "/api/orders" &&
        request.method === "GET"
      ) {

        const user =
          await requireUser(request, env);

        let result;

        if (
          user.role === "admin" ||
          user.role === "owner"
        ) {

          result =
            await env.DB.prepare(`
              SELECT
                o.*,

                p.title AS product_title,
                p.name AS product_name,
                p.image_url AS product_image,
                p.seller_id,
                p.seller,
                p.sellerName,

                a.name AS buyer_name,
                a.email AS buyer_email,
                a.phone AS buyer_account_phone,

                COALESCE(
                  t.platform_fee,
                  0
                ) AS platform_fee,

                COALESCE(
                  t.seller_earnings,
                  0
                ) AS seller_earnings

              FROM orders o

              LEFT JOIN products p
                ON p.id = o.product_id

              LEFT JOIN auth_accounts a
                ON a.id = o.buyer_id

              LEFT JOIN transactions t
                ON t.order_id = o.id
               AND t.type = 'commission'

              ORDER BY o.id DESC
            `)
              .all();

        } else {

          result =
            await env.DB.prepare(`
              SELECT
                o.*,

                p.title AS product_title,
                p.name AS product_name,
                p.image_url AS product_image,
                p.seller_id,
                p.seller,
                p.sellerName,

                a.name AS buyer_name,
                a.email AS buyer_email,
                a.phone AS buyer_account_phone,

                COALESCE(
                  t.platform_fee,
                  0
                ) AS platform_fee,

                COALESCE(
                  t.seller_earnings,
                  0
                ) AS seller_earnings

              FROM orders o

              LEFT JOIN products p
                ON p.id = o.product_id

              LEFT JOIN auth_accounts a
                ON a.id = o.buyer_id

              LEFT JOIN transactions t
                ON t.order_id = o.id
               AND t.type = 'commission'

              WHERE
                o.buyer_id = ?
                OR p.seller_id = ?

              ORDER BY o.id DESC
            `)
              .bind(
                user.id,
                user.id
              )
              .all();
        }

        return json({
          success: true,
          orders:
            (result.results || [])
              .map(formatOrder)
        });
      }

      /* =====================================================
         UPDATE ORDER
      ===================================================== */

      if (
        /^\/api\/orders\/[0-9]+$/.test(path) &&
        request.method === "PUT"
      ) {

        const user =
          await requireUser(request, env);

        const id =
          Number(path.split("/").pop());

        const order =
          await env.DB.prepare(`
            SELECT
              o.*,
              p.seller_id
            FROM orders o

            LEFT JOIN products p
              ON p.id = o.product_id

            WHERE o.id = ?

            LIMIT 1
          `)
            .bind(id)
            .first();

        if (!order) {
          return json({
            success: false,
            error: "Porosia nuk ekziston."
          }, 404);
        }

        const body =
          await request.json();

        let status =
          clean(body.status).toLowerCase();

        if (status === "delivered") {
          status = "completed";
        }

        const allowed = [
          "pending",
          "confirmed",
          "shipped",
          "completed",
          "cancelled"
        ];

        if (!allowed.includes(status)) {
          return json({
            success: false,
            error: "Status i pavlefshëm."
          }, 400);
        }

        const seller =
          Number(order.seller_id) === Number(user.id);

        const buyer =
          Number(order.buyer_id) === Number(user.id);

        const admin =
          user.role === "admin" ||
          user.role === "owner";

        if (!admin && !seller && !buyer) {
          return json({
            success: false,
            error: "Nuk keni akses."
          }, 403);
        }

        if (
          buyer &&
          !seller &&
          !admin &&
          status !== "cancelled"
        ) {
          return json({
            success: false,
            error:
              "Blerësi mund vetëm ta anulojë porosinë."
          }, 403);
        }

        const oldStatus =
          clean(order.status).toLowerCase();

        if (
          oldStatus === "cancelled" &&
          status !== "cancelled" &&
          !admin
        ) {
          return json({
            success: false,
            error: "Porosia është anuluar."
          }, 400);
        }

        /* RESTORE STOCK WHEN CANCELLED */

        if (
          status === "cancelled" &&
          oldStatus !== "cancelled"
        ) {

          const p =
            await env.DB.prepare(`
              SELECT stock
              FROM products
              WHERE id = ?
              LIMIT 1
            `)
              .bind(order.product_id)
              .first();

          if (p) {
            await env.DB.prepare(`
              UPDATE products
              SET stock = COALESCE(stock,0) + ?
              WHERE id = ?
            `)
              .bind(
                Number(order.quantity || 1),
                order.product_id
              )
              .run();
          }
        }

        await env.DB.prepare(`
          UPDATE orders
          SET status = ?
          WHERE id = ?
        `)
          .bind(status, id)
          .run();

        /* =====================================================
           COMMISSION
           ONLY ON COMPLETED
        ===================================================== */

        if (
          status === "completed" &&
          oldStatus !== "completed"
        ) {

          const commissionRate =
            await getCommission(env);

          const total =
            Number(order.total_price || 0);

          const fee =
            Math.round(
              total *
              commissionRate /
              100 *
              100
            ) / 100;

          const earnings =
            Math.round(
              (total - fee) * 100
            ) / 100;

          await env.DB.prepare(`
            INSERT INTO transactions
            (
              user_id,
              product_id,
              order_id,
              type,
              amount,
              platform_fee,
              seller_earnings,
              status,
              description
            )
            VALUES
            (?, ?, ?, 'commission', ?, ?, ?, 'completed', ?)
          `)
            .bind(
              order.seller_id,
              order.product_id,
              order.id,
              total,
              fee,
              earnings,
              `Komision ${commissionRate}% për porosinë ${order.order_code || order.id}`
            )
            .run();
        }

        return json({
          success: true,
          status
        });
      }

      /* =====================================================
         SELLER PROMOTION
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+\/promote$/.test(path) &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(request, env);

        const productId =
          Number(path.split("/")[3]);

        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(productId)
            .first();

        if (!product) {
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);
        }

        if (
          user.role !== "admin" &&
          user.role !== "owner" &&
          Number(product.seller_id) !== Number(user.id)
        ) {
          return json({
            success: false,
            error: "Nuk keni akses."
          }, 403);
        }

        const body =
          await request.json();

        const plan =
          clean(body.plan || body.duration);

        let days = 1;
        let price = num(body.price);

        if (
          plan === "1" ||
          plan === "1d" ||
          plan === "1_day"
        ) {
          days = 1;
          price = num(
            await getSetting(
              env,
              "promo_1_day",
              "100"
            )
          );
        }

        if (
          plan === "7" ||
          plan === "7d" ||
          plan === "7_day"
        ) {
          days = 7;
          price = num(
            await getSetting(
              env,
              "promo_7_day",
              "300"
            )
          );
        }

        if (
          plan === "30" ||
          plan === "30d" ||
          plan === "30_day"
        ) {
          days = 30;
          price = num(
            await getSetting(
              env,
              "promo_30_day",
              "700"
            )
          );
        }

        if (!price) {
          price = days === 1
            ? 100
            : days === 7
              ? 300
              : 700;
        }

        const start =
          new Date();

        const expires =
          new Date(
            start.getTime() +
            days *
            24 *
            60 *
            60 *
            1000
          );

        await env.DB.prepare(`
          UPDATE promotions
          SET active = 0
          WHERE product_id = ?
        `)
          .bind(productId)
          .run();

        const result =
          await env.DB.prepare(`
            INSERT INTO promotions
            (
              product_id,
              seller_id,
              type,
              plan,
              price,
              starts_at,
              expires_at,
              active
            )
            VALUES
            (?, ?, 'promoted', ?, ?, ?, ?, 1)
          `)
            .bind(
              productId,
              user.id,
              `${days}_day`,
              price,
              start.toISOString(),
              expires.toISOString()
            )
            .run();

        await env.DB.prepare(`
          INSERT INTO transactions
          (
            user_id,
            product_id,
            type,
            amount,
            status,
            description
          )
          VALUES
          (?, ?, 'promotion', ?, 'pending', ?)
        `)
          .bind(
            user.id,
            productId,
            price,
            `Promovim produkti ${productId} për ${days} ditë`
          )
          .run();

        return json({
          success: true,
          promotion: {
            id: result.meta.last_row_id,
            product_id: productId,
            days,
            price,
            status: "pending",
            expires_at: expires.toISOString()
          }
        }, 201);
      }

      /* =====================================================
         VIP
      ===================================================== */

      if (
        path === "/api/vip" &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(request, env);

        const price =
          num(
            await getSetting(
              env,
              "vip_7_day",
              "500"
            )
          );

        await env.DB.prepare(`
          INSERT INTO transactions
          (
            user_id,
            type,
            amount,
            status,
            description
          )
          VALUES
          (?, 'vip', ?, 'pending', 'VIP 7 ditë')
        `)
          .bind(
            user.id,
            price
          )
          .run();

        return json({
          success: true,
          vip: {
            days: 7,
            price,
            status: "pending"
          }
        }, 201);
      }

      /* =====================================================
         ADMIN STATS
      ===================================================== */

      if (
        path === "/api/admin/stats" &&
        request.method === "GET"
      ) {

        await requireAdmin(request, env);

        const users =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM auth_accounts
          `).first();

        const products =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM products
          `).first();

        const orders =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM orders
          `).first();

        const sellers =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM auth_accounts
            WHERE role = 'seller'
          `).first();

        const revenue =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(platform_fee),0) AS total
            FROM transactions
            WHERE type = 'commission'
              AND status = 'completed'
          `).first();

        const promotions =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(amount),0) AS total
            FROM transactions
            WHERE type = 'promotion'
              AND status IN ('completed','pending')
          `).first();

        return json({
          success: true,

          stats: {
            users: Number(users?.count || 0),
            products: Number(products?.count || 0),
            orders: Number(orders?.count || 0),
            sellers: Number(sellers?.count || 0),
            revenue: Number(revenue?.total || 0),
            promotion_revenue:
              Number(promotions?.total || 0)
          }
        });
      }

      /* =====================================================
         ADMIN USERS
      ===================================================== */

      if (
        path === "/api/users/all" &&
        request.method === "GET"
      ) {

        await requireAdmin(request, env);

        const result =
          await env.DB.prepare(`
            SELECT
              a.id,
              a.name,
              a.email,
              a.phone,
              a.identifier,
              a.role,
              a.created_at,

              CASE
                WHEN b.id IS NULL THEN 0
                ELSE 1
              END AS blocked

            FROM auth_accounts a

            LEFT JOIN blocked_users b
              ON b.user_id = a.id

            ORDER BY a.id DESC
          `)
            .all();

        return json({
          success: true,
          users:
            result.results || []
        });
      }

      /* =====================================================
         ADMIN BLOCK USER
      ===================================================== */

      if (
        /^\/api\/users\/[0-9]+\/block$/.test(path) &&
        (
          request.method === "PUT" ||
          request.method === "POST"
        )
      ) {

        const admin =
          await requireAdmin(request, env);

        const userId =
          Number(path.split("/")[3]);

        if (
          userId === Number(admin.id)
        ) {
          return json({
            success: false,
            error: "Nuk mund të bllokosh veten."
          }, 400);
        }

        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_users
            WHERE user_id = ?
            LIMIT 1
          `)
            .bind(userId)
            .first();

        if (existing) {

          await env.DB.prepare(`
            DELETE FROM blocked_users
            WHERE user_id = ?
          `)
            .bind(userId)
            .run();

          return json({
            success: true,
            blocked: false
          });
        }

        let body = {};

        try {
          body = await request.json();
        } catch (_) {}

        await env.DB.prepare(`
          INSERT INTO blocked_users
          (
            user_id,
            blocked_by,
            reason
          )
          VALUES (?, ?, ?)
        `)
          .bind(
            userId,
            admin.id,
            clean(body.reason)
          )
          .run();

        await env.DB.prepare(`
          DELETE FROM sessions
          WHERE user_id = ?
        `)
          .bind(userId)
          .run();

        return json({
          success: true,
          blocked: true
        });
      }

      /* =====================================================
         ADMIN BLOCK PRODUCT
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+\/block$/.test(path) &&
        (
          request.method === "PUT" ||
          request.method === "POST"
        )
      ) {

        const admin =
          await requireAdmin(request, env);

        const productId =
          Number(path.split("/")[3]);

        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_listings
            WHERE product_id = ?
            LIMIT 1
          `)
            .bind(productId)
            .first();

        if (existing) {

          await env.DB.prepare(`
            DELETE FROM blocked_listings
            WHERE product_id = ?
          `)
            .bind(productId)
            .run();

          return json({
            success: true,
            blocked: false
          });
        }

        let body = {};

        try {
          body = await request.json();
        } catch (_) {}

        await env.DB.prepare(`
          INSERT INTO blocked_listings
          (
            product_id,
            blocked_by,
            reason
          )
          VALUES (?, ?, ?)
        `)
          .bind(
            productId,
            admin.id,
            clean(body.reason)
          )
          .run();

        return json({
          success: true,
          blocked: true
        });
      }

      /* =====================================================
         ADMIN SETTINGS GET
      ===================================================== */

      if (
        path === "/api/admin/settings" &&
        request.method === "GET"
      ) {

        await requireAdmin(request, env);

        const result =
          await env.DB.prepare(`
            SELECT
              setting_key,
              setting_value
            FROM platform_settings
            ORDER BY setting_key
          `)
            .all();

        const settings = {};

        for (
          const row of
          result.results || []
        ) {
          settings[row.setting_key] =
            row.setting_value;
        }

        return json({
          success: true,
          settings
        });
      }

      /* =====================================================
         ADMIN SETTINGS PUT
      ===================================================== */

      if (
        path === "/api/admin/settings" &&
        request.method === "PUT"
      ) {

        await requireAdmin(request, env);

        const body =
          await request.json();

        const settings =
          body.settings || body;

        for (
          const [key, value]
          of Object.entries(settings)
        ) {

          await env.DB.prepare(`
            INSERT INTO platform_settings
            (
              setting_key,
              setting_value
            )
            VALUES (?, ?)

            ON CONFLICT(setting_key)
            DO UPDATE SET
              setting_value = excluded.setting_value
          `)
            .bind(
              String(key),
              String(value ?? "")
            )
            .run();
        }

        return json({
          success: true,
          settings
        });
      }

      /* =====================================================
         ADMIN FINANCE
      ===================================================== */

      if (
        path === "/api/admin/finance" &&
        request.method === "GET"
      ) {

        await requireAdmin(request, env);

        const completed =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(amount),0) AS total,
              COALESCE(SUM(platform_fee),0) AS fees,
              COALESCE(SUM(seller_earnings),0) AS earnings
            FROM transactions
            WHERE type = 'commission'
              AND status = 'completed'
          `)
            .first();

        const promotions =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(amount),0) AS total
            FROM transactions
            WHERE type = 'promotion'
          `)
            .first();

        const vip =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(amount),0) AS total
            FROM transactions
            WHERE type = 'vip'
          `)
            .first();

        return json({
          success: true,

          finance: {
            sales:
              Number(completed?.total || 0),

            commission:
              Number(completed?.fees || 0),

            seller_earnings:
              Number(completed?.earnings || 0),

            promotions:
              Number(promotions?.total || 0),

            vip:
              Number(vip?.total || 0)
          }
        });
      }

      /* =====================================================
         ADMIN SET TRANSACTION COMPLETED
      ===================================================== */

      if (
        /^\/api\/admin\/transactions\/[0-9]+$/.test(path) &&
        request.method === "PUT"
      ) {

        await requireAdmin(request, env);

        const id =
          Number(path.split("/").pop());

        const body =
          await request.json();

        const status =
          clean(body.status || "completed");

        await env.DB.prepare(`
          UPDATE transactions
          SET status = ?
          WHERE id = ?
        `)
          .bind(status, id)
          .run();

        return json({
          success: true,
          status
        });
      }

      /* =====================================================
         ADMIN SETUP
      ===================================================== */

      if (
        path === "/api/admin/setup" &&
        request.method === "POST"
      ) {

        if (!env.ADMIN_SETUP_KEY) {
          return json({
            success: false,
            error:
              "ADMIN_SETUP_KEY nuk është vendosur në Cloudflare."
          }, 500);
        }

        const body =
          await request.json();

        if (
          body.setupKey !==
          env.ADMIN_SETUP_KEY
        ) {
          return json({
            success: false,
            error: "Setup key e gabuar."
          }, 401);
        }

        const name =
          clean(
            body.name ||
            "SHIT.BLEJ Admin"
          );

        const email =
          clean(
            body.email ||
            "admin@shitblej.al"
          ).toLowerCase();

        const password =
          String(body.password || "");

        if (password.length < 4) {
          return json({
            success: false,
            error:
              "Password shumë i shkurtër."
          }, 400);
        }

        const { hash, salt } =
          await passwordHash(password);

        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM auth_accounts
            WHERE LOWER(email) = ?
            LIMIT 1
          `)
            .bind(email)
            .first();

        if (existing) {

          await env.DB.prepare(`
            UPDATE auth_accounts
            SET
              name = ?,
              password_hash = ?,
              password_salt = ?,
              role = 'admin'
            WHERE id = ?
          `)
            .bind(
              name,
              hash,
              salt,
              existing.id
            )
            .run();

          return json({
            success: true,
            message: "Admini u përditësua."
          });
        }

        await env.DB.prepare(`
          INSERT INTO auth_accounts
          (
            name,
            email,
            phone,
            identifier,
            password_hash,
            password_salt,
            role
          )
          VALUES
          (?, ?, '', ?, ?, ?, 'admin')
        `)
          .bind(
            name,
            email,
            email,
            hash,
            salt
          )
          .run();

        return json({
          success: true,
          message: "Admini u krijua."
        });
      }

      /* =====================================================
         STATIC FILES
      ===================================================== */

      if (env.ASSETS) {

        if (
          path === "/" ||
          path === ""
        ) {

          const req =
            new Request(
              new URL(
                "/index.html",
                url.origin
              ),
              request
            );

          return env.ASSETS.fetch(req);
        }

        return env.ASSETS.fetch(request);
      }

      return new Response(
        "SHIT.BLEJ PRO API ONLINE",
        {
          status: 404,
          headers: {
            "Content-Type":
              "text/plain; charset=UTF-8"
          }
        }
      );

    } catch (error) {

      console.error(
        "SHIT.BLEJ ERROR",
        error
      );

      if (
        error.message === "UNAUTHORIZED"
      ) {
        return json({
          success: false,
          error: "Duhet të identifikoheni."
        }, 401);
      }

      if (
        error.message === "FORBIDDEN"
      ) {
        return json({
          success: false,
          error: "Nuk keni akses."
        }, 403);
      }

      return json({
        success: false,
        error:
          error.message ||
          "Gabim serveri."
      }, 500);
    }
  }
};
