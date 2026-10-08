const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=UTF-8"
};

/* =========================================================
   RESPONSE / HELPERS
========================================================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS
  });
}

function getToken(request) {
  const auth = request.headers.get("Authorization") || "";
  return auth.startsWith("Bearer ")
    ? auth.slice(7).trim()
    : null;
}

function clean(v) {
  return String(v ?? "").trim();
}

function num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
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

function orderCode() {
  const date = new Date()
    .toISOString()
    .slice(0, 10)
    .replaceAll("-", "");

  return `SABI-${date}-${randomToken(4).toUpperCase()}`;
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
      value.slice(i * 2, i * 2 + 2),
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
   SAFE DB HELPERS
========================================================= */

async function column(env, table, name, definition) {
  try {
    await env.DB.prepare(
      `ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`
    ).run();
  } catch (_) {
    // Exists already.
  }
}

async function setupDatabase(env) {

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

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS saved_listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, product_id)
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS blocked_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      blocked_by INTEGER NOT NULL,
      reason TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS blocked_listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      blocked_by INTEGER NOT NULL,
      reason TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS marketplace_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT UNIQUE NOT NULL,
      setting_value TEXT DEFAULT ''
    )
  `).run();

  /* PRODUCTS — vetëm shtojmë kolona që mungojnë */

  await column(env, "products", "name", "TEXT DEFAULT ''");
  await column(env, "products", "image", "TEXT DEFAULT ''");
  await column(env, "products", "seller", "TEXT DEFAULT ''");
  await column(env, "products", "sellerName", "TEXT DEFAULT ''");
  await column(env, "products", "sellerPhone", "TEXT DEFAULT ''");
  await column(env, "products", "sellerEmail", "TEXT DEFAULT ''");
  await column(env, "products", "city", "TEXT DEFAULT ''");
  await column(env, "products", "condition", "TEXT DEFAULT ''");
  await column(env, "products", "phone", "TEXT DEFAULT ''");
  await column(env, "products", "negotiable", "INTEGER DEFAULT 0");

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

  await column(env, "orders", "product_id", "INTEGER");
  await column(env, "orders", "buyer_id", "INTEGER");
  await column(env, "orders", "quantity", "INTEGER DEFAULT 1");
  await column(env, "orders", "total_price", "REAL DEFAULT 0");
  await column(env, "orders", "status", "TEXT DEFAULT 'pending'");
  await column(env, "orders", "customer_name", "TEXT DEFAULT ''");
  await column(env, "orders", "customer_phone", "TEXT DEFAULT ''");
  await column(env, "orders", "customer_city", "TEXT DEFAULT ''");
  await column(env, "orders", "customer_address", "TEXT DEFAULT ''");
  await column(
    env,
    "orders",
    "payment_method",
    "TEXT DEFAULT 'cash_on_delivery'"
  );
  await column(env, "orders", "order_code", "TEXT DEFAULT ''");

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
      type TEXT DEFAULT '',
      amount REAL DEFAULT 0,
      reference_id INTEGER,
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

  /* Default settings */

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
   AUTH
========================================================= */

async function currentUser(request, env) {
  const token = getToken(request);

  if (!token) return null;

  return await env.DB.prepare(`
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
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);

  if (!user) throw new Error("UNAUTHORIZED");

  return user;
}

async function requireAdmin(request, env) {
  const user = await requireUser(request, env);

  if (!["admin", "owner"].includes(user.role)) {
    throw new Error("FORBIDDEN");
  }

  return user;
}

/* =========================================================
   SETTINGS
========================================================= */

async function getSetting(env, key, fallback) {
  const row = await env.DB.prepare(`
    SELECT setting_value
    FROM platform_settings
    WHERE setting_key = ?
    LIMIT 1
  `)
    .bind(key)
    .first();

  return row?.setting_value ?? fallback;
}

async function commissionRate(env) {
  return num(
    await getSetting(env, "commission_rate", "5"),
    5
  );
}

/* =========================================================
   PRODUCTS
========================================================= */

function formatProduct(p) {
  if (!p) return null;

  return {
    ...p,

    id: num(p.id),

    title:
      p.title ||
      p.name ||
      "",

    name:
      p.name ||
      p.title ||
      "",

    price:
      num(p.price),

    stock:
      num(p.stock),

    seller_id:
      p.seller_id == null
        ? null
        : num(p.seller_id),

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
      p.phone ||
      p.seller_account_phone ||
      "",

    sellerEmail:
      p.sellerEmail ||
      p.seller_account_email ||
      "",

    image:
      p.image ||
      p.image_url ||
      "",

    image_url:
      p.image_url ||
      p.image ||
      "",

    city:
      p.city ||
      "",

    condition:
      p.condition ||
      "",

    phone:
      p.phone ||
      "",

    negotiable:
      num(p.negotiable),

    promoted:
      Boolean(
        num(p.promoted) ||
        num(p.is_promoted)
      )
  };
}

async function getProduct(env, id) {
  const row = await env.DB.prepare(`
    SELECT
      p.*,
      a.name AS seller_account_name,
      a.email AS seller_account_email,
      a.phone AS seller_account_phone,

      CASE
        WHEN EXISTS (
          SELECT 1
          FROM promotions pr
          WHERE pr.product_id = p.id
            AND pr.active = 1
            AND datetime(pr.expires_at) > datetime('now')
        )
        THEN 1
        ELSE 0
      END AS promoted

    FROM products p

    LEFT JOIN auth_accounts a
      ON a.id = p.seller_id

    WHERE p.id = ?
    LIMIT 1
  `)
    .bind(id)
    .first();

  return formatProduct(row);
}

/* =========================================================
   ORDERS
========================================================= */

function formatOrder(o) {
  return {
    ...o,

    id: num(o.id),
    product_id:
      o.product_id == null
        ? null
        : num(o.product_id),

    buyer_id:
      o.buyer_id == null
        ? null
        : num(o.buyer_id),

    seller_id:
      o.seller_id == null
        ? null
        : num(o.seller_id),

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
      o.status ||
      "pending"
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

      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: CORS
        });
      }

      await setupDatabase(env);

      /* =====================================================
         API HEALTH
      ===================================================== */

      if (path === "/api" || path === "/api/") {
        return json({
          success: true,
          app: "SHIT.BLEJ PRO",
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

        const role =
          clean(body.role).toLowerCase() === "seller"
            ? "seller"
            : "customer";

        if (!name)
          return json({
            success: false,
            error: "Vendos emrin."
          }, 400);

        if (!email || !email.includes("@"))
          return json({
            success: false,
            error: "Email nuk është i vlefshëm."
          }, 400);

        if (password.length < 4)
          return json({
            success: false,
            error: "Password duhet të ketë të paktën 4 karaktere."
          }, 400);

        const existing = await env.DB.prepare(`
          SELECT id
          FROM auth_accounts
          WHERE LOWER(email) = ?
             OR LOWER(identifier) = ?
          LIMIT 1
        `)
          .bind(email, email)
          .first();

        if (existing)
          return json({
            success: false,
            error: "Ky email ekziston."
          }, 409);

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

        const account =
          await env.DB.prepare(`
            SELECT *
            FROM auth_accounts
            WHERE LOWER(email) = ?
               OR LOWER(identifier) = ?
            LIMIT 1
          `)
            .bind(identifier, identifier)
            .first();

        if (!account)
          return json({
            success: false,
            error: "Email ose password i gabuar."
          }, 401);

        const blocked =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_users
            WHERE user_id = ?
            LIMIT 1
          `)
            .bind(account.id)
            .first();

        if (blocked)
          return json({
            success: false,
            error: "Kjo llogari është bllokuar."
          }, 403);

        const { hash } =
          await passwordHash(
            password,
            account.password_salt
          );

        if (hash !== account.password_hash)
          return json({
            success: false,
            error: "Email ose password i gabuar."
          }, 401);

        const token = randomToken();

        await env.DB.prepare(`
          INSERT INTO sessions
          (user_id, token)
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

        if (!user)
          return json({
            success: false,
            error: "Nuk jeni i loguar."
          }, 401);

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

        return json({ success: true });
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

            CASE
              WHEN EXISTS (
                SELECT 1
                FROM promotions pr
                WHERE pr.product_id = p.id
                  AND pr.active = 1
                  AND datetime(pr.expires_at) > datetime('now')
              )
              THEN 1
              ELSE 0
            END AS promoted

          FROM products p

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

          params.push(s, s, s, s, s);
        }

        if (category) {
          sql += `
            AND LOWER(COALESCE(p.category,'')) =
                LOWER(?)
          `;

          params.push(category);
        }

        sql += `
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
         PRODUCTS LIST
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

            CASE
              WHEN EXISTS (
                SELECT 1
                FROM promotions pr
                WHERE pr.product_id = p.id
                  AND pr.active = 1
                  AND datetime(pr.expires_at) > datetime('now')
              )
              THEN 1
              ELSE 0
            END AS promoted

          FROM products p

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
         SINGLE PRODUCT
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+$/.test(path) &&
        request.method === "GET"
      ) {

        const id =
          num(path.split("/").pop());

        const blocked =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_listings
            WHERE product_id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (blocked)
          return json({
            success: false,
            error: "Ky produkt nuk është i disponueshëm."
          }, 404);

        const product =
          await getProduct(env, id);

        if (!product)
          return json({
            success: false,
            error: "Produkti nuk u gjet."
          }, 404);

        return json({
          success: true,
          product
        });
      }

      /* =====================================================
         SAVED
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
         SAVE / UNSAVE
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+\/save$/.test(path) &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(request, env);

        const id =
          num(path.split("/")[3]);

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

        if (!["seller", "admin", "owner"].includes(user.role)) {
          return json({
            success: false,
            error: "Vetëm shitësit mund të publikojnë produkte."
          }, 403);
        }

        const body =
          await request.json();

        const title =
          clean(body.title || body.name);

        const description =
          clean(body.description);

        const price =
          num(body.price);

        const image =
          clean(body.image_url || body.image);

        const category =
          clean(body.category || "Të tjera");

        const stock =
          Math.max(0, Math.floor(num(body.stock, 1)));

        const city =
          clean(body.city);

        const condition =
          clean(body.condition);

        const phone =
          clean(body.phone || user.phone);

        const negotiable =
          body.negotiable ? 1 : 0;

        if (!title)
          return json({
            success: false,
            error: "Titulli mungon."
          }, 400);

        if (price < 0)
          return json({
            success: false,
            error: "Çmimi nuk është i vlefshëm."
          }, 400);

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

        return json({
          success: true,
          product:
            await getProduct(
              env,
              result.meta.last_row_id
            )
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
          num(path.split("/").pop());

        const existing =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (!existing)
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);

        if (
          !["admin", "owner"].includes(user.role) &&
          num(existing.seller_id) !== num(user.id)
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
            ? num(existing.negotiable)
            : body.negotiable ? 1 : 0;

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
            await getProduct(env, id)
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
          num(path.split("/").pop());

        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (!product)
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);

        if (
          !["admin", "owner"].includes(user.role) &&
          num(product.seller_id) !== num(user.id)
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

        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(productId)
            .first();

        if (!product)
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);

        if (
          num(product.seller_id) ===
          num(user.id)
        ) {
          return json({
            success: false,
            error: "Nuk mund të blesh produktin tënd."
          }, 400);
        }

        if (
          num(product.stock) > 0 &&
          quantity > num(product.stock)
        ) {
          return json({
            success: false,
            error: `Ka vetëm ${product.stock} copë në stok.`
          }, 400);
        }

        const total =
          num(product.price) *
          quantity;

        const code =
          orderCode();

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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          `)
            .bind(
              productId,
              user.id,
              quantity,
              total,
              "pending",
              clean(body.customer_name || user.name),
              clean(body.customer_phone || user.phone),
              clean(body.customer_city),
              clean(body.customer_address),
              clean(body.payment_method || "cash_on_delivery"),
              code
            )
            .run();

        if (num(product.stock) > 0) {
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
         ORDERS LIST
      ===================================================== */

      if (
        path === "/api/orders" &&
        request.method === "GET"
      ) {

        const user =
          await requireUser(request, env);

        let result;

        if (
          ["admin", "owner"].includes(user.role)
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
                a.phone AS buyer_account_phone

              FROM orders o

              LEFT JOIN products p
                ON p.id = o.product_id

              LEFT JOIN auth_accounts a
                ON a.id = o.buyer_id

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
                a.phone AS buyer_account_phone

              FROM orders o

              LEFT JOIN products p
                ON p.id = o.product_id

              LEFT JOIN auth_accounts a
                ON a.id = o.buyer_id

              WHERE
                o.buyer_id = ?
                OR p.seller_id = ?

              ORDER BY o.id DESC
            `)
              .bind(user.id, user.id)
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
         UPDATE ORDER / COMMISSION
      ===================================================== */

      if (
        /^\/api\/orders\/[0-9]+$/.test(path) &&
        request.method === "PUT"
      ) {

        const user =
          await requireUser(request, env);

        const id =
          num(path.split("/").pop());

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

        if (!order)
          return json({
            success: false,
            error: "Porosia nuk ekziston."
          }, 404);

        const body =
          await request.json();

        const status =
          clean(body.status).toLowerCase();

        const allowed = [
          "pending",
          "confirmed",
          "shipped",
          "delivered",
          "completed",
          "cancelled"
        ];

        if (!allowed.includes(status))
          return json({
            success: false,
            error: "Status i pavlefshëm."
          }, 400);

        const isAdmin =
          ["admin", "owner"].includes(user.role);

        const isSeller =
          num(order.seller_id) === num(user.id);

        const isBuyer =
          num(order.buyer_id) === num(user.id);

        if (!isAdmin && !isSeller && !isBuyer)
          return json({
            success: false,
            error: "Nuk keni akses."
          }, 403);

        if (
          isBuyer &&
          !isSeller &&
          !isAdmin &&
          status !== "cancelled"
        ) {
          return json({
            success: false,
            error: "Blerësi mund vetëm ta anulojë porosinë."
          }, 403);
        }

        const previous =
          order.status;

        /* CANCELLED */

        if (
          status === "cancelled" &&
          previous !== "cancelled"
        ) {

          await env.DB.prepare(`
            UPDATE orders
            SET status = ?
            WHERE id = ?
          `)
            .bind(status, id)
            .run();

          /* kthim i stokut */

          const p =
            await env.DB.prepare(`
              SELECT product_id, quantity
              FROM orders
              WHERE id = ?
            `)
              .bind(id)
              .first();

          if (p?.product_id) {
            await env.DB.prepare(`
              UPDATE products
              SET stock = stock + ?
              WHERE id = ?
            `)
              .bind(
                num(p.quantity, 1),
                p.product_id
              )
              .run();
          }

          return json({
            success: true,
            status
          });
        }

        /* COMPLETED / DELIVERED */

        if (
          status === "delivered" ||
          status === "completed"
        ) {

          const rate =
            await commissionRate(env);

          const fee =
            num(order.total_price) *
            rate /
            100;

          const earnings =
            num(order.total_price) -
            fee;

          /* columns may not exist in old DB */
          await column(
            env,
            "orders",
            "platform_fee",
            "REAL DEFAULT 0"
          );

          await column(
            env,
            "orders",
            "seller_earnings",
            "REAL DEFAULT 0"
          );

          await env.DB.prepare(`
            UPDATE orders
            SET
              status = ?,
              platform_fee = ?,
              seller_earnings = ?
            WHERE id = ?
          `)
            .bind(
              status,
              fee,
              earnings,
              id
            )
            .run();

          if (status === "completed") {

            await env.DB.prepare(`
              INSERT INTO transactions
              (
                user_id,
                type,
                amount,
                reference_id,
                status,
                description
              )
              VALUES (?, ?, ?, ?, ?, ?)
            `)
              .bind(
                order.seller_id,
                "commission",
                fee,
                id,
                "completed",
                `Komision 5% për porosinë ${order.order_code || id}`
              )
              .run();
          }

          return json({
            success: true,
            status,
            platform_fee: fee,
            seller_earnings: earnings
          });
        }

        await env.DB.prepare(`
          UPDATE orders
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
         PROMOTION CREATE
      ===================================================== */

      if (
        path === "/api/promotions" &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(request, env);

        if (
          !["seller", "admin", "owner"].includes(user.role)
        ) {
          return json({
            success: false,
            error: "Nuk keni akses."
          }, 403);
        }

        const body =
          await request.json();

        const productId =
          num(body.product_id || body.productId);

        const plan =
          clean(body.plan || "1_day");

        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(productId)
            .first();

        if (!product)
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);

        if (
          !["admin", "owner"].includes(user.role) &&
          num(product.seller_id) !== num(user.id)
        ) {
          return json({
            success: false,
            error: "Ky produkt nuk është i yti."
          }, 403);
        }

        const plans = {
          "1_day": {
            price: num(
              await getSetting(
                env,
                "promo_1_day",
                "100"
              )
            ),
            days: 1,
            type: "promoted"
          },

          "7_day": {
            price: num(
              await getSetting(
                env,
                "promo_7_day",
                "300"
              )
            ),
            days: 7,
            type: "promoted"
          },

          "30_day": {
            price: num(
              await getSetting(
                env,
                "promo_30_day",
                "700"
              )
            ),
            days: 30,
            type: "promoted"
          },

          "vip_7_day": {
            price: num(
              await getSetting(
                env,
                "vip_7_day",
                "500"
              )
            ),
            days: 7,
            type: "vip"
          }
        };

        const selected =
          plans[plan];

        if (!selected)
          return json({
            success: false,
            error: "Paketa nuk ekziston."
          }, 400);

        const starts =
          new Date();

        const expires =
          new Date(
            starts.getTime() +
            selected.days *
            24 *
            60 *
            60 *
            1000
          );

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
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
          `)
            .bind(
              productId,
              product.seller_id,
              selected.type,
              plan,
              selected.price,
              starts.toISOString(),
              expires.toISOString()
            )
            .run();

        await env.DB.prepare(`
          INSERT INTO transactions
          (
            user_id,
            type,
            amount,
            reference_id,
            status,
            description
          )
          VALUES (?, ?, ?, ?, ?, ?)
        `)
          .bind(
            user.id,
            selected.type,
            selected.price,
            result.meta.last_row_id,
            "pending",
            `Promovim ${plan} për produktin #${productId}`
          )
          .run();

        return json({
          success: true,
          promotion: {
            id: result.meta.last_row_id,
            product_id: productId,
            plan,
            type: selected.type,
            price: selected.price,
            expires_at: expires.toISOString()
          },

          /*
            Për momentin statusi është pending.
            Kur të lidhim pagesat reale,
            ky bëhet completed pas pagesës.
          */

          payment_status: "pending"
        }, 201);
      }

      /* =====================================================
         PROMOTIONS FOR PRODUCT
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+\/promotions$/.test(path) &&
        request.method === "GET"
      ) {

        const productId =
          num(path.split("/")[3]);

        const result =
          await env.DB.prepare(`
            SELECT *
            FROM promotions
            WHERE product_id = ?
            ORDER BY id DESC
          `)
            .bind(productId)
            .all();

        return json({
          success: true,
          promotions:
            result.results || []
        });
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
            SELECT COUNT(*) count
            FROM auth_accounts
          `).first();

        const products =
          await env.DB.prepare(`
            SELECT COUNT(*) count
            FROM products
          `).first();

        const orders =
          await env.DB.prepare(`
            SELECT COUNT(*) count
            FROM orders
          `).first();

        const sellers =
          await env.DB.prepare(`
            SELECT COUNT(*) count
            FROM auth_accounts
            WHERE role = 'seller'
          `).first();

        const sales =
          await env.DB.prepare(`
            SELECT COALESCE(SUM(total_price),0) total
            FROM orders
            WHERE status IN ('delivered','completed')
          `).first();

        const commission =
          await env.DB.prepare(`
            SELECT COALESCE(SUM(platform_fee),0) total
            FROM orders
            WHERE status = 'completed'
          `).first();

        return json({
          success: true,

          stats: {
            users: num(users?.count),
            products: num(products?.count),
            orders: num(orders?.count),
            sellers: num(sellers?.count),
            sales: num(sales?.total),
            commission: num(commission?.total)
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
              END blocked

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
        ["POST", "PUT"].includes(request.method)
      ) {

        const admin =
          await requireAdmin(request, env);

        const userId =
          num(path.split("/")[3]);

        if (userId === num(admin.id))
          return json({
            success: false,
            error: "Nuk mund të bllokosh veten."
          }, 400);

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

        await env.DB.prepare(`
          INSERT INTO blocked_users
          (user_id, blocked_by, reason)
          VALUES (?, ?, ?)
        `)
          .bind(
            userId,
            admin.id,
            "Bllokuar nga administratori"
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
        ["POST", "PUT"].includes(request.method)
      ) {

        const admin =
          await requireAdmin(request, env);

        const productId =
          num(path.split("/")[3]);

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

        await env.DB.prepare(`
          INSERT INTO blocked_listings
          (product_id, blocked_by, reason)
          VALUES (?, ?, ?)
        `)
          .bind(
            productId,
            admin.id,
            "Bllokuar nga administratori"
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

        for (const row of result.results || []) {
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
          body.settings ||
          body;

        for (
          const [key, value]
          of Object.entries(settings)
        ) {

          await env.DB.prepare(`
            INSERT INTO platform_settings
            (setting_key, setting_value)
            VALUES (?, ?)

            ON CONFLICT(setting_key)
            DO UPDATE SET
              setting_value =
                excluded.setting_value
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

        const sales =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(total_price),0) total
            FROM orders
            WHERE status IN ('delivered','completed')
          `).first();

        const commission =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(platform_fee),0) total
            FROM orders
            WHERE status = 'completed'
          `).first();

        const sellerEarnings =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(seller_earnings),0) total
            FROM orders
            WHERE status = 'completed'
          `).first();

        const promotions =
          await env.DB.prepare(`
            SELECT
              COALESCE(SUM(amount),0) total
            FROM transactions
            WHERE type IN ('promoted','vip')
              AND status IN ('completed','pending')
          `).first();

        return json({
          success: true,
          finance: {
            sales: num(sales?.total),
            commission: num(commission?.total),
            seller_earnings: num(sellerEarnings?.total),
            promotion_revenue: num(promotions?.total)
          }
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
            error: "ADMIN_SETUP_KEY nuk është vendosur."
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
            error: "Password shumë i shkurtër."
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

        } else {

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
            VALUES (?, ?, '', ?, ?, ?, 'admin')
          `)
            .bind(
              name,
              email,
              email,
              hash,
              salt
            )
            .run();
        }

        return json({
          success: true,
          message: "Admini u krijua/përditësua."
        });
      }

      /* =====================================================
         STATIC FILES
      ===================================================== */

      if (env.ASSETS) {

        if (path === "/" || path === "") {

          return env.ASSETS.fetch(
            new Request(
              new URL(
                "/index.html",
                url.origin
              ),
              request
            )
          );
        }

        return env.ASSETS.fetch(request);
      }

      return new Response(
        "SHIT.BLEJ PRO API is online.",
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
        "SHIT.BLEJ ERROR:",
        error
      );

      if (error.message === "UNAUTHORIZED") {
        return json({
          success: false,
          error: "Duhet të identifikoheni."
        }, 401);
      }

      if (error.message === "FORBIDDEN") {
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
