const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400"
};

const CATEGORY_MAP = {
  "Makina": "Makina",
  "Prona": "Prona",
  "Elektronikë": "Elektronikë",
  "Telefona": "Telefona",
  "Kompjuterë": "Kompjuterë",
  "Rroba": "Rroba",
  "Këpucë": "Këpucë",
  "Shtëpi & Mobilje": "Shtëpi & Mobilje",
  "Punë": "Punë",
  "Shërbime": "Shërbime",
  "Sport": "Sport",
  "Vegla & Makineri": "Vegla & Makineri",
  "Të tjera": "Të tjera"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

function text(data, status = 200) {
  return new Response(data, {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "text/plain; charset=utf-8"
    }
  });
}

function unauthorized(message = "Nuk jeni i autorizuar") {
  return json({ success: false, error: message }, 401);
}

function forbidden(message = "Nuk keni të drejtë") {
  return json({ success: false, error: message }, 403);
}

function badRequest(message = "Kërkesë e pavlefshme") {
  return json({ success: false, error: message }, 400);
}

function serverError(message = "Gabim serveri") {
  return json({ success: false, error: message }, 500);
}

function randomString(length = 48) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  let result = "";

  for (let i = 0; i < length; i++) {
    result += chars[bytes[i] % chars.length];
  }

  return result;
}

function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

async function hashPassword(password, saltHex = null) {
  const salt = saltHex
    ? hexToBytes(saltHex)
    : crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
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
    hash: bytesToHex(new Uint8Array(bits)),
    salt: bytesToHex(salt)
  };
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return bytes;
}

function normalizeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name || "",
    email: user.email || "",
    phone: user.phone || "",
    role: user.role || "customer"
  };
}

async function ensureDatabase(env) {
  /*
    Këto janë CREATE IF NOT EXISTS.
    Nuk fshijnë tabelat ose të dhënat ekzistuese.
  */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS auth_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT DEFAULT '',
      email TEXT,
      phone TEXT DEFAULT '',
      identifier TEXT,
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
      reason TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS blocked_listings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      blocked_by INTEGER NOT NULL,
      reason TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS marketplace_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT NOT NULL UNIQUE,
      setting_value TEXT
    )
  `).run();

  /*
    Shtojmë kolonat vetëm nëse nuk ekzistojnë.
    SQLite/D1 nuk ka IF NOT EXISTS për ALTER COLUMN,
    prandaj përdorim try/catch.
  */

  try {
    await env.DB.prepare(
      `ALTER TABLE products ADD COLUMN city TEXT DEFAULT ''`
    ).run();
  } catch {}

  try {
    await env.DB.prepare(
      `ALTER TABLE products ADD COLUMN condition TEXT DEFAULT ''`
    ).run();
  } catch {}

  try {
    await env.DB.prepare(
      `ALTER TABLE products ADD COLUMN phone TEXT DEFAULT ''`
    ).run();
  } catch {}

  try {
    await env.DB.prepare(
      `ALTER TABLE products ADD COLUMN negotiable INTEGER DEFAULT 0`
    ).run();
  } catch {}
}

async function getAuthUser(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return null;
  }

  const result = await env.DB.prepare(`
    SELECT
      a.id,
      a.name,
      a.email,
      a.phone,
      a.role
    FROM sessions s
    JOIN auth_accounts a ON a.id = s.user_id
    WHERE s.token = ?
    LIMIT 1
  `)
    .bind(token)
    .first();

  return normalizeUser(result);
}

async function requireAuth(request, env) {
  const user = await getAuthUser(request, env);

  if (!user) {
    throw new Error("UNAUTHORIZED");
  }

  return user;
}

async function requireAdmin(request, env) {
  const user = await requireAuth(request, env);

  if (user.role !== "admin") {
    throw new Error("FORBIDDEN");
  }

  return user;
}

function productResponse(product) {
  if (!product) return null;

  return {
    ...product,

    id: Number(product.id),

    price:
      product.price === null || product.price === undefined
        ? 0
        : Number(product.price),

    stock:
      product.stock === null || product.stock === undefined
        ? 0
        : Number(product.stock),

    seller_id:
      product.seller_id === null || product.seller_id === undefined
        ? null
        : Number(product.seller_id),

    negotiable: Number(product.negotiable || 0),

    image: product.image || product.image_url || "",
    image_url: product.image_url || product.image || "",

    category:
      CATEGORY_MAP[product.category] ||
      product.category ||
      "Të tjera"
  };
}

async function getProduct(env, id) {
  const product = await env.DB.prepare(`
    SELECT
      p.*,
      COALESCE(
        p.seller,
        a.name
      ) AS seller_name,
      a.email AS seller_email,
      a.phone AS seller_account_phone
    FROM products p
    LEFT JOIN auth_accounts a
      ON a.id = p.seller_id
    WHERE p.id = ?
    LIMIT 1
  `)
    .bind(id)
    .first();

  if (!product) {
    return null;
  }

  return productResponse({
    ...product,
    sellerName:
      product.sellerName ||
      product.seller_name ||
      product.seller ||
      "",
    sellerPhone:
      product.sellerPhone ||
      product.seller_account_phone ||
      product.phone ||
      "",
    sellerEmail:
      product.sellerEmail ||
      product.seller_email ||
      ""
  });
}

async function createOrderCode() {
  const now = Date.now().toString(36).toUpperCase();
  const random = randomString(5).toUpperCase();

  return `SB-${now}-${random}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    try {
      await ensureDatabase(env);

      /*
      ============================================================
      HEALTH
      ============================================================
      */

      if (path === "/api" || path === "/api/") {
        return json({
          success: true,
          app: "SHIT.BLEJ",
          message: "API OK"
        });
      }

      /*
      ============================================================
      AUTH - REGISTER
      ============================================================
      */

      if (
        path === "/api/auth/register" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const name = String(body.name || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const phone = String(body.phone || "").trim();
        const identifier = String(
          body.identifier || email
        ).trim().toLowerCase();

        const password = String(body.password || "");
        const role =
          body.role === "seller"
            ? "seller"
            : "customer";

        if (!name) {
          return badRequest("Vendosni emrin.");
        }

        if (!email) {
          return badRequest("Vendosni email-in.");
        }

        if (!password || password.length < 4) {
          return badRequest(
            "Fjalëkalimi duhet të ketë të paktën 4 karaktere."
          );
        }

        const existing = await env.DB.prepare(`
          SELECT id
          FROM auth_accounts
          WHERE LOWER(email) = ?
             OR LOWER(identifier) = ?
          LIMIT 1
        `)
          .bind(email, identifier)
          .first();

        if (existing) {
          return json(
            {
              success: false,
              error: "Ky email/username ekziston."
            },
            409
          );
        }

        const { hash, salt } = await hashPassword(password);

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
            identifier,
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

      /*
      ============================================================
      AUTH - LOGIN
      ============================================================
      */

      if (
        path === "/api/auth/login" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const identifier = String(
          body.identifier ||
          body.email ||
          body.username ||
          ""
        )
          .trim()
          .toLowerCase();

        const password = String(body.password || "");

        if (!identifier || !password) {
          return badRequest(
            "Vendosni username/email dhe password."
          );
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
          return unauthorized(
            "Email/username ose password i gabuar."
          );
        }

        const { hash } = await hashPassword(
          password,
          account.password_salt
        );

        if (hash !== account.password_hash) {
          return unauthorized(
            "Email/username ose password i gabuar."
          );
        }

        /*
          Nëse frontend dërgon role,
          kontrollojmë që të përputhet.
        */

        if (
          body.role &&
          body.role !== account.role
        ) {
          return unauthorized(
            "Roli i zgjedhur nuk përputhet me llogarinë."
          );
        }

        const token = randomString(64);

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

        const user = normalizeUser(account);

        return json({
          success: true,
          token,
          user
        });
      }

      /*
      ============================================================
      AUTH - ME
      ============================================================
      */

      if (
        path === "/api/auth/me" &&
        request.method === "GET"
      ) {
        const user = await getAuthUser(request, env);

        if (!user) {
          return unauthorized();
        }

        return json({
          success: true,
          user
        });
      }

      /*
      ============================================================
      AUTH - LOGOUT
      ============================================================
      */

      if (
        path === "/api/auth/logout" &&
        request.method === "POST"
      ) {
        const token = getBearerToken(request);

        if (token) {
          await env.DB.prepare(`
            DELETE FROM sessions
            WHERE token = ?
          `)
            .bind(token)
            .run();
        }

        return json({
          success: true,
          message: "U çkyçët."
        });
      }

      /*
      ============================================================
      PRODUCTS - SEARCH
      ============================================================
      */

      if (
        path === "/api/products/search" &&
        request.method === "GET"
      ) {
        const q =
          url.searchParams.get("q")?.trim() || "";

        const category =
          url.searchParams.get("category")?.trim() || "";

        const city =
          url.searchParams.get("city")?.trim() || "";

        const condition =
          url.searchParams.get("condition")?.trim() || "";

        const minRaw =
          url.searchParams.get("min");

        const maxRaw =
          url.searchParams.get("max");

        const sort =
          url.searchParams.get("sort") || "newest";

        let sql = `
          SELECT *
          FROM products
          WHERE 1 = 1
        `;

        const params = [];

        if (q) {
          sql += `
            AND (
              LOWER(COALESCE(name, '')) LIKE ?
              OR LOWER(COALESCE(title, '')) LIKE ?
              OR LOWER(COALESCE(description, '')) LIKE ?
            )
          `;

          const search = `%${q.toLowerCase()}%`;

          params.push(search, search, search);
        }

        if (category) {
          sql += `
            AND LOWER(COALESCE(category, '')) = LOWER(?)
          `;

          params.push(category);
        }

        if (city) {
          sql += `
            AND LOWER(COALESCE(city, '')) LIKE LOWER(?)
          `;

          params.push(`%${city}%`);
        }

        if (condition) {
          sql += `
            AND LOWER(COALESCE(condition, '')) = LOWER(?)
          `;

          params.push(condition);
        }

        if (
          minRaw !== null &&
          minRaw !== "" &&
          !Number.isNaN(Number(minRaw))
        ) {
          sql += ` AND CAST(price AS REAL) >= ?`;
          params.push(Number(minRaw));
        }

        if (
          maxRaw !== null &&
          maxRaw !== "" &&
          !Number.isNaN(Number(maxRaw))
        ) {
          sql += ` AND CAST(price AS REAL) <= ?`;
          params.push(Number(maxRaw));
        }

        if (sort === "price_asc") {
          sql += ` ORDER BY CAST(price AS REAL) ASC`;
        } else if (sort === "price_desc") {
          sql += ` ORDER BY CAST(price AS REAL) DESC`;
        } else {
          sql += `
            ORDER BY
              datetime(created_at) DESC,
              id DESC
          `;
        }

        sql += ` LIMIT 200`;

        const result = await env.DB
          .prepare(sql)
          .bind(...params)
          .all();

        return json({
          success: true,
          products: (result.results || []).map(productResponse)
        });
      }

      /*
      ============================================================
      PRODUCTS - SAVED
      IMPORTANT: before /api/products/:id
      ============================================================
      */

      if (
        path === "/api/products/saved" &&
        request.method === "GET"
      ) {
        let user;

        try {
          user = await requireAuth(request, env);
        } catch (error) {
          if (error.message === "UNAUTHORIZED") {
            return unauthorized();
          }

          throw error;
        }

        const result = await env.DB.prepare(`
          SELECT
            p.*
          FROM saved_listings s
          JOIN products p
            ON p.id = s.product_id
          WHERE s.user_id = ?
          ORDER BY s.id DESC
        `)
          .bind(user.id)
          .all();

        return json({
          success: true,
          products: (result.results || []).map(productResponse)
        });
      }

      /*
      ============================================================
      PRODUCTS - LIST
      ============================================================
      */

      if (
        path === "/api/products" &&
        request.method === "GET"
      ) {
        const category =
          url.searchParams.get("category")?.trim() || "";

        const sellerId =
          url.searchParams.get("seller_id");

        let sql = `
          SELECT *
          FROM products
          WHERE 1 = 1
        `;

        const params = [];

        if (category) {
          sql += `
            AND LOWER(COALESCE(category, '')) = LOWER(?)
          `;

          params.push(category);
        }

        if (
          sellerId !== null &&
          sellerId !== "" &&
          !Number.isNaN(Number(sellerId))
        ) {
          sql += ` AND seller_id = ?`;
          params.push(Number(sellerId));
        }

        sql += `
          ORDER BY
            datetime(created_at) DESC,
            id DESC
          LIMIT 500
        `;

        const result = await env.DB
          .prepare(sql)
          .bind(...params)
          .all();

        return json({
          success: true,
          products: (result.results || []).map(productResponse)
        });
      }

      /*
      ============================================================
      PRODUCTS - SAVE / UNSAVE
      ============================================================
      */

      if (
        /^\/api\/products\/\d+\/save$/.test(path) &&
        request.method === "POST"
      ) {
        const user = await requireAuth(request, env);

        const id = Number(
          path.split("/")[3]
        );

        const product = await env.DB.prepare(`
          SELECT id
          FROM products
          WHERE id = ?
          LIMIT 1
        `)
          .bind(id)
          .first();

        if (!product) {
          return json(
            {
              success: false,
              error: "Produkti nuk ekziston."
            },
            404
          );
        }

        const existing = await env.DB.prepare(`
          SELECT id
          FROM saved_listings
          WHERE user_id = ?
            AND product_id = ?
          LIMIT 1
        `)
          .bind(user.id, id)
          .first();

        if (existing) {
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
          (
            user_id,
            product_id
          )
          VALUES (?, ?)
        `)
          .bind(user.id, id)
          .run();

        return json({
          success: true,
          saved: true
        });
      }

      /*
      ============================================================
      PRODUCTS - SINGLE PRODUCT
      ============================================================
      */

      if (
        /^\/api\/products\/\d+$/.test(path) &&
        request.method === "GET"
      ) {
        const id = Number(
          path.split("/").pop()
        );

        const product = await getProduct(env, id);

        if (!product) {
          return json(
            {
              success: false,
              error: "Produkti nuk u gjet."
            },
            404
          );
        }

        return json({
          success: true,
          product
        });
      }

      /*
      ============================================================
      PRODUCTS - CREATE
      ============================================================
      */

      if (
        path === "/api/products" &&
        request.method === "POST"
      ) {
        const user = await requireAuth(request, env);

        const body = await request.json();

        const title = String(
          body.title ||
          body.name ||
          ""
        ).trim();

        const description = String(
          body.description || ""
        ).trim();

        const price = Number(body.price || 0);

        const image =
          String(
            body.image_url ||
            body.image ||
            ""
          ).trim();

        const category =
          String(
            body.category ||
            "Të tjera"
          ).trim();

        const stock = Number(
          body.stock ?? 1
        );

        const city =
          String(
            body.city || ""
          ).trim();

        const condition =
          String(
            body.condition || ""
          ).trim();

        const phone =
          String(
            body.phone ||
            user.phone ||
            ""
          ).trim();

        const negotiable =
          body.negotiable ? 1 : 0;

        if (!title) {
          return badRequest(
            "Vendosni titullin e produktit."
          );
        }

        if (!Number.isFinite(price) || price < 0) {
          return badRequest(
            "Çmimi nuk është i vlefshëm."
          );
        }

        const result = await env.DB.prepare(`
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
            user.name,
            user.name,
            phone,
            user.email,
            category,
            stock,
            city,
            condition,
            phone,
            negotiable
          )
          .run();

        const product = await getProduct(
          env,
          result.meta.last_row_id
        );

        return json({
          success: true,
          message: "Produkti u publikua.",
          product
        }, 201);
      }

      /*
      ============================================================
      PRODUCTS - ADMIN BLOCK
      ============================================================
      */

      if (
        /^\/api\/products\/\d+\/block$/.test(path) &&
        request.method === "PUT"
      ) {
        const admin = await requireAdmin(
          request,
          env
        );

        const id = Number(
          path.split("/")[3]
        );

        const body = await request.json();

        const reason =
          String(
            body.reason || ""
          ).trim();

        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(id)
            .first();

        if (!existing) {
          return json(
            {
              success: false,
              error: "Produkti nuk ekziston."
            },
            404
          );
        }

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
          await env.DB.prepare(`
            DELETE FROM blocked_listings
            WHERE product_id = ?
          `)
            .bind(id)
            .run();

          return json({
            success: true,
            blocked: false
          });
        }

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
            id,
            admin.id,
            reason
          )
          .run();

        return json({
          success: true,
          blocked: true
        });
      }

      /*
      ============================================================
      PRODUCTS - UPDATE
      ============================================================
      */

      if (
        /^\/api\/products\/\d+$/.test(path) &&
        request.method === "PUT"
      ) {
        const user = await requireAuth(
          request,
          env
        );

        const id = Number(
          path.split("/").pop()
        );

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
          return json(
            {
              success: false,
              error: "Produkti nuk ekziston."
            },
            404
          );
        }

        if (
          user.role !== "admin" &&
          Number(existing.seller_id) !== Number(user.id)
        ) {
          return forbidden();
        }

        const body = await request.json();

        const title =
          body.title !== undefined
            ? String(body.title)
            : existing.title || existing.name || "";

        const description =
          body.description !== undefined
            ? String(body.description)
            : existing.description || "";

        const price =
          body.price !== undefined
            ? Number(body.price)
            : Number(existing.price || 0);

        const image =
          body.image_url !== undefined
            ? String(body.image_url)
            : body.image !== undefined
              ? String(body.image)
              : existing.image_url ||
                existing.image ||
                "";

        const category =
          body.category !== undefined
            ? String(body.category)
            : existing.category || "Të tjera";

        const stock =
          body.stock !== undefined
            ? Number(body.stock)
            : Number(existing.stock || 0);

        const city =
          body.city !== undefined
            ? String(body.city)
            : existing.city || "";

        const condition =
          body.condition !== undefined
            ? String(body.condition)
            : existing.condition || "";

        const phone =
          body.phone !== undefined
            ? String(body.phone)
            : existing.phone || "";

        const negotiable =
          body.negotiable !== undefined
            ? (body.negotiable ? 1 : 0)
            : Number(existing.negotiable || 0);

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
          product: await getProduct(env, id)
        });
      }

      /*
      ============================================================
      PRODUCTS - DELETE
      ============================================================
      */

      if (
        /^\/api\/products\/\d+$/.test(path) &&
        request.method === "DELETE"
      ) {
        const user = await requireAuth(
          request,
          env
        );

        const id = Number(
          path.split("/").pop()
        );

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
          return json(
            {
              success: false,
              error: "Produkti nuk ekziston."
            },
            404
          );
        }

        if (
          user.role !== "admin" &&
          Number(existing.seller_id) !== Number(user.id)
        ) {
          return forbidden();
        }

        await env.DB.prepare(`
          DELETE FROM saved_listings
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

      /*
      ============================================================
      USERS - CREATE/UPSERT
      ============================================================
      */

      if (
        path === "/api/users" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const name =
          String(body.name || "").trim();

        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();

        const phone =
          String(body.phone || "").trim();

        if (!name || !email) {
          return badRequest(
            "Emri dhe email janë të detyrueshme."
          );
        }

        const existing =
          await env.DB.prepare(`
            SELECT *
            FROM auth_accounts
            WHERE LOWER(email) = ?
            LIMIT 1
          `)
            .bind(email)
            .first();

        if (existing) {
          return json({
            success: true,
            user: normalizeUser(existing),
            existing: true
          });
        }

        /*
          Ky endpoint është kompatibilitet për frontend-et
          e vjetra. Për regjistrim normal përdoret /auth/register.
        */

        const tempPassword =
          randomString(24);

        const { hash, salt } =
          await hashPassword(tempPassword);

        const result =
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
            VALUES (?, ?, ?, ?, ?, ?, 'customer')
          `)
            .bind(
              name,
              email,
              phone,
              email,
              hash,
              salt
            )
            .run();

        return json({
          success: true,
          user: {
            id: result.meta.last_row_id,
            name,
            email,
            phone,
            role: "customer"
          }
        }, 201);
      }

      /*
      ============================================================
      USERS - FIND
      ============================================================
      */

      if (
        path === "/api/users/find" &&
        request.method === "GET"
      ) {
        const q =
          url.searchParams.get("q")?.trim() || "";

        if (!q) {
          return badRequest(
            "Vendosni kërkimin."
          );
        }

        const result =
          await env.DB.prepare(`
            SELECT
              id,
              name,
              email,
              phone,
              role
            FROM auth_accounts
            WHERE
              LOWER(name) LIKE LOWER(?)
              OR LOWER(email) LIKE LOWER(?)
              OR LOWER(identifier) LIKE LOWER(?)
            ORDER BY id DESC
            LIMIT 20
          `)
            .bind(
              `%${q}%`,
              `%${q}%`,
              `%${q}%`
            )
            .all();

        return json({
          success: true,
          users: result.results || []
        });
      }

      /*
      ============================================================
      ADMIN - USERS ALL
      ============================================================
      */

      if (
        path === "/api/users/all" &&
        request.method === "GET"
      ) {
        await requireAdmin(
          request,
          env
        );

        const result =
          await env.DB.prepare(`
            SELECT
              id,
              name,
              email,
              phone,
              identifier,
              role,
              created_at
            FROM auth_accounts
            ORDER BY id DESC
          `)
            .all();

        return json({
          success: true,
          users: result.results || []
        });
      }

      /*
      ============================================================
      ADMIN - BLOCK USER
      ============================================================
      */

      if (
        /^\/api\/users\/\d+\/block$/.test(path) &&
        request.method === "PUT"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const userId =
          Number(path.split("/")[3]);

        const body =
          await request.json();

        const reason =
          String(
            body.reason || ""
          ).trim();

        if (
          Number(userId) === Number(admin.id)
        ) {
          return badRequest(
            "Admini nuk mund të bllokojë veten."
          );
        }

        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM auth_accounts
            WHERE id = ?
            LIMIT 1
          `)
            .bind(userId)
            .first();

        if (!existing) {
          return json(
            {
              success: false,
              error: "Përdoruesi nuk ekziston."
            },
            404
          );
        }

        const blocked =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_users
            WHERE user_id = ?
            LIMIT 1
          `)
            .bind(userId)
            .first();

        if (blocked) {
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
            reason
          )
          .run();

        /*
          I mbyllim edhe session-et ekzistuese.
        */

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

      /*
      ============================================================
      ADMIN - SETTINGS GET
      ============================================================
      */

      if (
        path === "/api/admin/settings" &&
        request.method === "GET"
      ) {
        await requireAdmin(
          request,
          env
        );

        const result =
          await env.DB.prepare(`
            SELECT
              setting_key,
              setting_value
            FROM marketplace_settings
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

      /*
      ============================================================
      ADMIN - SETTINGS PUT
      ============================================================
      */

      if (
        path === "/api/admin/settings" &&
        request.method === "PUT"
      ) {
        await requireAdmin(
          request,
          env
        );

        const body =
          await request.json();

        const settings =
          body.settings || body;

        for (const [key, value] of Object.entries(settings)) {
          await env.DB.prepare(`
            INSERT INTO marketplace_settings
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
              value === null ||
              value === undefined
                ? ""
                : String(value)
            )
            .run();
        }

        return json({
          success: true,
          settings
        });
      }

      /*
      ============================================================
      ADMIN - STATS
      ============================================================
      */

      if (
        path === "/api/admin/stats" &&
        request.method === "GET"
      ) {
        await requireAdmin(
          request,
          env
        );

        const [
          users,
          products,
          orders,
          sellers,
          blockedUsers,
          blockedProducts
        ] = await Promise.all([
          env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM auth_accounts
          `).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM products
          `).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM orders
          `).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM auth_accounts
            WHERE role = 'seller'
          `).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM blocked_users
          `).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM blocked_listings
          `).first()
        ]);

        return json({
          success: true,
          stats: {
            users: Number(users?.count || 0),
            products: Number(products?.count || 0),
            orders: Number(orders?.count || 0),
            sellers: Number(sellers?.count || 0),
            blockedUsers: Number(
              blockedUsers?.count || 0
            ),
            blockedProducts: Number(
              blockedProducts?.count || 0
            )
          }
        });
      }

      /*
      ============================================================
      ORDERS - CREATE
      ============================================================
      */

      if (
        path === "/api/orders" &&
        request.method === "POST"
      ) {
        const user =
          await requireAuth(
            request,
            env
          );

        const body =
          await request.json();

        const productId =
          Number(
            body.product_id ||
            body.productId
          );

        const quantity =
          Number(
            body.quantity || 1
          );

        if (
          !Number.isInteger(productId) ||
          productId <= 0
        ) {
          return badRequest(
            "Produkti nuk është i vlefshëm."
          );
        }

        if (
          !Number.isInteger(quantity) ||
          quantity <= 0
        ) {
          return badRequest(
            "Sasia nuk është e vlefshme."
          );
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
          return json(
            {
              success: false,
              error: "Produkti nuk ekziston."
            },
            404
          );
        }

        const stock =
          Number(product.stock || 0);

        if (
          stock > 0 &&
          quantity > stock
        ) {
          return badRequest(
            "Nuk ka stok të mjaftueshëm."
          );
        }

        const totalPrice =
          Number(product.price || 0) *
          quantity;

        const customerName =
          String(
            body.customer_name ||
            body.customerName ||
            user.name ||
            ""
          ).trim();

        const customerPhone =
          String(
            body.customer_phone ||
            body.customerPhone ||
            user.phone ||
            ""
          ).trim();

        const customerCity =
          String(
            body.customer_city ||
            body.customerCity ||
            ""
          ).trim();

        const customerAddress =
          String(
            body.customer_address ||
            body.customerAddress ||
            ""
          ).trim();

        const paymentMethod =
          String(
            body.payment_method ||
            body.paymentMethod ||
            "cash"
          ).trim();

        const orderCode =
          await createOrderCode();

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
              order_code
            )
            VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
            .bind(
              productId,
              user.id,
              quantity,
              totalPrice,
              "pending",
              customerName,
              customerPhone,
              customerCity,
              customerAddress,
              paymentMethod,
              orderCode
            )
            .run();

        /*
          Përditësojmë stokun vetëm nëse produkti
          ka stok pozitiv.
        */

        if (stock > 0) {
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
          message: "Porosia u krijua.",
          order: {
            id: result.meta.last_row_id,
            order_code: orderCode,
            product_id: productId,
            quantity,
            total_price: totalPrice,
            status: "pending"
          }
        }, 201);
      }

      /*
      ============================================================
      ORDERS - GET
      ============================================================
      */

      if (
        path === "/api/orders" &&
        request.method === "GET"
      ) {
        const user =
          await requireAuth(
            request,
            env
          );

        let result;

        if (user.role === "admin") {
          result =
            await env.DB.prepare(`
              SELECT
                o.*,
                p.title AS product_title,
                p.name AS product_name,
                p.image_url AS product_image,
                p.seller_id,
                p.seller
              FROM orders o
              LEFT JOIN products p
                ON p.id = o.product_id
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
                p.seller
              FROM orders o
              LEFT JOIN products p
                ON p.id = o.product_id
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
          orders: result.results || []
        });
      }

      /*
      ============================================================
      ORDERS - UPDATE
      ============================================================
      */

      if (
        /^\/api\/orders\/\d+$/.test(path) &&
        request.method === "PUT"
      ) {
        const user =
          await requireAuth(
            request,
            env
          );

        const id =
          Number(
            path.split("/").pop()
          );

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
          return json(
            {
              success: false,
              error: "Porosia nuk ekziston."
            },
            404
          );
        }

        const body =
          await request.json();

        const status =
          String(
            body.status || ""
          ).trim();

        if (!status) {
          return badRequest(
            "Statusi mungon."
          );
        }

        const allowedStatuses = [
          "pending",
          "confirmed",
          "processing",
          "shipped",
          "completed",
          "cancelled",
          "rejected"
        ];

        if (
          !allowedStatuses.includes(status)
        ) {
          return badRequest(
            "Status i pavlefshëm."
          );
        }

        const isAdmin =
          user.role === "admin";

        const isSeller =
          Number(order.seller_id) ===
          Number(user.id);

        const isBuyer =
          Number(order.buyer_id) ===
          Number(user.id);

        if (
          !isAdmin &&
          !isSeller &&
          !isBuyer
        ) {
          return forbidden();
        }

        /*
          Buyer nuk mund të ndryshojë statusin
          në statuset e shitësit/adminit.
        */

        if (
          !isAdmin &&
          !isSeller &&
          isBuyer &&
          !["cancelled"].includes(status)
        ) {
          return forbidden(
            "Blerësi mund të anulojë vetëm porosinë."
          );
        }

        await env.DB.prepare(`
          UPDATE orders
          SET status = ?
          WHERE id = ?
        `)
          .bind(
            status,
            id
          )
          .run();

        return json({
          success: true,
          order: {
            ...order,
            status
          }
        });
      }

      /*
      ============================================================
      ADMIN SETUP
      ============================================================
      */

      if (
        path === "/api/admin/setup" &&
        request.method === "POST"
      ) {
        const setupKey =
          env.ADMIN_SETUP_KEY;

        if (!setupKey) {
          return serverError(
            "ADMIN_SETUP_KEY nuk është vendosur në Worker Secrets."
          );
        }

        const body =
          await request.json();

        const providedKey =
          String(
            body.setupKey ||
            body.key ||
            ""
          );

        if (
          providedKey !== setupKey
        ) {
          return unauthorized(
            "Setup key i gabuar."
          );
        }

        const name =
          String(
            body.name ||
            "SHIT.BLEJ Admin"
          ).trim();

        const email =
          String(
            body.email ||
            "admin@sabi.com"
          )
            .trim()
            .toLowerCase();

        const password =
          String(
            body.password || ""
          );

        if (
          !password ||
          password.length < 4
        ) {
          return badRequest(
            "Admin password duhet të ketë të paktën 4 karaktere."
          );
        }

        const existing =
          await env.DB.prepare(`
            SELECT *
            FROM auth_accounts
            WHERE LOWER(email) = ?
            LIMIT 1
          `)
            .bind(email)
            .first();

        const { hash, salt } =
          await hashPassword(password);

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

          await env.DB.prepare(`
            DELETE FROM sessions
            WHERE user_id = ?
          `)
            .bind(existing.id)
            .run();

          return json({
            success: true,
            message: "Admini u përditësua.",
            user: {
              id: existing.id,
              name,
              email,
              role: "admin"
            }
          });
        }

        const result =
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

        return json({
          success: true,
          message: "Admini u krijua.",
          user: {
            id: result.meta.last_row_id,
            name,
            email,
            role: "admin"
          }
        }, 201);
      }

      /*
      ============================================================
      FALLBACK
      ============================================================
      */

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return text(
        "SHIT.BLEJ API is running, but ASSETS binding is missing.",
        404
      );

    } catch (error) {
      console.error(error);

      if (error?.message === "UNAUTHORIZED") {
        return unauthorized();
      }

      if (error?.message === "FORBIDDEN") {
        return forbidden();
      }

      return serverError(
        error?.message ||
        "Gabim i panjohur."
      );
    }
  }
};
