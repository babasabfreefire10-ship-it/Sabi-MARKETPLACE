const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=UTF-8"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS
  });
}

function getToken(request) {
  const auth = request.headers.get("Authorization") || "";

  if (!auth.startsWith("Bearer ")) return null;

  return auth.substring(7).trim();
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
    bytes[i] = parseInt(value.substr(i * 2, 2), 16);
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
   DATABASE SETUP
========================================================= */

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


  /*
    Mos fshijmë asgjë.
    Nëse kolonat ekzistojnë, SQLite jep error dhe
    catch e injoron.
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
    WHERE s.token = ?
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

  if (user.role !== "admin") {
    throw new Error("FORBIDDEN");
  }

  return user;
}


/* =========================================================
   PRODUCT FORMAT
========================================================= */

function formatProduct(product) {

  if (!product) return null;

  return {
    ...product,

    id: Number(product.id),

    price: Number(product.price || 0),

    stock: Number(product.stock || 0),

    seller_id:
      product.seller_id == null
        ? null
        : Number(product.seller_id),

    image:
      product.image ||
      product.image_url ||
      "",

    image_url:
      product.image_url ||
      product.image ||
      "",

    title:
      product.title ||
      product.name ||
      "",

    sellerName:
      product.sellerName ||
      product.seller_name ||
      product.seller ||
      "",

    sellerPhone:
      product.sellerPhone ||
      product.seller_phone ||
      product.phone ||
      "",

    sellerEmail:
      product.sellerEmail ||
      product.seller_email ||
      ""
  };
}


async function findProduct(env, id) {

  const product = await env.DB.prepare(`
    SELECT
      p.*,
      a.name AS seller_name,
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

  if (!product) return null;

  return formatProduct({
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


/* =========================================================
   MAIN WORKER
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

      if (path === "/api" || path === "/api/") {

        return json({
          success: true,
          app: "SABI Marketplace",
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

        const name =
          String(body.name || "").trim();

        const email =
          String(body.email || "").trim().toLowerCase();

        const phone =
          String(body.phone || "").trim();

        const password =
          String(body.password || "");

        const role =
          body.role === "seller"
            ? "seller"
            : "customer";


        if (!name) {
          return json({
            success: false,
            error: "Vendos emrin."
          }, 400);
        }


        if (!email) {
          return json({
            success: false,
            error: "Vendos email."
          }, 400);
        }


        if (password.length < 4) {
          return json({
            success: false,
            error: "Password duhet të ketë të paktën 4 karaktere."
          }, 400);
        }


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
          return json({
            success: false,
            error: "Ky email ekziston."
          }, 409);
        }


        const { hash, salt } =
          await passwordHash(password);


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
          String(
            body.identifier ||
            body.email ||
            ""
          )
            .trim()
            .toLowerCase();

        const password =
          String(body.password || "");


        if (!identifier || !password) {

          return json({
            success: false,
            error: "Plotëso të gjitha fushat."
          }, 400);

        }


        const account =
          await env.DB.prepare(`
            SELECT *
            FROM auth_accounts
            WHERE
              LOWER(email) = ?
              OR LOWER(identifier) = ?
            LIMIT 1
          `)
            .bind(
              identifier,
              identifier
            )
            .first();


        if (!account) {

          return json({
            success: false,
            error: "Email ose password i gabuar."
          }, 401);

        }


        const { hash } =
          await passwordHash(
            password,
            account.password_salt
          );


        if (
          hash !== account.password_hash
        ) {

          return json({
            success: false,
            error: "Email ose password i gabuar."
          }, 401);

        }


        if (
          body.role &&
          body.role !== account.role
        ) {

          return json({
            success: false,
            error: "Roli nuk përputhet me llogarinë."
          }, 401);

        }


        const token =
          randomToken(64);


        await env.DB.prepare(`
          INSERT INTO sessions
          (
            user_id,
            token
          )
          VALUES (?, ?)
        `)
          .bind(
            account.id,
            token
          )
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
          await currentUser(
            request,
            env
          );


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

        const token =
          getToken(request);


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
         MUST COME BEFORE /products/:id
      ===================================================== */

      if (
        path === "/api/products/search" &&
        request.method === "GET"
      ) {

        const q =
          url.searchParams.get("q") || "";

        const category =
          url.searchParams.get("category") || "";

        const minRaw =
          url.searchParams.get("min");

        const maxRaw =
          url.searchParams.get("max");


        let sql = `
          SELECT *
          FROM products
          WHERE 1 = 1
        `;

        const params = [];


        if (q.trim()) {

          sql += `
            AND (
              LOWER(COALESCE(title,'')) LIKE ?
              OR LOWER(COALESCE(name,'')) LIKE ?
              OR LOWER(COALESCE(description,'')) LIKE ?
            )
          `;

          const search =
            `%${q.trim().toLowerCase()}%`;

          params.push(
            search,
            search,
            search
          );

        }


        if (category.trim()) {

          sql += `
            AND LOWER(COALESCE(category,'')) = LOWER(?)
          `;

          params.push(
            category.trim()
          );

        }


        if (
          minRaw !== null &&
          minRaw !== "" &&
          !Number.isNaN(Number(minRaw))
        ) {

          sql += `
            AND CAST(price AS REAL) >= ?
          `;

          params.push(
            Number(minRaw)
          );

        }


        if (
          maxRaw !== null &&
          maxRaw !== "" &&
          !Number.isNaN(Number(maxRaw))
        ) {

          sql += `
            AND CAST(price AS REAL) <= ?
          `;

          params.push(
            Number(maxRaw)
          );

        }


        sql += `
          ORDER BY id DESC
          LIMIT 300
        `;


        const result =
          await env.DB
            .prepare(sql)
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
          await requireUser(
            request,
            env
          );


        const result =
          await env.DB.prepare(`
            SELECT p.*
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
          products:
            (result.results || [])
              .map(formatProduct)
        });

      }


      /* =====================================================
         ALL PRODUCTS
      ===================================================== */

      if (
        path === "/api/products" &&
        request.method === "GET"
      ) {

        const category =
          url.searchParams.get("category");


        let result;


        if (category) {

          result =
            await env.DB.prepare(`
              SELECT *
              FROM products
              WHERE LOWER(COALESCE(category,'')) =
                    LOWER(?)
              ORDER BY id DESC
              LIMIT 500
            `)
              .bind(category)
              .all();

        } else {

          result =
            await env.DB.prepare(`
              SELECT *
              FROM products
              ORDER BY id DESC
              LIMIT 500
            `)
              .all();

        }


        return json(
          (result.results || [])
            .map(formatProduct)
        );

      }


      /* =====================================================
         PRODUCT SAVE
      ===================================================== */

      if (
        /^\/api\/products\/[0-9]+\/save$/.test(path) &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(
            request,
            env
          );


        const id =
          Number(path.split("/")[3]);


        const product =
          await env.DB.prepare(`
            SELECT id
            FROM products
            WHERE id = ?
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
          `)
            .bind(
              user.id,
              id
            )
            .first();


        if (saved) {

          await env.DB.prepare(`
            DELETE FROM saved_listings
            WHERE user_id = ?
              AND product_id = ?
          `)
            .bind(
              user.id,
              id
            )
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
          .bind(
            user.id,
            id
          )
          .run();


        return json({
          success: true,
          saved: true
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


        const product =
          await findProduct(
            env,
            id
          );


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
         CREATE PRODUCT
      ===================================================== */

      if (
        path === "/api/products" &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(
            request,
            env
          );


        const body =
          await request.json();


        const title =
          String(
            body.title ||
            body.name ||
            ""
          ).trim();


        const description =
          String(
            body.description ||
            ""
          ).trim();


        const price =
          Number(body.price || 0);


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


        const stock =
          Number(
            body.stock ?? 1
          );


        const city =
          String(
            body.city ||
            ""
          ).trim();


        const condition =
          String(
            body.condition ||
            ""
          ).trim();


        const phone =
          String(
            body.phone ||
            user.phone ||
            ""
          ).trim();


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
          await requireUser(
            request,
            env
          );


        const id =
          Number(path.split("/").pop());


        const existing =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
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
          Number(existing.seller_id) !==
            Number(user.id)
        ) {

          return json({
            success: false,
            error: "Nuk keni akses."
          }, 403);

        }


        const body =
          await request.json();


        const title =
          String(
            body.title ??
            existing.title ??
            existing.name ??
            ""
          );


        const description =
          String(
            body.description ??
            existing.description ??
            ""
          );


        const price =
          Number(
            body.price ??
            existing.price ??
            0
          );


        const image =
          String(
            body.image_url ??
            body.image ??
            existing.image_url ??
            existing.image ??
            ""
          );


        const category =
          String(
            body.category ??
            existing.category ??
            "Të tjera"
          );


        const stock =
          Number(
            body.stock ??
            existing.stock ??
            0
          );


        const city =
          String(
            body.city ??
            existing.city ??
            ""
          );


        const condition =
          String(
            body.condition ??
            existing.condition ??
            ""
          );


        const phone =
          String(
            body.phone ??
            existing.phone ??
            ""
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
            await findProduct(
              env,
              id
            )
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
          await requireUser(
            request,
            env
          );


        const id =
          Number(path.split("/").pop());


        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
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
          Number(product.seller_id) !==
            Number(user.id)
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
         ORDERS CREATE
      ===================================================== */

      if (
        path === "/api/orders" &&
        request.method === "POST"
      ) {

        const user =
          await requireUser(
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


        const product =
          await env.DB.prepare(`
            SELECT *
            FROM products
            WHERE id = ?
          `)
            .bind(productId)
            .first();


        if (!product) {

          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);

        }


        const total =
          Number(product.price || 0) *
          quantity;


        const code =
          "SABI-" +
          Date.now().toString(36).toUpperCase() +
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
              order_code
            )
            VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
            .bind(
              productId,
              user.id,
              quantity,
              total,
              "pending",
              body.customer_name ||
                user.name ||
                "",
              body.customer_phone ||
                user.phone ||
                "",
              body.customer_city ||
                "",
              body.customer_address ||
                "",
              body.payment_method ||
                "cash",
              code
            )
            .run();


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
          await requireUser(
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
          orders:
            result.results || []
        });

      }


      /* =====================================================
         ORDER UPDATE
      ===================================================== */

      if (
        /^\/api\/orders\/[0-9]+$/.test(path) &&
        request.method === "PUT"
      ) {

        const user =
          await requireUser(
            request,
            env
          );


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


        const status =
          String(body.status || "")
            .trim();


        const seller =
          Number(order.seller_id) ===
          Number(user.id);


        const buyer =
          Number(order.buyer_id) ===
          Number(user.id);


        const admin =
          user.role === "admin";


        if (
          !admin &&
          !seller &&
          !buyer
        ) {

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
            error: "Blerësi mund vetëm ta anulojë porosinë."
          }, 403);

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
          success: true
        });

      }


      /* =====================================================
         ADMIN STATS
      ===================================================== */

      if (
        path === "/api/admin/stats" &&
        request.method === "GET"
      ) {

        await requireAdmin(
          request,
          env
        );


        const users =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM auth_accounts
          `)
            .first();


        const products =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM products
          `)
            .first();


        const orders =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM orders
          `)
            .first();


        const sellers =
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM auth_accounts
            WHERE role = 'seller'
          `)
            .first();


        return json({
          success: true,

          stats: {
            users:
              Number(users?.count || 0),

            products:
              Number(products?.count || 0),

            orders:
              Number(orders?.count || 0),

            sellers:
              Number(sellers?.count || 0)
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
          users:
            result.results || []
        });

      }


      /* =====================================================
         ADMIN BLOCK USER
      ===================================================== */

      if (
        /^\/api\/users\/[0-9]+\/block$/.test(path) &&
        request.method === "PUT"
      ) {

        const admin =
          await requireAdmin(
            request,
            env
          );


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


        const body =
          await request.json();


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
            body.reason || ""
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
        request.method === "PUT"
      ) {

        const admin =
          await requireAdmin(
            request,
            env
          );


        const productId =
          Number(path.split("/")[3]);


        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM blocked_listings
            WHERE product_id = ?
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


        const body =
          await request.json();


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
            body.reason || ""
          )
          .run();


        return json({
          success: true,
          blocked: true
        });

      }


      /* =====================================================
         ADMIN SETTINGS
      ===================================================== */

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
          `)
            .all();


        const settings = {};


        for (
          const item of result.results || []
        ) {

          settings[item.setting_key] =
            item.setting_value;

        }


        return json({
          success: true,
          settings
        });

      }


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


        for (
          const [key,value]
          of Object.entries(settings)
        ) {

          await env.DB.prepare(`
            INSERT INTO marketplace_settings
            (
              setting_key,
              setting_value
            )
            VALUES (?, ?)
            ON CONFLICT(setting_key)
            DO UPDATE SET
              setting_value =
                excluded.setting_value
          `)
            .bind(
              key,
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
              "ADMIN_SETUP_KEY nuk është vendosur."
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
          body.name ||
          "SABI Admin";


        const email =
          String(
            body.email ||
            "admin@sabi.com"
          )
            .toLowerCase()
            .trim();


        const password =
          String(
            body.password || ""
          );


        if (password.length < 4) {

          return json({
            success: false,
            error:
              "Password shumë i shkurtër."
          }, 400);

        }


        const {hash,salt} =
          await passwordHash(password);


        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM auth_accounts
            WHERE LOWER(email) = ?
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

        /*
          / -> index.html
        */

        if (
          path === "/" ||
          path === ""
        ) {

          const newRequest =
            new Request(
              new URL(
                "/index.html",
                url.origin
              ),
              request
            );

          return env.ASSETS.fetch(
            newRequest
          );

        }


        return env.ASSETS.fetch(
          request
        );

      }


      return new Response(
        "SABI Marketplace API is online.",
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
        "SABI WORKER ERROR:",
        error
      );


      if (
        error.message ===
        "UNAUTHORIZED"
      ) {

        return json({
          success: false,
          error: "Duhet të identifikoheni."
        }, 401);

      }


      if (
        error.message ===
        "FORBIDDEN"
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
