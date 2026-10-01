export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          ...corsHeaders
        }
      });

    /* =========================================================
       HELPERS
    ========================================================= */

    const text = v => String(v ?? "").trim();

    function categoryToUI(category) {
      const map = {
        Electronics: "Elektronikë",
        Accessories: "Aksesorë",
        Fashion: "Rroba",
        Shoes: "Këpucë",
        Home: "Shtëpi & Mobilje",
        Other: "Të tjera",
        Cars: "Makina",
        Property: "Prona",
        Phones: "Telefona",
        Computers: "Kompjuterë",
        Jobs: "Punë",
        Services: "Shërbime",
        Sports: "Sport",
        Tools: "Vegla & Makineri"
      };

      return map[category] || category || "Të tjera";
    }

    function categoryToDB(category) {
      const map = {
        "Elektronikë": "Electronics",
        "Aksesorë": "Accessories",
        "Rroba": "Fashion",
        "Fashion": "Fashion",
        "Këpucë": "Shoes",
        "Shtëpi & Mobilje": "Home",
        "Të tjera": "Other",
        "Makina": "Cars",
        "Prona": "Property",
        "Telefona": "Phones",
        "Kompjuterë": "Computers",
        "Punë": "Jobs",
        "Shërbime": "Services",
        "Sport": "Sports",
        "Vegla & Makineri": "Tools"
      };

      return map[category] || category || "Other";
    }

    function createToken() {
      const bytes = crypto.getRandomValues(new Uint8Array(32));

      return [...bytes]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    }

    function getBearer(request) {
      const auth = request.headers.get("Authorization") || "";

      if (!auth.startsWith("Bearer ")) {
        return "";
      }

      return auth.slice(7).trim();
    }

    /* =========================================================
       DATABASE SETUP
       Nuk fshin asnjë të dhënë ekzistuese.
    ========================================================= */

    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS auth_accounts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          identifier TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'customer',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
      `).run();

      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          token TEXT NOT NULL UNIQUE,
          expires_at TEXT NOT NULL,
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

    } catch (error) {
      return json({
        success: false,
        error: "Gabim me D1: " + error.message
      }, 500);
    }

    /* =========================================================
       ADD COLUMNS TO EXISTING PRODUCTS
       ========================================================= */

    const alterColumns = [
      `ALTER TABLE products ADD COLUMN city TEXT DEFAULT ''`,
      `ALTER TABLE products ADD COLUMN condition TEXT DEFAULT ''`,
      `ALTER TABLE products ADD COLUMN phone TEXT DEFAULT ''`,
      `ALTER TABLE products ADD COLUMN negotiable INTEGER DEFAULT 0`
    ];

    for (const sql of alterColumns) {
      try {
        await env.DB.prepare(sql).run();
      } catch {
        // Kolona ekziston.
      }
    }

    /* =========================================================
       PASSWORD HASH
    ========================================================= */

    async function hashPassword(password) {
      const encoder = new TextEncoder();

      const salt = crypto.getRandomValues(
        new Uint8Array(16)
      );

      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
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

      const saltHex = [...salt]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      const hashHex = [...new Uint8Array(bits)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      return `pbkdf2$100000$${saltHex}$${hashHex}`;
    }

    async function verifyPassword(password, stored) {
      try {
        const parts = stored.split("$");

        if (
          parts.length !== 4 ||
          parts[0] !== "pbkdf2"
        ) {
          return false;
        }

        const iterations = Number(parts[1]);

        const salt = new Uint8Array(
          parts[2]
            .match(/.{1,2}/g)
            .map(x => parseInt(x, 16))
        );

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
            iterations,
            hash: "SHA-256"
          },
          key,
          256
        );

        const actual = [...new Uint8Array(bits)]
          .map(b => b.toString(16).padStart(2, "0"))
          .join("");

        return actual === parts[3];

      } catch {
        return false;
      }
    }

    /* =========================================================
       AUTH
    ========================================================= */

    async function getAuthUser(request) {
      const token = getBearer(request);

      if (!token) return null;

      const session = await env.DB.prepare(`
        SELECT
          s.user_id,
          s.expires_at,
          u.id,
          u.name,
          u.email,
          a.identifier,
          a.role
        FROM sessions s
        JOIN users u
          ON u.id = s.user_id
        LEFT JOIN auth_accounts a
          ON a.user_id = s.user_id
        WHERE s.token = ?
        LIMIT 1
      `)
        .bind(token)
        .first();

      if (!session) return null;

      if (
        new Date(session.expires_at).getTime() < Date.now()
      ) {
        await env.DB.prepare(`
          DELETE FROM sessions
          WHERE token = ?
        `)
          .bind(token)
          .run();

        return null;
      }

      return session;
    }

    async function requireAuth(request) {
      const user = await getAuthUser(request);

      if (!user) {
        return json({
          success: false,
          error: "Duhet të identifikohesh."
        }, 401);
      }

      return user;
    }

    async function requireAdmin(request) {
      const user = await requireAuth(request);

      if (user instanceof Response) {
        return user;
      }

      if (user.role !== "admin") {
        return json({
          success: false,
          error: "Vetëm administratori ka akses."
        }, 403);
      }

      return user;
    }

    /* =========================================================
       REGISTER
    ========================================================= */

    if (
      url.pathname === "/api/auth/register" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const name = text(body.name);

        const identifier = text(
          body.identifier ||
          body.email ||
          body.phone
        ).toLowerCase();

        const password = String(body.password || "");

        const role =
          body.role === "seller"
            ? "seller"
            : "customer";

        if (!name) {
          return json({
            success: false,
            error: "Emri është i detyrueshëm."
          }, 400);
        }

        if (!identifier) {
          return json({
            success: false,
            error: "Email ose telefoni është i detyrueshëm."
          }, 400);
        }

        if (password.length < 6) {
          return json({
            success: false,
            error: "Fjalëkalimi duhet të ketë të paktën 6 karaktere."
          }, 400);
        }

        const exists = await env.DB.prepare(`
          SELECT id
          FROM auth_accounts
          WHERE identifier = ?
          LIMIT 1
        `)
          .bind(identifier)
          .first();

        if (exists) {
          return json({
            success: false,
            error: "Kjo llogari ekziston."
          }, 409);
        }

        const email =
          identifier.includes("@")
            ? identifier
            : `${identifier}@phone.sabi.local`;

        let user = await env.DB.prepare(`
          SELECT id, name, email
          FROM users
          WHERE LOWER(email) = ?
          LIMIT 1
        `)
          .bind(email)
          .first();

        if (!user) {
          const result = await env.DB.prepare(`
            INSERT INTO users
              (name, email)
            VALUES (?, ?)
          `)
            .bind(name, email)
            .run();

          user = await env.DB.prepare(`
            SELECT id, name, email
            FROM users
            WHERE id = ?
          `)
            .bind(result.meta.last_row_id)
            .first();
        }

        const passwordHash =
          await hashPassword(password);

        await env.DB.prepare(`
          INSERT INTO auth_accounts
            (user_id, identifier, password_hash, role)
          VALUES (?, ?, ?, ?)
        `)
          .bind(
            user.id,
            identifier,
            passwordHash,
            role
          )
          .run();

        return json({
          success: true,
          message: "Llogaria u krijua.",
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            identifier,
            role
          }
        }, 201);

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       LOGIN
    ========================================================= */

    if (
      url.pathname === "/api/auth/login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const identifier = text(
          body.identifier ||
          body.email ||
          body.username
        ).toLowerCase();

        const password = String(
          body.password || ""
        );

        if (!identifier || !password) {
          return json({
            success: false,
            error: "Plotëso emailin dhe fjalëkalimin."
          }, 400);
        }

        const account = await env.DB.prepare(`
          SELECT
            a.id,
            a.user_id,
            a.identifier,
            a.password_hash,
            a.role,
            u.name,
            u.email
          FROM auth_accounts a
          JOIN users u
            ON u.id = a.user_id
          WHERE a.identifier = ?
          LIMIT 1
        `)
          .bind(identifier)
          .first();

        if (!account) {
          return json({
            success: false,
            error: "Emaili/telefoni ose fjalëkalimi është i gabuar."
          }, 401);
        }

        const valid = await verifyPassword(
          password,
          account.password_hash
        );

        if (!valid) {
          return json({
            success: false,
            error: "Emaili/telefoni ose fjalëkalimi është i gabuar."
          }, 401);
        }

        /*
          Admini mund të hyjë edhe kur login.html
          dërgon role=admin.
        */

        const requestedRole = text(body.role);

        if (
          requestedRole &&
          requestedRole !== "admin" &&
          requestedRole !== account.role
        ) {
          return json({
            success: false,
            error: "Roli i zgjedhur nuk përputhet me llogarinë."
          }, 403);
        }

        const token = createToken();

        const expires = new Date(
          Date.now() +
          1000 * 60 * 60 * 24 * 30
        ).toISOString();

        await env.DB.prepare(`
          INSERT INTO sessions
            (user_id, token, expires_at)
          VALUES (?, ?, ?)
        `)
          .bind(
            account.user_id,
            token,
            expires
          )
          .run();

        return json({
          success: true,
          token,
          user: {
            id: account.user_id,
            name: account.name,
            email: account.email,
            identifier: account.identifier,
            role: account.role
          }
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ME
    ========================================================= */

    if (
      url.pathname === "/api/auth/me" &&
      request.method === "GET"
    ) {
      const user = await getAuthUser(request);

      if (!user) {
        return json({
          success: false,
          authenticated: false
        }, 401);
      }

      return json({
        success: true,
        authenticated: true,
        user: {
          id: user.user_id,
          name: user.name,
          email: user.email,
          identifier: user.identifier || "",
          role: user.role
        }
      });
    }

    /* =========================================================
       LOGOUT
    ========================================================= */

    if (
      url.pathname === "/api/auth/logout" &&
      request.method === "POST"
    ) {
      const token = getBearer(request);

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

    /* =========================================================
       PRODUCTS - GET
    ========================================================= */

    if (
      url.pathname === "/api/products" &&
      request.method === "GET"
    ) {
      try {
        const { results } = await env.DB.prepare(`
          SELECT
            p.*,
            u.name AS seller_name,
            u.email AS seller_email
          FROM products p
          LEFT JOIN users u
            ON u.id = p.seller_id
          ORDER BY p.id DESC
        `).all();

        const products = results.map(p => ({
          id: p.id,
          name: p.title || p.name || "",
          title: p.title || p.name || "",
          description: p.description || "",
          price: Number(p.price || 0),

          image: p.image_url || p.image || "",
          image_url: p.image_url || p.image || "",

          seller_id: p.seller_id,

          seller: p.seller_name || "SHIT.BLEJ",
          sellerName: p.seller_name || "SHIT.BLEJ",
          sellerEmail: p.seller_email || "",

          category: categoryToUI(p.category),

          stock: Number(p.stock ?? 1),

          city: p.city || "",
          condition: p.condition || "",
          phone: p.phone || "",
          negotiable: Boolean(p.negotiable),

          created_at: p.created_at
        }));

        return json(products);

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       PRODUCTS - SEARCH
    ========================================================= */

    if (
      url.pathname === "/api/products/search" &&
      request.method === "GET"
    ) {
      try {
        const q = text(
          url.searchParams.get("q")
        );

        const category = text(
          url.searchParams.get("category")
        );

        const city = text(
          url.searchParams.get("city")
        );

        const min = Number(
          url.searchParams.get("min")
        );

        const max = Number(
          url.searchParams.get("max")
        );

        let query = `
          SELECT
            p.*,
            u.name AS seller_name,
            u.email AS seller_email
          FROM products p
          LEFT JOIN users u
            ON u.id = p.seller_id
          WHERE NOT EXISTS (
            SELECT 1
            FROM blocked_listings bl
            WHERE bl.product_id = p.id
          )
        `;

        const params = [];

        if (q) {
          query += `
            AND (
              LOWER(p.title) LIKE ?
              OR LOWER(p.description) LIKE ?
            )
          `;

          const search = `%${q.toLowerCase()}%`;

          params.push(search, search);
        }

        if (category) {
          query += ` AND p.category = ?`;
          params.push(categoryToDB(category));
        }

        if (city) {
          query += ` AND LOWER(p.city) LIKE ?`;
          params.push(`%${city.toLowerCase()}%`);
        }

        if (Number.isFinite(min)) {
          query += ` AND p.price >= ?`;
          params.push(min);
        }

        if (Number.isFinite(max)) {
          query += ` AND p.price <= ?`;
          params.push(max);
        }

        query += ` ORDER BY p.id DESC`;

        const statement = env.DB.prepare(query);

        const { results } = params.length
          ? await statement.bind(...params).all()
          : await statement.all();

        return json(results.map(p => ({
          id: p.id,
          name: p.title || "",
          title: p.title || "",
          description: p.description || "",
          price: Number(p.price || 0),
          image: p.image_url || "",
          image_url: p.image_url || "",
          seller_id: p.seller_id,
          seller: p.seller_name || "SHIT.BLEJ",
          sellerName: p.seller_name || "SHIT.BLEJ",
          sellerEmail: p.seller_email || "",
          category: categoryToUI(p.category),
          stock: Number(p.stock ?? 1),
          city: p.city || "",
          condition: p.condition || "",
          phone: p.phone || "",
          negotiable: Boolean(p.negotiable),
          created_at: p.created_at
        })));

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       SINGLE PRODUCT
    ========================================================= */

    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "GET"
    ) {
      const id = Number(
        url.pathname.split("/").pop()
      );

      if (!Number.isInteger(id)) {
        return json({
          success: false,
          error: "ID i pavlefshëm."
        }, 400);
      }

      try {
        const p = await env.DB.prepare(`
          SELECT
            p.*,
            u.name AS seller_name,
            u.email AS seller_email
          FROM products p
          LEFT JOIN users u
            ON u.id = p.seller_id
          WHERE p.id = ?
          LIMIT 1
        `)
          .bind(id)
          .first();

        if (!p) {
          return json({
            success: false,
            error: "Produkti nuk ekziston."
          }, 404);
        }

        return json({
          success: true,
          product: {
            id: p.id,
            name: p.title || "",
            title: p.title || "",
            description: p.description || "",
            price: Number(p.price || 0),
            image: p.image_url || "",
            image_url: p.image_url || "",
            seller_id: p.seller_id,
            seller: p.seller_name || "SHIT.BLEJ",
            sellerName: p.seller_name || "SHIT.BLEJ",
            sellerEmail: p.seller_email || "",
            category: categoryToUI(p.category),
            stock: Number(p.stock ?? 1),
            city: p.city || "",
            condition: p.condition || "",
            phone: p.phone || "",
            negotiable: Boolean(p.negotiable),
            created_at: p.created_at
          }
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       CREATE PRODUCT
    ========================================================= */

    if (
      url.pathname === "/api/products" &&
      request.method === "POST"
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      if (
        auth.role !== "seller" &&
        auth.role !== "admin"
      ) {
        return json({
          success: false,
          error: "Duhet të jesh shitës për të publikuar."
        }, 403);
      }

      try {
        const body = await request.json();

        const title = text(
          body.title || body.name
        );

        const description = text(
          body.description
        );

        const price = Number(
          body.price
        );

        const imageUrl = text(
          body.image_url || body.image
        );

        const category = categoryToDB(
          body.category
        );

        const stock = Math.max(
          0,
          Number.isFinite(Number(body.stock))
            ? Number(body.stock)
            : 1
        );

        const city = text(body.city);

        const condition = text(
          body.condition
        );

        const phone = text(body.phone);

        const negotiable =
          body.negotiable ? 1 : 0;

        if (!title) {
          return json({
            success: false,
            error: "Titulli mungon."
          }, 400);
        }

        if (
          !Number.isFinite(price) ||
          price <= 0
        ) {
          return json({
            success: false,
            error: "Çmimi nuk është i vlefshëm."
          }, 400);
        }

        const result = await env.DB.prepare(`
          INSERT INTO products
          (
            title,
            description,
            price,
            image_url,
            seller_id,
            category,
            stock,
            city,
            condition,
            phone,
            negotiable
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
          .bind(
            title,
            description,
            price,
            imageUrl,
            Number(auth.user_id),
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
          id: result.meta.last_row_id
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       SAVE / UNSAVE PRODUCT
       POST /api/products/:id/save
    ========================================================= */

    if (
      url.pathname.match(/^\/api\/products\/\d+\/save$/) &&
      request.method === "POST"
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      const parts = url.pathname.split("/");
      const id = Number(parts[3]);

      try {
        const existing = await env.DB.prepare(`
          SELECT id
          FROM saved_listings
          WHERE user_id = ?
            AND product_id = ?
          LIMIT 1
        `)
          .bind(
            Number(auth.user_id),
            id
          )
          .first();

        if (existing) {
          await env.DB.prepare(`
            DELETE FROM saved_listings
            WHERE user_id = ?
              AND product_id = ?
          `)
            .bind(
              Number(auth.user_id),
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
            (user_id, product_id)
          VALUES (?, ?)
        `)
          .bind(
            Number(auth.user_id),
            id
          )
          .run();

        return json({
          success: true,
          saved: true
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       SAVED PRODUCTS
    ========================================================= */

    if (
      url.pathname === "/api/products/saved" &&
      request.method === "GET"
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      try {
        const { results } = await env.DB.prepare(`
          SELECT
            p.*,
            u.name AS seller_name,
            u.email AS seller_email
          FROM saved_listings s
          JOIN products p
            ON p.id = s.product_id
          LEFT JOIN users u
            ON u.id = p.seller_id
          WHERE s.user_id = ?
          ORDER BY s.id DESC
        `)
          .bind(Number(auth.user_id))
          .all();

        return json(results);

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       UPDATE PRODUCT
    ========================================================= */

    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "PUT" &&
      !url.pathname.endsWith("/save") &&
      !url.pathname.endsWith("/block")
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      const id = Number(
        url.pathname.split("/").pop()
      );

      if (!Number.isInteger(id)) {
        return json({
          success: false,
          error: "ID i pavlefshëm."
        }, 400);
      }

      try {
        const product = await env.DB.prepare(`
          SELECT seller_id
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
          auth.role !== "admin" &&
          Number(product.seller_id) !==
          Number(auth.user_id)
        ) {
          return json({
            success: false,
            error: "Nuk ke leje."
          }, 403);
        }

        const body = await request.json();

        const title = text(
          body.title || body.name
        );

        const description = text(
          body.description
        );

        const price = Number(body.price);

        const imageUrl = text(
          body.image_url || body.image
        );

        const category = categoryToDB(
          body.category
        );

        const stock = Math.max(
          0,
          Number(body.stock ?? 0)
        );

        const city = text(body.city);
        const condition = text(body.condition);
        const phone = text(body.phone);
        const negotiable =
          body.negotiable ? 1 : 0;

        if (!title || !Number.isFinite(price) || price <= 0) {
          return json({
            success: false,
            error: "Të dhënat e produktit nuk janë të vlefshme."
          }, 400);
        }

        await env.DB.prepare(`
          UPDATE products
          SET
            title = ?,
            description = ?,
            price = ?,
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
            description,
            price,
            imageUrl,
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
          success: true
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       DELETE PRODUCT
    ========================================================= */

    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "DELETE"
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      const id = Number(
        url.pathname.split("/").pop()
      );

      try {
        const product = await env.DB.prepare(`
          SELECT seller_id
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
          auth.role !== "admin" &&
          Number(product.seller_id) !==
          Number(auth.user_id)
        ) {
          return json({
            success: false,
            error: "Nuk ke leje."
          }, 403);
        }

        await env.DB.prepare(`
          DELETE FROM saved_listings
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
          success: true
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       USERS - LEGACY
    ========================================================= */

    if (
      url.pathname === "/api/users" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const name = text(body.name);
        const email = text(body.email).toLowerCase();

        if (!name || !email) {
          return json({
            success: false,
            error: "Emri dhe email janë të detyrueshëm."
          }, 400);
        }

        const existing = await env.DB.prepare(`
          SELECT id, name, email
          FROM users
          WHERE LOWER(email) = ?
          LIMIT 1
        `)
          .bind(email)
          .first();

        if (existing) {
          return json({
            success: true,
            user: existing,
            existing: true
          });
        }

        const result = await env.DB.prepare(`
          INSERT INTO users
            (name, email)
          VALUES (?, ?)
        `)
          .bind(name, email)
          .run();

        const user = await env.DB.prepare(`
          SELECT id, name, email
          FROM users
          WHERE id = ?
        `)
          .bind(result.meta.last_row_id)
          .first();

        return json({
          success: true,
          user
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       FIND USER
    ========================================================= */

    if (
      url.pathname === "/api/users/find" &&
      request.method === "GET"
    ) {
      const email = text(
        url.searchParams.get("email")
      ).toLowerCase();

      if (!email) {
        return json({
          success: false,
          error: "Email mungon."
        }, 400);
      }

      const user = await env.DB.prepare(`
        SELECT id, name, email
        FROM users
        WHERE LOWER(email) = ?
        LIMIT 1
      `)
        .bind(email)
        .first();

      return json({
        success: true,
        user: user || null
      });
    }

    /* =========================================================
       ADMIN - ALL USERS
    ========================================================= */

    if (
      url.pathname === "/api/users/all" &&
      request.method === "GET"
    ) {
      const admin = await requireAdmin(request);

      if (admin instanceof Response) {
        return admin;
      }

      try {
        const { results } = await env.DB.prepare(`
          SELECT
            u.id,
            u.name,
            u.email,
            a.identifier,
            a.role,
            a.created_at
          FROM users u
          LEFT JOIN auth_accounts a
            ON a.user_id = u.id
          ORDER BY u.id DESC
        `).all();

        return json(results);

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ADMIN - BLOCK USER
    ========================================================= */

    if (
      url.pathname.match(/^\/api\/users\/\d+\/block$/) &&
      request.method === "PUT"
    ) {
      const admin = await requireAdmin(request);

      if (admin instanceof Response) {
        return admin;
      }

      const id = Number(
        url.pathname.split("/")[3]
      );

      try {
        const body = await request.json().catch(() => ({}));

        const existing = await env.DB.prepare(`
          SELECT id
          FROM blocked_users
          WHERE user_id = ?
            AND blocked_by = ?
          LIMIT 1
        `)
          .bind(
            id,
            Number(admin.user_id)
          )
          .first();

        if (existing) {
          await env.DB.prepare(`
            DELETE FROM blocked_users
            WHERE user_id = ?
              AND blocked_by = ?
          `)
            .bind(
              id,
              Number(admin.user_id)
            )
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
            id,
            Number(admin.user_id),
            text(body.reason)
          )
          .run();

        return json({
          success: true,
          blocked: true
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ADMIN - BLOCK LISTING
    ========================================================= */

    if (
      url.pathname.match(/^\/api\/products\/\d+\/block$/) &&
      request.method === "PUT"
    ) {
      const admin = await requireAdmin(request);

      if (admin instanceof Response) {
        return admin;
      }

      const id = Number(
        url.pathname.split("/")[3]
      );

      try {
        const body = await request.json().catch(() => ({}));

        const existing = await env.DB.prepare(`
          SELECT id
          FROM blocked_listings
          WHERE product_id = ?
            AND blocked_by = ?
          LIMIT 1
        `)
          .bind(
            id,
            Number(admin.user_id)
          )
          .first();

        if (existing) {
          await env.DB.prepare(`
            DELETE FROM blocked_listings
            WHERE product_id = ?
              AND blocked_by = ?
          `)
            .bind(
              id,
              Number(admin.user_id)
            )
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
            id,
            Number(admin.user_id),
            text(body.reason)
          )
          .run();

        return json({
          success: true,
          blocked: true
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ADMIN - SETTINGS
    ========================================================= */

    if (
      url.pathname === "/api/admin/settings" &&
      request.method === "GET"
    ) {
      const admin = await requireAdmin(request);

      if (admin instanceof Response) {
        return admin;
      }

      const { results } = await env.DB.prepare(`
        SELECT setting_key, setting_value
        FROM marketplace_settings
        ORDER BY setting_key
      `).all();

      const settings = {};

      for (const row of results) {
        settings[row.setting_key] = row.setting_value;
      }

      return json({
        success: true,
        settings
      });
    }

    if (
      url.pathname === "/api/admin/settings" &&
      request.method === "PUT"
    ) {
      const admin = await requireAdmin(request);

      if (admin instanceof Response) {
        return admin;
      }

      try {
        const body = await request.json();

        for (const [key, value] of Object.entries(body)) {
          await env.DB.prepare(`
            INSERT INTO marketplace_settings
              (setting_key, setting_value)
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
          success: true
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ADMIN - STATS
    ========================================================= */

    if (
      url.pathname === "/api/admin/stats" &&
      request.method === "GET"
    ) {
      const admin = await requireAdmin(request);

      if (admin instanceof Response) {
        return admin;
      }

      try {
        const users = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM users
        `).first();

        const products = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM products
        `).first();

        const orders = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM orders
        `).first();

        const sellers = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM auth_accounts
          WHERE role = 'seller'
        `).first();

        return json({
          success: true,
          stats: {
            users: Number(users?.count || 0),
            products: Number(products?.count || 0),
            orders: Number(orders?.count || 0),
            sellers: Number(sellers?.count || 0)
          }
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ORDERS - CREATE
    ========================================================= */

    if (
      url.pathname === "/api/orders" &&
      request.method === "POST"
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      try {
        const body = await request.json();

        const customerName =
          text(body.customer_name);

        const customerPhone =
          text(body.customer_phone);

        const customerCity =
          text(body.customer_city);

        const customerAddress =
          text(body.customer_address);

        const items =
          Array.isArray(body.items)
            ? body.items
            : [];

        if (!customerName) {
          return json({
            success: false,
            error: "Emri është i detyrueshëm."
          }, 400);
        }

        if (!customerPhone) {
          return json({
            success: false,
            error: "Telefoni është i detyrueshëm."
          }, 400);
        }

        if (!customerCity) {
          return json({
            success: false,
            error: "Qyteti është i detyrueshëm."
          }, 400);
        }

        if (!customerAddress) {
          return json({
            success: false,
            error: "Adresa është e detyrueshme."
          }, 400);
        }

        if (!items.length) {
          return json({
            success: false,
            error: "Shporta është bosh."
          }, 400);
        }

        const quantities = new Map();

        for (const item of items) {
          const id = Number(item.id);
          const qty = Math.floor(
            Number(item.qty || 1)
          );

          if (
            Number.isInteger(id) &&
            Number.isInteger(qty) &&
            qty > 0
          ) {
            quantities.set(
              id,
              (quantities.get(id) || 0) + qty
            );
          }
        }

        if (!quantities.size) {
          return json({
            success: false,
            error: "Produktet nuk janë të vlefshme."
          }, 400);
        }

        const orderCode =
          "SABI-" +
          Date.now().toString(36).toUpperCase() +
          "-" +
          crypto
            .getRandomValues(new Uint8Array(3))
            .map(x => x.toString(16).padStart(2, "0"))
            .join("")
            .toUpperCase();

        const statements = [];

        let grandTotal = 0;

        for (const [productId, quantity] of quantities) {
          const product = await env.DB.prepare(`
            SELECT
              id,
              title,
              price,
              stock
            FROM products
            WHERE id = ?
            LIMIT 1
          `)
            .bind(productId)
            .first();

          if (!product) {
            return json({
              success: false,
              error: `Produkti ${productId} nuk ekziston.`
            }, 404);
          }

          const stock = Number(
            product.stock ?? 0
          );

          if (stock < quantity) {
            return json({
              success: false,
              error:
                `Nuk ka stok të mjaftueshëm për "${product.title}".`
            }, 400);
          }

          const total =
            Number(product.price || 0) *
            quantity;

          grandTotal += total;

          statements.push(
            env.DB.prepare(`
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
          );

          statements.push(
            env.DB.prepare(`
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
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `)
              .bind(
                productId,
                Number(auth.user_id),
                quantity,
                total,
                "pending",
                customerName,
                customerPhone,
                customerCity,
                customerAddress,
                "cash_on_delivery",
                orderCode
              )
          );
        }

        await env.DB.batch(statements);

        const { results } = await env.DB.prepare(`
          SELECT *
          FROM orders
          WHERE order_code = ?
          ORDER BY id ASC
        `)
          .bind(orderCode)
          .all();

        return json({
          success: true,
          message: "Porosia u regjistrua me sukses.",
          order_code: orderCode,
          payment_method: "cash_on_delivery",
          status: "pending",
          total: grandTotal,
          orders: results
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ORDERS - GET
    ========================================================= */

    if (
      url.pathname === "/api/orders" &&
      request.method === "GET"
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      try {
        let query = `
          SELECT
            o.*,
            p.title AS product_name,
            p.image_url AS product_image,
            p.seller_id,
            u.name AS buyer_name,
            u.email AS buyer_email
          FROM orders o
          LEFT JOIN products p
            ON p.id = o.product_id
          LEFT JOIN users u
            ON u.id = o.buyer_id
        `;

        const params = [];

        if (auth.role !== "admin") {
          query += `
            WHERE
              o.buyer_id = ?
              OR p.seller_id = ?
          `;

          params.push(
            Number(auth.user_id),
            Number(auth.user_id)
          );
        }

        query += `
          ORDER BY o.id DESC
        `;

        const statement = env.DB.prepare(query);

        const { results } =
          params.length
            ? await statement.bind(...params).all()
            : await statement.all();

        return json(results);

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       UPDATE ORDER
    ========================================================= */

    if (
      url.pathname.startsWith("/api/orders/") &&
      request.method === "PUT"
    ) {
      const auth = await requireAuth(request);

      if (auth instanceof Response) {
        return auth;
      }

      const id = Number(
        url.pathname.split("/").pop()
      );

      if (!Number.isInteger(id)) {
        return json({
          success: false,
          error: "ID i pavlefshëm."
        }, 400);
      }

      try {
        const order = await env.DB.prepare(`
          SELECT
            o.id,
            o.buyer_id,
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

        const allowed =
          auth.role === "admin" ||
          Number(order.seller_id) === Number(auth.user_id);

        if (!allowed) {
          return json({
            success: false,
            error: "Nuk ke leje."
          }, 403);
        }

        const body = await request.json();

        const statuses = [
          "pending",
          "confirmed",
          "shipped",
          "delivered",
          "cancelled"
        ];

        const status = text(
          body.status
        ).toLowerCase();

        if (!statuses.includes(status)) {
          return json({
            success: false,
            error: "Statusi nuk është i vlefshëm."
          }, 400);
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

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       LEGACY ADMIN SETUP
       Përdoret vetëm nëse vendos ADMIN_SETUP_KEY si
       Cloudflare Worker Secret.
    ========================================================= */

    if (
      url.pathname === "/api/admin/setup" &&
      request.method === "POST"
    ) {
      try {
        const setupKey =
          request.headers.get("X-Admin-Setup-Key") || "";

        if (
          !env.ADMIN_SETUP_KEY ||
          setupKey !== env.ADMIN_SETUP_KEY
        ) {
          return json({
            success: false,
            error: "Setup key e pavlefshme."
          }, 403);
        }

        const body = await request.json();

        const name =
          text(body.name || "Administrator");

        const email =
          text(
            body.email || "admin@sabi.com"
          ).toLowerCase();

        const password =
          String(body.password || "");

        if (password.length < 6) {
          return json({
            success: false,
            error:
              "Fjalëkalimi duhet të ketë të paktën 6 karaktere."
          }, 400);
        }

        let user = await env.DB.prepare(`
          SELECT id, name, email
          FROM users
          WHERE LOWER(email) = ?
          LIMIT 1
        `)
          .bind(email)
          .first();

        if (!user) {
          const result = await env.DB.prepare(`
            INSERT INTO users
              (name, email)
            VALUES (?, ?)
          `)
            .bind(name, email)
            .run();

          user = await env.DB.prepare(`
            SELECT id, name, email
            FROM users
            WHERE id = ?
          `)
            .bind(result.meta.last_row_id)
            .first();
        }

        const passwordHash =
          await hashPassword(password);

        const existing = await env.DB.prepare(`
          SELECT id
          FROM auth_accounts
          WHERE identifier = ?
          LIMIT 1
        `)
          .bind(email)
          .first();

        if (existing) {
          await env.DB.prepare(`
            UPDATE auth_accounts
            SET
              password_hash = ?,
              role = 'admin'
            WHERE identifier = ?
          `)
            .bind(
              passwordHash,
              email
            )
            .run();
        } else {
          await env.DB.prepare(`
            INSERT INTO auth_accounts
              (user_id, identifier, password_hash, role)
            VALUES (?, ?, ?, 'admin')
          `)
            .bind(
              user.id,
              email,
              passwordHash
            )
            .run();
        }

        return json({
          success: true,
          message: "Admin u krijua/përditësua.",
          email
        });

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    /* =========================================================
       ASSETS
    ========================================================= */

    return env.ASSETS.fetch(request);
  }
};
