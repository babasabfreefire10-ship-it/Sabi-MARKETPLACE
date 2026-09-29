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
    function json(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          ...corsHeaders
        }
      });
    }
    // =========================================================
    // AUTH TABLES
    // Krijohen automatikisht. Nuk prekin tabelat ekzistuese.
    // =========================================================
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
    } catch (error) {
      return json({
        success: false,
        error: "Nuk u krijuan tabelat e autentikimit: " + error.message
      }, 500);
    }
    // =========================================================
    // CATEGORY
    // =========================================================
    function categoryToUI(category) {
      const map = {
        "Electronics": "Elektronikë",
        "Accessories": "Aksesorë",
        "Fashion": "Fashion",
        "Shoes": "Këpucë",
        "Home": "Të tjera",
        "Other": "Të tjera",
        "Të tjera": "Të tjera",
        "Elektronikë": "Elektronikë",
        "Këpucë": "Këpucë",
        "Aksesorë": "Aksesorë"
      };
      return map[category] || category || "Të tjera";
    }
    function categoryToDB(category) {
      const map = {
        "Elektronikë": "Electronics",
        "Aksesorë": "Accessories",
        "Këpucë": "Shoes",
        "Fashion": "Fashion",
        "Të tjera": "Other"
      };
      return map[category] || category || "Other";
    }
    // =========================================================
    // PASSWORD HASH
    // =========================================================
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
        const saltHex = parts[2];
        const expectedHex = parts[3];
        const salt = new Uint8Array(
          saltHex.match(/.{1,2}/g).map(
            byte => parseInt(byte, 16)
          )
        );
        const encoder = new TextEncoder();
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
            iterations,
            hash: "SHA-256"
          },
          key,
          256
        );
        const actualHex = [...new Uint8Array(bits)]
          .map(b => b.toString(16).padStart(2, "0"))
          .join("");
        return actualHex === expectedHex;
      } catch {
        return false;
      }
    }
    // =========================================================
    // TOKEN
    // =========================================================
    function createToken() {
      const bytes = crypto.getRandomValues(
        new Uint8Array(32)
      );
      return [...bytes]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    }
    async function getAuthUser(request) {
      const auth =
        request.headers.get("Authorization") || "";
      if (!auth.startsWith("Bearer ")) {
        return null;
      }
      const token =
        auth.slice(7).trim();
      if (!token) {
        return null;
      }
      const session =
        await env.DB.prepare(`
          SELECT
            s.user_id,
            s.expires_at,
            u.id,
            u.name,
            u.email,
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
      if (!session) {
        return null;
      }
      if (
        new Date(session.expires_at).getTime()
        < Date.now()
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
      const user =
        await getAuthUser(request);
      if (!user) {
        return json({
          success: false,
          error: "Duhet të identifikohesh."
        }, 401);
      }
      return user;
    }
    // =========================================================
    // REGISTER
    // =========================================================
    if (
      url.pathname === "/api/auth/register" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();
        const name =
          String(body.name || "").trim();
        const identifier =
          String(
            body.identifier ||
            body.email ||
            body.phone ||
            ""
          )
          .trim()
          .toLowerCase();
        const password =
          String(body.password || "");
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
            error:
              "Fjalëkalimi duhet të ketë të paktën 6 karaktere."
          }, 400);
        }
        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM auth_accounts
            WHERE identifier = ?
            LIMIT 1
          `)
          .bind(identifier)
          .first();
        if (existing) {
          return json({
            success: false,
            error: "Kjo llogari ekziston."
          }, 409);
        }
        // users.email është NOT NULL.
        // Për telefon përdorim një adresë teknike unike.
        const email =
          identifier.includes("@")
            ? identifier
            : `${identifier}@phone.sabi.local`;
        const existingUser =
          await env.DB.prepare(`
            SELECT id, name, email
            FROM users
            WHERE LOWER(email) = ?
            LIMIT 1
          `)
          .bind(email)
          .first();
        let user;
        if (existingUser) {
          user = existingUser;
        } else {
          const userResult =
            await env.DB.prepare(`
              INSERT INTO users
                (name, email)
              VALUES (?, ?)
            `)
            .bind(name, email)
            .run();
          user =
            await env.DB.prepare(`
              SELECT id, name, email
              FROM users
              WHERE id = ?
            `)
            .bind(userResult.meta.last_row_id)
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
    // =========================================================
    // LOGIN
    // =========================================================
    if (
      url.pathname === "/api/auth/login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();
        const identifier =
          String(body.identifier || "")
            .trim()
            .toLowerCase();
        const password =
          String(body.password || "");
        const requestedRole =
          body.role === "seller"
            ? "seller"
            : "customer";
        if (!identifier || !password) {
          return json({
            success: false,
            error:
              "Plotëso kontaktin dhe fjalëkalimin."
          }, 400);
        }
        const account =
          await env.DB.prepare(`
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
            error:
              "Emaili/telefoni ose fjalëkalimi është i gabuar."
          }, 401);
        }
        const valid =
          await verifyPassword(
            password,
            account.password_hash
          );
        if (!valid) {
          return json({
            success: false,
            error:
              "Emaili/telefoni ose fjalëkalimi është i gabuar."
          }, 401);
        }
        if (
          account.role !== requestedRole
        ) {
          return json({
            success: false,
            error:
              requestedRole === "seller"
                ? "Kjo llogari nuk është llogari shitësi."
                : "Kjo llogari nuk është llogari klienti."
          }, 403);
        }
        const token =
          createToken();
        const expires =
          new Date(
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
    // =========================================================
    // CURRENT USER
    // =========================================================
    if (
      url.pathname === "/api/auth/me" &&
      request.method === "GET"
    ) {
      try {
        const user =
          await getAuthUser(request);
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
            role: user.role
          }
        });
      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }
    // =========================================================
    // LOGOUT
    // =========================================================
    if (
      url.pathname === "/api/auth/logout" &&
      request.method === "POST"
    ) {
      try {
        const auth =
          request.headers.get("Authorization") || "";
        if (auth.startsWith("Bearer ")) {
          const token =
            auth.slice(7).trim();
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
      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }
    // =========================================================
    // GET PRODUCTS
    // =========================================================
    if (
      url.pathname === "/api/products" &&
      request.method === "GET"
    ) {
      try {
        const { results } =
          await env.DB.prepare(`
            SELECT
              p.id,
              p.title,
              p.description,
              p.price,
              p.image_url,
              p.seller_id,
              p.category,
              p.stock,
              p.created_at,
              u.name AS seller_name,
              u.email AS seller_email
            FROM products p
            LEFT JOIN users u
              ON u.id = p.seller_id
            ORDER BY p.id DESC
          `)
          .all();
        const products =
          results.map(p => ({
            id: p.id,
            name: p.title,
            title: p.title,
            description: p.description || "",
            price: Number(p.price || 0),
            image: p.image_url || "",
            image_url: p.image_url || "",
            seller_id: p.seller_id,
            seller: p.seller_name || "SABI",
            sellerName: p.seller_name || "SABI",
            sellerPhone: "",
            sellerEmail: p.seller_email || "",
            category: categoryToUI(p.category),
            stock: Number(p.stock ?? 0),
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
    // =========================================================
    // CREATE USER - LEGACY
    // =========================================================
    if (
      url.pathname === "/api/users" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();
        const name =
          String(body.name || "").trim();
        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();
        if (!name || !email) {
          return json({
            success: false,
            error:
              "Emri dhe email janë të detyrueshëm."
          }, 400);
        }
        const existing =
          await env.DB.prepare(`
            SELECT id, name, email
            FROM users
            WHERE email = ?
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
        const result =
          await env.DB.prepare(`
            INSERT INTO users
              (name, email)
            VALUES (?, ?)
          `)
          .bind(name, email)
          .run();
        const user =
          await env.DB.prepare(`
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
    // =========================================================
    // FIND USER
    // =========================================================
    if (
      url.pathname === "/api/users/find" &&
      request.method === "GET"
    ) {
      try {
        const email =
          String(
            url.searchParams.get("email") || ""
          )
          .trim()
          .toLowerCase();
        if (!email) {
          return json({
            success: false,
            error: "Email mungon."
          }, 400);
        }
        const user =
          await env.DB.prepare(`
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
      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }
    // =========================================================
    // CREATE PRODUCT
    // =========================================================
    if (
      url.pathname === "/api/products" &&
      request.method === "POST"
    ) {
      try {
        const auth =
          await requireAuth(request);
        if (auth instanceof Response) {
          return auth;
        }
        if (
          auth.role !== "seller" &&
          auth.role !== "admin"
        ) {
          return json({
            success: false,
            error:
              "Vetëm shitësi mund të shtojë produkte."
          }, 403);
        }
        const body =
          await request.json();
        const title =
          String(
            body.title ||
            body.name ||
            ""
          ).trim();
        const description =
          String(body.description || "");
        const price =
          Number(body.price || 0);
        const imageUrl =
          String(
            body.image_url ||
            body.image ||
            ""
          ).trim();
        const category =
          categoryToDB(body.category);
        const stock =
          Math.max(
            0,
            Number.isFinite(Number(body.stock))
              ? Number(body.stock)
              : 1
          );
        // Për siguri, produkti i shitësit lidhet
        // me user-in e sesionit.
        const sellerId =
          Number(auth.user_id);
        if (!title) {
          return json({
            success: false,
            error:
              "Emri i produktit mungon."
          }, 400);
        }
        if (
          !Number.isFinite(price) ||
          price <= 0
        ) {
          return json({
            success: false,
            error:
              "Çmimi nuk është i vlefshëm."
          }, 400);
        }
        const result =
          await env.DB.prepare(`
            INSERT INTO products
            (
              title,
              description,
              price,
              image_url,
              seller_id,
              category,
              stock
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `)
          .bind(
            title,
            description,
            price,
            imageUrl,
            sellerId,
            category,
            stock
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
    // =========================================================
    // UPDATE PRODUCT
    // =========================================================
    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "PUT"
    ) {
      try {
        const auth =
          await requireAuth(request);
        if (auth instanceof Response) {
          return auth;
        }
        const id =
          Number(
            url.pathname.split("/").pop()
          );
        if (!Number.isInteger(id)) {
          return json({
            success: false,
            error: "ID i pavlefshëm."
          }, 400);
        }
        const product =
          await env.DB.prepare(`
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
        const owner =
          Number(product.seller_id) ===
          Number(auth.user_id);
        if (
          auth.role !== "admin" &&
          !owner
        ) {
          return json({
            success: false,
            error:
              "Nuk ke leje të ndryshosh këtë produkt."
          }, 403);
        }
        const body =
          await request.json();
        const title =
          String(
            body.title ||
            body.name ||
            ""
          ).trim();
        const description =
          String(body.description || "");
        const price =
          Number(body.price || 0);
        const imageUrl =
          String(
            body.image_url ||
            body.image ||
            ""
          ).trim();
        const category =
          categoryToDB(body.category);
        const stock =
          Math.max(
            0,
            Number(body.stock ?? 0)
          );
        if (!title) {
          return json({
            success: false,
            error:
              "Emri i produktit mungon."
          }, 400);
        }
        if (
          !Number.isFinite(price) ||
          price <= 0
        ) {
          return json({
            success: false,
            error:
              "Çmimi nuk është i vlefshëm."
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
            stock = ?
          WHERE id = ?
        `)
        .bind(
          title,
          description,
          price,
          imageUrl,
          category,
          stock,
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
    // =========================================================
    // DELETE PRODUCT
    // =========================================================
    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "DELETE"
    ) {
      try {
        const auth =
          await requireAuth(request);
        if (auth instanceof Response) {
          return auth;
        }
        const id =
          Number(
            url.pathname.split("/").pop()
          );
        if (!Number.isInteger(id)) {
          return json({
            success: false,
            error: "ID i pavlefshëm."
          }, 400);
        }
        const product =
          await env.DB.prepare(`
            SELECT seller_id
            FROM products
            WHERE id = ?
          `)
          .bind(id)
          .first();
        if (!product) {
          return json({
            success: false,
            error:
              "Produkti nuk ekziston."
          }, 404);
        }
        const owner =
          Number(product.seller_id) ===
          Number(auth.user_id);
        if (
          auth.role !== "admin" &&
          !owner
        ) {
          return json({
            success: false,
            error:
              "Nuk ke leje të fshish këtë produkt."
          }, 403);
        }
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
    // =========================================================
    // CREATE ORDERS
    // =========================================================
    if (
      url.pathname === "/api/orders" &&
      request.method === "POST"
    ) {
      try {
        const auth =
          await requireAuth(request);
        if (auth instanceof Response) {
          return auth;
        }
        const body =
          await request.json();
        const buyerId =
          Number(auth.user_id);
        const items =
          Array.isArray(body.items)
            ? body.items
            : [];
        if (!items.length) {
          return json({
            success: false,
            error:
              "Shporta është bosh."
          }, 400);
        }
        const created = [];
        for (const item of items) {
          const productId =
            Number(item.id);
          const quantity =
            Math.max(
              1,
              Number(item.qty || 1)
            );
          if (!Number.isInteger(productId)) {
            continue;
          }
          const product =
            await env.DB.prepare(`
              SELECT
                id,
                price,
                stock
              FROM products
              WHERE id = ?
            `)
            .bind(productId)
            .first();
          if (!product) {
            continue;
          }
          if (
            Number(product.stock) <
            quantity
          ) {
            return json({
              success: false,
              error:
                "Nuk ka stok të mjaftueshëm për produktin ID " +
                productId
            }, 400);
          }
          const totalPrice =
            Number(product.price) *
            quantity;
          const result =
            await env.DB.prepare(`
              INSERT INTO orders
              (
                product_id,
                buyer_id,
                quantity,
                total_price,
                status
              )
              VALUES (?, ?, ?, ?, ?)
            `)
            .bind(
              productId,
              buyerId,
              quantity,
              totalPrice,
              "pending"
            )
            .run();
          await env.DB.prepare(`
            UPDATE products
            SET stock = stock - ?
            WHERE id = ?
          `)
          .bind(
            quantity,
            productId
          )
          .run();
          created.push({
            id: result.meta.last_row_id,
            product_id: productId,
            quantity,
            total_price: totalPrice
          });
        }
        return json({
          success: true,
          orders: created
        });
      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }
    // =========================================================
    // GET ORDERS
    // =========================================================
    if (
      url.pathname === "/api/orders" &&
      request.method === "GET"
    ) {
      try {
        const auth =
          await requireAuth(request);
        if (auth instanceof Response) {
          return auth;
        }
        let query = `
          SELECT
            o.id,
            o.product_id,
            o.buyer_id,
            o.quantity,
            o.total_price,
            o.status,
            o.created_at,
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
        if (
          auth.role !== "admin"
        ) {
          query += `
            WHERE p.seller_id = ?
          `;
          params.push(
            Number(auth.user_id)
          );
        }
        query += `
          ORDER BY o.id DESC
        `;
        const statement =
          env.DB.prepare(query);
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
    // =========================================================
    // UPDATE ORDER STATUS
    // =========================================================
    if (
      url.pathname.startsWith("/api/orders/") &&
      request.method === "PUT"
    ) {
      try {
        const auth =
          await requireAuth(request);
        if (auth instanceof Response) {
          return auth;
        }
        const id =
          Number(
            url.pathname.split("/").pop()
          );
        if (!Number.isInteger(id)) {
          return json({
            success: false,
            error: "ID i pavlefshëm."
          }, 400);
        }
        const order =
          await env.DB.prepare(`
            SELECT
              o.id,
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
            error:
              "Porosia nuk ekziston."
          }, 404);
        }
        if (
          auth.role !== "admin" &&
          Number(order.seller_id) !==
          Number(auth.user_id)
        ) {
          return json({
            success: false,
            error:
              "Nuk ke leje të ndryshosh këtë porosi."
          }, 403);
        }
        const body =
          await request.json();
        const status =
          String(
            body.status || "pending"
          );
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
      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }
    // =========================================================
    // ASSETS
    // =========================================================
    return env.ASSETS.fetch(request);
  }
};
