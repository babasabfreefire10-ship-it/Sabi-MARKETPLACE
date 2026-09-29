export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // CORS
    // =========================

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // =========================
    // RESPONSE HELPER
    // =========================

    function json(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          ...corsHeaders
        }
      });
    }

    // =========================
    // CATEGORY MAP
    // =========================

    function categoryToUI(category) {
      const map = {
        "Electronics": "Elektronikë",
        "Accessories": "Aksesorë",
        "Fashion": "Fashion",
        "Shoes": "Këpucë",
        "Home": "Të tjera",
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

    // =========================
    // GET PRODUCTS
    // =========================

    if (
      url.pathname === "/api/products" &&
      request.method === "GET"
    ) {
      try {
        const { results } = await env.DB
          .prepare(`
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

        const products = results.map(p => ({
          id: p.id,

          name: p.title,

          title: p.title,

          description: p.description || "",

          price: Number(p.price || 0),

          image: p.image_url || "",

          image_url: p.image_url || "",

          seller_id: p.seller_id,

          seller:
            p.seller_name ||
            "SABI",

          sellerName:
            p.seller_name ||
            "SABI",

          sellerPhone: "",

          sellerEmail:
            p.seller_email || "",

          category:
            categoryToUI(p.category),

          stock:
            Number(p.stock ?? 0),

          created_at:
            p.created_at
        }));

        return json(products);

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    // =========================
    // CREATE USER
    // =========================

    if (
      url.pathname === "/api/users" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const name =
          String(body.name || "").trim();

        const email =
          String(body.email || "").trim().toLowerCase();

        if (!name || !email) {
          return json({
            success: false,
            error: "Emri dhe email janë të detyrueshëm."
          }, 400);
        }

        const existing = await env.DB
          .prepare(`
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

        const result = await env.DB
          .prepare(`
            INSERT INTO users
              (name, email)
            VALUES (?, ?)
          `)
          .bind(name, email)
          .run();

        const user = await env.DB
          .prepare(`
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

    // =========================
    // FIND USER
    // =========================

    if (
      url.pathname === "/api/users/find" &&
      request.method === "GET"
    ) {
      try {
        const email =
          String(url.searchParams.get("email") || "")
            .trim()
            .toLowerCase();

        if (!email) {
          return json({
            success: false,
            error: "Email mungon."
          }, 400);
        }

        const user = await env.DB
          .prepare(`
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

    // =========================
    // CREATE PRODUCT
    // =========================

    if (
      url.pathname === "/api/products" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

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

        let sellerId =
          body.seller_id == null ||
          body.seller_id === ""
            ? null
            : Number(body.seller_id);

        if (!title) {
          return json({
            success: false,
            error: "Emri i produktit mungon."
          }, 400);
        }

        if (!Number.isFinite(price) || price <= 0) {
          return json({
            success: false,
            error: "Çmimi nuk është i vlefshëm."
          }, 400);
        }

        if (sellerId !== null) {
          const user = await env.DB
            .prepare(`
              SELECT id
              FROM users
              WHERE id = ?
            `)
            .bind(sellerId)
            .first();

          if (!user) {
            sellerId = null;
          }
        }

        const result = await env.DB
          .prepare(`
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

    // =========================
    // UPDATE PRODUCT
    // =========================

    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "PUT"
    ) {
      try {
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

        const body = await request.json();

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

        const sellerId =
          body.seller_id == null ||
          body.seller_id === ""
            ? null
            : Number(body.seller_id);

        await env.DB
          .prepare(`
            UPDATE products
            SET
              title = ?,
              description = ?,
              price = ?,
              image_url = ?,
              seller_id = ?,
              category = ?,
              stock = ?
            WHERE id = ?
          `)
          .bind(
            title,
            description,
            price,
            imageUrl,
            sellerId,
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

    // =========================
    // DELETE PRODUCT
    // =========================

    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "DELETE"
    ) {
      try {
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

        await env.DB
          .prepare(`
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

    // =========================
    // CREATE ORDERS
    // =========================

    if (
      url.pathname === "/api/orders" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const buyerId =
          body.buyer_id == null ||
          body.buyer_id === ""
            ? null
            : Number(body.buyer_id);

        const items =
          Array.isArray(body.items)
            ? body.items
            : [];

        if (!items.length) {
          return json({
            success: false,
            error: "Shporta është bosh."
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

          const product = await env.DB
            .prepare(`
              SELECT id, price, stock
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
            await env.DB
              .prepare(`
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

          await env.DB
            .prepare(`
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

    // =========================
    // GET ORDERS
    // =========================

    if (
      url.pathname === "/api/orders" &&
      request.method === "GET"
    ) {
      try {
        const { results } = await env.DB
          .prepare(`
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

              u.name AS buyer_name,
              u.email AS buyer_email

            FROM orders o

            LEFT JOIN products p
              ON p.id = o.product_id

            LEFT JOIN users u
              ON u.id = o.buyer_id

            ORDER BY o.id DESC
          `)
          .all();

        return json(results);

      } catch (error) {
        return json({
          success: false,
          error: error.message
        }, 500);
      }
    }

    // =========================
    // UPDATE ORDER STATUS
    // =========================

    if (
      url.pathname.startsWith("/api/orders/") &&
      request.method === "PUT"
    ) {
      try {
        const id =
          Number(
            url.pathname.split("/").pop()
          );

        const body =
          await request.json();

        const status =
          String(
            body.status || "pending"
          );

        await env.DB
          .prepare(`
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

    // =========================
    // ASSETS
    // =========================

    return env.ASSETS.fetch(request);
  }
};
