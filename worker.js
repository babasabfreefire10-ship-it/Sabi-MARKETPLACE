export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // GET PRODUCTS
    // =========================
    if (url.pathname === "/api/products" && request.method === "GET") {
      try {
        const { results } = await env.DB.prepare(`
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
          LEFT JOIN users u ON u.id = p.seller_id
          ORDER BY p.created_at DESC
        `).all();

        return Response.json(results);
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // GET ONE PRODUCT
    // =========================
    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "GET"
    ) {
      try {
        const id = url.pathname.split("/").pop();

        const product = await env.DB.prepare(`
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
          LEFT JOIN users u ON u.id = p.seller_id
          WHERE p.id = ?
        `)
          .bind(id)
          .first();

        if (!product) {
          return Response.json(
            { success: false, error: "Produkti nuk u gjet." },
            { status: 404 }
          );
        }

        return Response.json(product);
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // ADD PRODUCT
    // =========================
    if (url.pathname === "/api/products" && request.method === "POST") {
      try {
        const product = await request.json();

        const title = String(
          product.title || product.name || ""
        ).trim();

        const description = String(
          product.description || ""
        ).trim();

        const price = Number(product.price || 0);

        const image_url = String(
          product.image_url || product.image || ""
        ).trim();

        const category = String(
          product.category || "Të tjera"
        ).trim();

        const seller_id = Number(
          product.seller_id || 0
        );

        const stock = Number(
          product.stock ?? 1
        );

        if (!title) {
          return Response.json(
            {
              success: false,
              error: "Emri i produktit mungon."
            },
            { status: 400 }
          );
        }

        if (!price || price < 0) {
          return Response.json(
            {
              success: false,
              error: "Çmimi nuk është i vlefshëm."
            },
            { status: 400 }
          );
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
            stock
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
          .bind(
            title,
            description,
            price,
            image_url,
            seller_id || null,
            category,
            stock
          )
          .run();

        return Response.json({
          success: true,
          id: result.meta.last_row_id
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
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
        const id = url.pathname.split("/").pop();
        const product = await request.json();

        const title = String(
          product.title || product.name || ""
        ).trim();

        const description = String(
          product.description || ""
        ).trim();

        const price = Number(product.price || 0);

        const image_url = String(
          product.image_url || product.image || ""
        ).trim();

        const category = String(
          product.category || "Të tjera"
        ).trim();

        const seller_id = Number(
          product.seller_id || 0
        );

        const stock = Number(
          product.stock ?? 1
        );

        await env.DB.prepare(`
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
            image_url,
            seller_id || null,
            category,
            stock,
            id
          )
          .run();

        return Response.json({
          success: true
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
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
        const id = url.pathname.split("/").pop();

        await env.DB.prepare(`
          DELETE FROM products
          WHERE id = ?
        `)
          .bind(id)
          .run();

        return Response.json({
          success: true
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // GET USERS
    // =========================
    if (url.pathname === "/api/users" && request.method === "GET") {
      try {
        const { results } = await env.DB.prepare(`
          SELECT id, name, email, created_at
          FROM users
          ORDER BY created_at DESC
        `).all();

        return Response.json(results);
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // GET ORDERS
    // =========================
    if (url.pathname === "/api/orders" && request.method === "GET") {
      try {
        const { results } = await env.DB.prepare(`
          SELECT
            o.id,
            o.product_id,
            o.buyer_id,
            o.quantity,
            o.total_price,
            o.status,
            o.created_at,

            p.title AS product_title,
            p.image_url,
            p.seller_id,

            u.name AS buyer_name,
            u.email AS buyer_email

          FROM orders o

          LEFT JOIN products p
            ON p.id = o.product_id

          LEFT JOIN users u
            ON u.id = o.buyer_id

          ORDER BY o.created_at DESC
        `).all();

        return Response.json(results);
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // CREATE ORDER
    // =========================
    if (url.pathname === "/api/orders" && request.method === "POST") {
      try {
        const order = await request.json();

        const product_id = Number(
          order.product_id || 0
        );

        const buyer_id = Number(
          order.buyer_id || 0
        );

        const quantity = Math.max(
          1,
          Number(order.quantity || 1)
        );

        const total_price = Number(
          order.total_price || 0
        );

        if (!product_id) {
          return Response.json(
            {
              success: false,
              error: "Produkti mungon."
            },
            { status: 400 }
          );
        }

        if (!total_price || total_price < 0) {
          return Response.json(
            {
              success: false,
              error: "Totali nuk është i vlefshëm."
            },
            { status: 400 }
          );
        }

        const result = await env.DB.prepare(`
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
            product_id,
            buyer_id || null,
            quantity,
            total_price,
            "pending"
          )
          .run();

        return Response.json({
          success: true,
          id: result.meta.last_row_id
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
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
        const id = url.pathname.split("/").pop();
        const data = await request.json();

        const status = String(
          data.status || "pending"
        ).trim();

        await env.DB.prepare(`
          UPDATE orders
          SET status = ?
          WHERE id = ?
        `)
          .bind(status, id)
          .run();

        return Response.json({
          success: true
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // WEBSITE FILES
    // =========================
    return env.ASSETS.fetch(request);
  }
};
