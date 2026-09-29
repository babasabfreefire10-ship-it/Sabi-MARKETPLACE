export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // API: GET PRODUCTS
    // =========================
    if (url.pathname === "/api/products" && request.method === "GET") {
      try {
        const { results } = await env.DB
          .prepare("SELECT * FROM products ORDER BY created_at DESC")
          .all();

        return Response.json(results);
      } catch (error) {
        return Response.json(
          {
            error: "Database error",
            message: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // API: ADD PRODUCT
    // =========================
    if (url.pathname === "/api/products" && request.method === "POST") {
      try {
        const product = await request.json();

        const id = crypto.randomUUID();

        await env.DB.prepare(`
          INSERT INTO products
          (
            id,
            name,
            price,
            category,
            seller,
            seller_name,
            seller_phone,
            image,
            description
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
          .bind(
            id,
            product.name || "",
            Number(product.price) || 0,
            product.category || "Të tjera",
            product.seller || "",
            product.seller_name || "",
            product.seller_phone || "",
            product.image || "",
            product.description || ""
          )
          .run();

        return Response.json({
          success: true,
          id
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
    // API: DELETE PRODUCT
    // =========================
    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "DELETE"
    ) {
      try {
        const id = url.pathname.split("/").pop();

        await env.DB
          .prepare("DELETE FROM products WHERE id = ?")
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
    // API: UPDATE PRODUCT
    // =========================
    if (
      url.pathname.startsWith("/api/products/") &&
      request.method === "PUT"
    ) {
      try {
        const id = url.pathname.split("/").pop();
        const product = await request.json();

        await env.DB.prepare(`
          UPDATE products
          SET
            name = ?,
            price = ?,
            category = ?,
            seller = ?,
            seller_name = ?,
            seller_phone = ?,
            image = ?,
            description = ?
          WHERE id = ?
        `)
          .bind(
            product.name || "",
            Number(product.price) || 0,
            product.category || "Të tjera",
            product.seller || "",
            product.seller_name || "",
            product.seller_phone || "",
            product.image || "",
            product.description || "",
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
    // WEBSITE
    // =========================
    return env.ASSETS.fetch(request);
  }
};
