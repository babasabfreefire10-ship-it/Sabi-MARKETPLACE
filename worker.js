const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Auth-Token",
  "Access-Control-Max-Age": "86400"
};

let DB_READY = false;
let DB_SETUP_PROMISE = null;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS,
      "Content-Type": "application/json; charset=utf-8"
    }
  });

const fail = (error, status = 400) =>
  json({ success: false, error: String(error) }, status);

const ok = (data = {}, status = 200) =>
  json({ success: true, ...data }, status);

const num = (v, fallback = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};

const clean = (v, max = 5000) =>
  String(v ?? "").trim().slice(0, max);

const boolInt = v =>
  v === true || v === 1 || v === "1" || v === "true" ? 1 : 0;

const isAdmin = user =>
  !!user && ["admin", "owner"].includes(String(user.role).toLowerCase());

const sqlNow = () => new Date().toISOString().slice(0, 19).replace("T", " ");

const addDays = days => {
  const d = new Date();
  d.setTime(d.getTime() + days * 86400000);
  return d.toISOString().slice(0, 19).replace("T", " ");
};

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function randomToken(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return Array.from(a, b => b.toString(16).padStart(2, "0")).join("");
}

async function passwordHash(password) {
  const data = new TextEncoder().encode(String(password));
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

async function addColumn(env, table, name, definition) {
  const allowedTables = new Set([
    "auth_accounts",
    "products",
    "orders",
    "platform_settings",
    "promotions",
    "transactions"
  ]);

  if (!allowedTables.has(table)) throw new Error("Tabela e palejuar");
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw new Error("Emër kolone i pavlefshëm");
  }

  try {
    await env.DB.prepare(
      `ALTER TABLE "${table}" ADD COLUMN "${name}" ${definition}`
    ).run();
  } catch (e) {
    if (!/duplicate column|already exists/i.test(e.message || "")) {
      throw e;
    }
  }
}

async function setupDatabase(env) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS auth_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT DEFAULT '',
      email TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      password_hash TEXT DEFAULT '',
      role TEXT DEFAULT 'customer',
      blocked INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,

    `CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,

    `CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL DEFAULT '',
      name TEXT DEFAULT '',
      description TEXT DEFAULT '',
      price REAL NOT NULL DEFAULT 0,
      image_url TEXT DEFAULT '',
      image TEXT DEFAULT '',
      seller_id INTEGER,
      category TEXT DEFAULT 'Të tjera',
      stock INTEGER DEFAULT 0,
      city TEXT DEFAULT '',
      condition TEXT DEFAULT 'used',
      phone TEXT DEFAULT '',
      negotiable INTEGER DEFAULT 0,
      blocked INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,

    `CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_code TEXT,
      product_id INTEGER,
      buyer_id INTEGER,
      seller_id INTEGER,
      quantity INTEGER DEFAULT 1,
      total_price REAL DEFAULT 0,
      customer_name TEXT DEFAULT '',
      customer_phone TEXT DEFAULT '',
      customer_city TEXT DEFAULT '',
      customer_address TEXT DEFAULT '',
      payment_method TEXT DEFAULT 'cash_on_delivery',
      status TEXT DEFAULT 'pending',
      commission_rate REAL DEFAULT 5,
      platform_fee REAL DEFAULT 0,
      seller_earnings REAL DEFAULT 0,
      stock_restored INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,

    `CREATE TABLE IF NOT EXISTS saved_listings (
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, product_id)
    )`,

    `CREATE TABLE IF NOT EXISTS blocked_users (
      user_id INTEGER PRIMARY KEY,
      blocked INTEGER DEFAULT 1
    )`,

    `CREATE TABLE IF NOT EXISTS blocked_listings (
      product_id INTEGER PRIMARY KEY,
      blocked INTEGER DEFAULT 1
    )`,

    `CREATE TABLE IF NOT EXISTS marketplace_settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT DEFAULT ''
    )`,

    `CREATE TABLE IF NOT EXISTS promotions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      seller_id INTEGER NOT NULL,
      type TEXT DEFAULT 'promoted',
      price REAL DEFAULT 0,
      starts_at TEXT,
      ends_at TEXT,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,

    `CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      type TEXT DEFAULT '',
      amount REAL DEFAULT 0,
      currency TEXT DEFAULT 'ALL',
      status TEXT DEFAULT 'pending',
      reference_id TEXT,
      metadata TEXT DEFAULT '{}',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,

    // Kjo strukturë ruan kolonat e platform_settings që ekzistojnë.
    `CREATE TABLE IF NOT EXISTS platform_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      commission_rate REAL DEFAULT 5,
      currency TEXT DEFAULT 'ALL',
      promotion_price_1d REAL DEFAULT 100,
      promotion_price_7d REAL DEFAULT 300,
      promotion_price_30d REAL DEFAULT 700,
      vip_price_7d REAL DEFAULT 500
    )`
  ];

  for (const sql of statements) {
    await env.DB.prepare(sql).run();
  }

  const columns = {
    auth_accounts: {
      name: "TEXT DEFAULT ''",
      email: "TEXT DEFAULT ''",
      phone: "TEXT DEFAULT ''",
      password_hash: "TEXT DEFAULT ''",
      role: "TEXT DEFAULT 'customer'",
      blocked: "INTEGER DEFAULT 0",
      created_at: "TEXT"
    },
    products: {
      title: "TEXT DEFAULT ''",
      name: "TEXT DEFAULT ''",
      description: "TEXT DEFAULT ''",
      price: "REAL DEFAULT 0",
      image_url: "TEXT DEFAULT ''",
      image: "TEXT DEFAULT ''",
      seller_id: "INTEGER",
      category: "TEXT DEFAULT 'Të tjera'",
      stock: "INTEGER DEFAULT 0",
      city: "TEXT DEFAULT ''",
      condition: "TEXT DEFAULT 'used'",
      phone: "TEXT DEFAULT ''",
      negotiable: "INTEGER DEFAULT 0",
      blocked: "INTEGER DEFAULT 0",
      created_at: "TEXT"
    },
    orders: {
      order_code: "TEXT",
      product_id: "INTEGER",
      buyer_id: "INTEGER",
      seller_id: "INTEGER",
      quantity: "INTEGER DEFAULT 1",
      total_price: "REAL DEFAULT 0",
      customer_name: "TEXT DEFAULT ''",
      customer_phone: "TEXT DEFAULT ''",
      customer_city: "TEXT DEFAULT ''",
      customer_address: "TEXT DEFAULT ''",
      payment_method: "TEXT DEFAULT 'cash_on_delivery'",
      status: "TEXT DEFAULT 'pending'",
      commission_rate: "REAL DEFAULT 5",
      platform_fee: "REAL DEFAULT 0",
      seller_earnings: "REAL DEFAULT 0",
      stock_restored: "INTEGER DEFAULT 0",
      created_at: "TEXT",
      updated_at: "TEXT"
    },
    platform_settings: {
      commission_rate: "REAL DEFAULT 5",
      currency: "TEXT DEFAULT 'ALL'",
      promotion_price_1d: "REAL DEFAULT 100",
      promotion_price_7d: "REAL DEFAULT 300",
      promotion_price_30d: "REAL DEFAULT 700",
      vip_price_7d: "REAL DEFAULT 500"
    }
  };

  for (const [table, defs] of Object.entries(columns)) {
    for (const [name, definition] of Object.entries(defs)) {
      await addColumn(env, table, name, definition);
    }
  }

  await env.DB.prepare(`
    INSERT INTO platform_settings
      (commission_rate, currency, promotion_price_1d,
       promotion_price_7d, promotion_price_30d, vip_price_7d)
    SELECT 5, 'ALL', 100, 300, 700, 500
    WHERE NOT EXISTS (SELECT 1 FROM platform_settings)
  `).run();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO marketplace_settings (setting_key, setting_value)
    VALUES ('platform_name', 'SHIT.BLEJ')
  `).run();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO marketplace_settings (setting_key, setting_value)
    VALUES ('admin_email', 'admin@shitblej.al')
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id)
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id)
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id)
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_promotions_product ON promotions(product_id)
  `).run();
}

async function ensureDatabase(env) {
  if (DB_READY) return;

  if (!DB_SETUP_PROMISE) {
    DB_SETUP_PROMISE = setupDatabase(env)
      .then(() => {
        DB_READY = true;
      })
      .catch(error => {
        DB_SETUP_PROMISE = null;
        throw error;
      });
  }

  await DB_SETUP_PROMISE;
}

async function getPlatformSettings(env) {
  const row = await env.DB.prepare(`
    SELECT * FROM platform_settings ORDER BY id ASC LIMIT 1
  `).first();

  return {
    commission_rate: num(row?.commission_rate, 5),
    currency: row?.currency || "ALL",
    promo_1_day: num(row?.promotion_price_1d, 100),
    promo_7_day: num(row?.promotion_price_7d, 300),
    promo_30_day: num(row?.promotion_price_30d, 700),
    vip_7_day: num(row?.vip_price_7d, 500)
  };
}

async function getMarketplaceSetting(env, key, fallback = "") {
  const row = await env.DB.prepare(`
    SELECT setting_value
    FROM marketplace_settings
    WHERE setting_key = ?
    LIMIT 1
  `).bind(key).first();

  return row?.setting_value ?? fallback;
}

async function setMarketplaceSetting(env, key, value) {
  await env.DB.prepare(`
    INSERT INTO marketplace_settings (setting_key, setting_value)
    VALUES (?, ?)
    ON CONFLICT(setting_key)
    DO UPDATE SET setting_value = excluded.setting_value
  `).bind(key, String(value)).run();
}

function tokenFromRequest(request) {
  const auth = request.headers.get("Authorization") || "";

  if (auth.toLowerCase().startsWith("bearer ")) {
    return auth.slice(7).trim();
  }

  return request.headers.get("X-Auth-Token") || "";
}

async function currentUser(env, request) {
  const token = tokenFromRequest(request);
  if (!token) return null;

  const row = await env.DB.prepare(`
    SELECT a.id, a.name, a.email, a.phone, a.role, a.blocked,
           s.token, s.expires_at
    FROM sessions s
    JOIN auth_accounts a ON a.id = s.user_id
    WHERE s.token = ?
    LIMIT 1
  `).bind(token).first();

  if (!row || num(row.blocked) === 1) return null;

  if (row.expires_at) {
    const expires = new Date(
      String(row.expires_at).replace(" ", "T") + "Z"
    );

    if (!Number.isNaN(expires.getTime()) && expires < new Date()) {
      await env.DB.prepare("DELETE FROM sessions WHERE token = ?")
        .bind(token).run();
      return null;
    }
  }

  return {
    id: row.id,
    name: row.name || "",
    email: row.email || "",
    phone: row.phone || "",
    role: row.role || "customer"
  };
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name || "",
    email: user.email || "",
    phone: user.phone || "",
    role: user.role || "customer"
  };
}

async function createSession(env, userId) {
  const token = randomToken();
  await env.DB.prepare(`
    INSERT INTO sessions (token, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(token, userId, addDays(30)).run();

  return token;
}

async function register(env, body) {
  const name = clean(body.name || body.full_name, 120);
  const email = clean(body.email || body.identifier, 190).toLowerCase();
  const phone = clean(body.phone, 50);
  const password = String(body.password || "");
  let role = clean(body.role || "customer", 20).toLowerCase();

  if (!name || !email || !password) {
    return fail("Plotëso emrin, email-in dhe fjalëkalimin.", 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return fail("Email-i nuk është i vlefshëm.", 400);
  }

  if (password.length < 6) {
    return fail("Fjalëkalimi duhet të ketë të paktën 6 karaktere.", 400);
  }

  if (!["customer", "seller"].includes(role)) role = "customer";

  const existing = await env.DB.prepare(`
    SELECT id FROM auth_accounts WHERE lower(email) = ? LIMIT 1
  `).bind(email).first();

  if (existing) return fail("Ky email është regjistruar më parë.", 409);

  const hash = await passwordHash(password);

  const result = await env.DB.prepare(`
    INSERT INTO auth_accounts (name, email, phone, password_hash, role, blocked)
    VALUES (?, ?, ?, ?, ?, 0)
  `).bind(name, email, phone, hash, role).run();

  const id = result.meta?.last_row_id;

  if (!id) return fail("Regjistrimi nuk u krye.", 500);

  const user = { id, name, email, phone, role };
  const token = await createSession(env, id);

  return ok({ user, token }, 201);
}

async function login(env, body) {
  const identifier = clean(
    body.identifier || body.email || body.phone,
    190
  ).toLowerCase();

  const password = String(body.password || "");

  if (!identifier || !password) {
    return fail("Vendos email-in dhe fjalëkalimin.", 400);
  }

  const user = await env.DB.prepare(`
    SELECT * FROM auth_accounts
    WHERE lower(email) = ? OR phone = ?
    LIMIT 1
  `).bind(identifier, identifier).first();

  if (!user) return fail("Email ose fjalëkalim i gabuar.", 401);
  if (num(user.blocked) === 1) return fail("Llogaria është bllokuar.", 403);

  const hash = await passwordHash(password);

  if (hash !== user.password_hash) {
    return fail("Email ose fjalëkalim i gabuar.", 401);
  }

  const token = await createSession(env, user.id);

  return ok({
    token,
    user: publicUser(user)
  });
}

const PRODUCT_SELECT = `
  SELECT
    p.*,
    a.name AS account_name,
    a.email AS account_email,
    a.phone AS account_phone,
    CASE WHEN EXISTS (
      SELECT 1 FROM promotions pr
      WHERE pr.product_id = p.id
        AND pr.type != 'vip'
        AND pr.status = 'active'
        AND datetime(pr.ends_at) > datetime('now')
    ) THEN 1 ELSE 0 END AS promotion_active,
    CASE WHEN EXISTS (
      SELECT 1 FROM promotions pr
      WHERE pr.product_id = p.id
        AND pr.type = 'vip'
        AND pr.status = 'active'
        AND datetime(pr.ends_at) > datetime('now')
    ) THEN 1 ELSE 0 END AS vip_active,
    (
      SELECT MAX(pr.ends_at) FROM promotions pr
      WHERE pr.product_id = p.id
        AND pr.status = 'active'
        AND datetime(pr.ends_at) > datetime('now')
    ) AS promotion_expires_at
  FROM products p
  LEFT JOIN auth_accounts a ON a.id = p.seller_id
`;

function formatProduct(p) {
  if (!p) return null;

  const title = p.title || p.name || "";
  const image = p.image_url || p.image || "";
  const sellerName = p.seller || p.sellerName || p.account_name || "Shitës";
  const sellerPhone = p.sellerPhone || p.account_phone || p.phone || "";

  return {
    ...p,
    id: p.id,
    title,
    name: title,
    description: p.description || "",
    price: num(p.price),
    image,
    image_url: image,
    seller_id: p.seller_id ?? null,
    seller: sellerName,
    sellerName,
    sellerPhone,
    sellerEmail: p.sellerEmail || p.account_email || "",
    category: p.category || "Të tjera",
    stock: num(p.stock),
    city: p.city || "",
    condition: p.condition || "used",
    phone: p.phone || sellerPhone,
    negotiable: boolInt(p.negotiable),
    promoted: boolInt(p.promotion_active),
    is_promoted: boolInt(p.promotion_active),
    promotion_active: boolInt(p.promotion_active),
    vip: boolInt(p.vip_active),
    promotion_expires_at: p.promotion_expires_at || null
  };
}

async function getProduct(env, id) {
  return env.DB.prepare(`
    ${PRODUCT_SELECT}
    WHERE p.id = ?
    LIMIT 1
  `).bind(id).first();
}

async function listProducts(env, request, user) {
  const url = new URL(request.url);
  const q = clean(url.searchParams.get("q") || url.searchParams.get("search"), 200);
  const category = clean(url.searchParams.get("category"), 100);
  const sellerId = num(url.searchParams.get("seller_id"), 0);
  const limit = Math.max(1, Math.min(100, num(url.searchParams.get("limit"), 60)));

  let sql = PRODUCT_SELECT + " WHERE 1=1 ";
  const values = [];

  if (!isAdmin(user)) {
    if (sellerId && user && Number(user.id) === sellerId) {
      sql += " AND p.seller_id = ? ";
      values.push(sellerId);
    } else {
      sql += `
        AND COALESCE(p.blocked, 0) = 0
        AND NOT EXISTS (
          SELECT 1 FROM blocked_listings bl
          WHERE bl.product_id = p.id AND bl.blocked = 1
        )
      `;

      if (sellerId) {
        sql += " AND p.seller_id = ? ";
        values.push(sellerId);
      }
    }
  } else if (sellerId) {
    sql += " AND p.seller_id = ? ";
    values.push(sellerId);
  }

  if (q) {
    sql += ` AND (
      p.title LIKE ? OR p.name LIKE ? OR
      p.description LIKE ? OR p.category LIKE ? OR p.city LIKE ?
    ) `;
    const term = `%${q}%`;
    values.push(term, term, term, term, term);
  }

  if (category) {
    sql += " AND p.category = ? ";
    values.push(category);
  }

  sql += `
    ORDER BY vip_active DESC, promotion_active DESC, p.id DESC
    LIMIT ?
  `;
  values.push(limit);

  const result = await env.DB.prepare(sql).bind(...values).all();
  return json((result.results || []).map(formatProduct));
}

async function createProduct(env, user, body) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  if (!isAdmin(user) && user.role !== "seller") {
    return fail("Duhet llogari shitësi për të publikuar.", 403);
  }

  const title = clean(body.title || body.name, 200);
  const description = clean(body.description, 10000);
  const price = num(body.price, -1);
  const stock = Math.max(0, Math.floor(num(body.stock, 1)));
  const category = clean(body.category || "Të tjera", 100);
  const image = clean(body.image_url || body.image, 2000);
  const city = clean(body.city || body.location, 100);
  const condition = clean(body.condition || "used", 40);
  const phone = clean(body.phone || user.phone, 50);
  const negotiable = boolInt(body.negotiable);
  const sellerId = isAdmin(user) && body.seller_id
    ? num(body.seller_id, user.id)
    : user.id;

  if (!title) return fail("Vendos titullin e produktit.");
  if (price < 0) return fail("Çmimi nuk është i vlefshëm.");

  const result = await env.DB.prepare(`
    INSERT INTO products
      (title, name, description, price, image_url, image, seller_id,
       category, stock, city, "condition", phone, negotiable, blocked)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).bind(
    title, title, description, price, image, image,
    sellerId, category, stock, city, condition, phone, negotiable
  ).run();

  const product = await getProduct(env, result.meta.last_row_id);

  return ok({ product: formatProduct(product) }, 201);
}

async function updateProduct(env, user, id, body) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  const old = await getProduct(env, id);
  if (!old) return fail("Produkti nuk u gjet.", 404);

  if (!isAdmin(user) && Number(old.seller_id) !== Number(user.id)) {
    return fail("Nuk ke leje ta ndryshosh këtë produkt.", 403);
  }

  const title = clean(body.title ?? body.name ?? old.title, 200);
  const description = clean(body.description ?? old.description, 10000);
  const price = num(body.price ?? old.price, 0);
  const image = clean(body.image_url ?? body.image ?? old.image_url ?? old.image, 2000);
  const category = clean(body.category ?? old.category, 100);
  const stock = Math.max(0, Math.floor(num(body.stock ?? old.stock, 0)));
  const city = clean(body.city ?? old.city, 100);
  const condition = clean(body.condition ?? old.condition, 40);
  const phone = clean(body.phone ?? old.phone, 50);
  const negotiable = boolInt(body.negotiable ?? old.negotiable);

  if (!title || price < 0) return fail("Titulli ose çmimi nuk është i vlefshëm.");

  await env.DB.prepare(`
    UPDATE products
    SET title=?, name=?, description=?, price=?, image_url=?, image=?,
        category=?, stock=?, city=?, "condition"=?, phone=?, negotiable=?
    WHERE id=?
  `).bind(
    title, title, description, price, image, image,
    category, stock, city, condition, phone, negotiable, id
  ).run();

  return ok({ product: formatProduct(await getProduct(env, id)) });
}

async function deleteProduct(env, user, id) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  const product = await getProduct(env, id);
  if (!product) return fail("Produkti nuk u gjet.", 404);

  if (!isAdmin(user) && Number(product.seller_id) !== Number(user.id)) {
    return fail("Nuk ke leje ta fshish këtë produkt.", 403);
  }

  await env.DB.prepare("DELETE FROM saved_listings WHERE product_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM promotions WHERE product_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM blocked_listings WHERE product_id=?").bind(id).run();

  // Porositë historike nuk fshihen.
  await env.DB.prepare("DELETE FROM products WHERE id=?").bind(id).run();

  return ok({ message: "Produkti u fshi." });
}

async function blockProduct(env, user, id, body) {
  if (!isAdmin(user)) return fail("Vetëm administratori mund ta bllokojë.", 403);

  const product = await getProduct(env, id);
  if (!product) return fail("Produkti nuk u gjet.", 404);

  const blocked = body.blocked === undefined ? 1 : boolInt(body.blocked);

  await env.DB.prepare("UPDATE products SET blocked=? WHERE id=?")
    .bind(blocked, id).run();

  if (blocked) {
    await env.DB.prepare(`
      INSERT INTO blocked_listings (product_id, blocked)
      VALUES (?, 1)
      ON CONFLICT(product_id) DO UPDATE SET blocked=1
    `).bind(id).run();
  } else {
    await env.DB.prepare("DELETE FROM blocked_listings WHERE product_id=?")
      .bind(id).run();
  }

  return ok({ blocked: !!blocked });
}

async function toggleSaved(env, user, id, method) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  const product = await getProduct(env, id);
  if (!product) return fail("Produkti nuk u gjet.", 404);

  if (method === "DELETE") {
    await env.DB.prepare(
      "DELETE FROM saved_listings WHERE user_id=? AND product_id=?"
    ).bind(user.id, id).run();

    return ok({ saved: false });
  }

  const exists = await env.DB.prepare(`
    SELECT user_id FROM saved_listings
    WHERE user_id=? AND product_id=?
  `).bind(user.id, id).first();

  if (exists) {
    await env.DB.prepare(
      "DELETE FROM saved_listings WHERE user_id=? AND product_id=?"
    ).bind(user.id, id).run();

    return ok({ saved: false });
  }

  await env.DB.prepare(`
    INSERT OR IGNORE INTO saved_listings (user_id, product_id)
    VALUES (?, ?)
  `).bind(user.id, id).run();

  return ok({ saved: true });
}

async function createOrder(env, user, body) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  const productId = num(body.product_id || body.productId, 0);
  const quantity = Math.floor(num(body.quantity, 1));

  if (!productId || quantity < 1 || quantity > 100) {
    return fail("Produkti ose sasia nuk është e vlefshme.");
  }

  const product = await getProduct(env, productId);
  if (!product) return fail("Produkti nuk u gjet.", 404);
  if (num(product.blocked) === 1) return fail("Ky produkt nuk është i disponueshëm.", 403);
  if (Number(product.seller_id) === Number(user.id)) {
    return fail("Nuk mund të blesh produktin tënd.");
  }

  const stock = num(product.stock);
  let stockReserved = false;

  if (stock > 0) {
    const updated = await env.DB.prepare(`
      UPDATE products SET stock = stock - ?
      WHERE id = ? AND stock >= ?
    `).bind(quantity, productId, quantity).run();

    if (updated.meta?.changes !== 1) {
      return fail("Nuk ka stok të mjaftueshëm.", 409);
    }

    stockReserved = true;
  }

  const settings = await getPlatformSettings(env);
  const total = num(product.price) * quantity;
  const code = "SHIT-" +
    new Date().toISOString().slice(0, 10).replaceAll("-", "") +
    "-" + randomToken(3).toUpperCase();

  try {
    const result = await env.DB.prepare(`
      INSERT INTO orders
        (order_code, product_id, buyer_id, seller_id, quantity,
         total_price, customer_name, customer_phone, customer_city,
         customer_address, payment_method, status, commission_rate,
         platform_fee, seller_earnings, stock_restored)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, 0, ?, 0)
    `).bind(
      code,
      productId,
      user.id,
      product.seller_id,
      quantity,
      total,
      clean(body.customer_name || user.name, 150),
      clean(body.customer_phone || user.phone, 60),
      clean(body.customer_city, 100),
      clean(body.customer_address, 500),
      clean(body.payment_method || "cash_on_delivery", 60),
      settings.commission_rate,
      total
    ).run();

    const order = await env.DB.prepare(
      "SELECT * FROM orders WHERE id=?"
    ).bind(result.meta.last_row_id).first();

    return ok({ order }, 201);
  } catch (e) {
    if (stockReserved) {
      await env.DB.prepare(
        "UPDATE products SET stock = stock + ? WHERE id=?"
      ).bind(quantity, productId).run();
    }

    throw e;
  }
}

async function listOrders(env, user) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  let sql = `
    SELECT
      o.*,
      p.title AS product_title,
      p.name AS product_name,
      p.image_url AS product_image,
      p.image AS product_image_alt,
      p.price AS product_price,
      COALESCE(o.seller_id, p.seller_id) AS effective_seller_id,
      buyer.name AS buyer_account_name,
      buyer.email AS buyer_email,
      buyer.phone AS buyer_phone,
      seller.name AS seller_account_name,
      seller.email AS seller_email,
      seller.phone AS seller_phone
    FROM orders o
    LEFT JOIN products p ON p.id=o.product_id
    LEFT JOIN auth_accounts buyer ON buyer.id=o.buyer_id
    LEFT JOIN auth_accounts seller ON seller.id=COALESCE(o.seller_id,p.seller_id)
  `;

  let result;

  if (isAdmin(user)) {
    result = await env.DB.prepare(sql + " ORDER BY o.id DESC LIMIT 500").all();
  } else {
    result = await env.DB.prepare(
      sql + ` WHERE o.buyer_id=? OR COALESCE(o.seller_id,p.seller_id)=?
              ORDER BY o.id DESC LIMIT 300`
    ).bind(user.id, user.id).all();
  }

  return json((result.results || []).map(o => ({
    ...o,
    id: o.id,
    code: o.order_code || `ORDER-${o.id}`,
    seller_id: o.effective_seller_id,
    product: {
      id: o.product_id,
      title: o.product_title || o.product_name || "Produkt i fshirë",
      image_url: o.product_image || o.product_image_alt || "",
      price: num(o.product_price)
    },
    buyer: {
      id: o.buyer_id,
      name: o.customer_name || o.buyer_account_name || "",
      email: o.buyer_email || "",
      phone: o.customer_phone || o.buyer_phone || ""
    },
    seller: {
      id: o.effective_seller_id,
      name: o.seller_account_name || "",
      email: o.seller_email || "",
      phone: o.seller_phone || ""
    },
    total: num(o.total_price),
    status: o.status || "pending"
  })));
}

async function updateOrder(env, user, id, body) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  const order = await env.DB.prepare(
    "SELECT * FROM orders WHERE id=?"
  ).bind(id).first();

  if (!order) return fail("Porosia nuk u gjet.", 404);

  const product = order.product_id
    ? await getProduct(env, order.product_id)
    : null;

  const sellerId = order.seller_id ?? product?.seller_id;
  const isBuyer = Number(order.buyer_id) === Number(user.id);
  const isSeller = Number(sellerId) === Number(user.id);

  const status = clean(body.status, 30).toLowerCase();

  const allowed = [
    "pending", "confirmed", "shipped",
    "delivered", "completed", "cancelled"
  ];

  if (!allowed.includes(status)) {
    return fail("Statusi nuk është i vlefshëm.");
  }

  if (!isAdmin(user)) {
    if (isBuyer) {
      if (
        status !== "cancelled" ||
        !["pending", "confirmed"].includes(String(order.status))
      ) {
        return fail("Nuk mund ta ndryshosh këtë porosi.", 403);
      }
    } else if (isSeller) {
      if (!["confirmed", "shipped", "delivered", "completed", "cancelled"].includes(status)) {
        return fail("Nuk lejohet ky ndryshim statusi.", 403);
      }
      if (status === "cancelled" && !["pending", "confirmed"].includes(order.status)) {
        return fail("Porosia nuk mund të anulohet në këtë fazë.", 400);
      }
    } else {
      return fail("Nuk ke leje për këtë porosi.", 403);
    }
  }

  if (
    ["delivered", "completed"].includes(String(order.status)) &&
    status === "cancelled"
  ) {
    return fail("Një porosi e përfunduar nuk mund të anulohet.", 400);
  }

  if (
    status === "cancelled" &&
    num(order.stock_restored) === 0 &&
    product &&
    num(order.quantity) > 0
  ) {
    await env.DB.prepare(
      "UPDATE products SET stock=stock+? WHERE id=?"
    ).bind(num(order.quantity), order.product_id).run();

    await env.DB.prepare(
      "UPDATE orders SET stock_restored=1 WHERE id=?"
    ).bind(id).run();
  }

  const settings = await getPlatformSettings(env);
  const total = num(order.total_price);
  const commissionRate = num(order.commission_rate, settings.commission_rate);
  const fee = ["delivered", "completed"].includes(status)
    ? Math.round(total * commissionRate) / 100
    : 0;
  const earnings = total - fee;

  await env.DB.prepare(`
    UPDATE orders
    SET status=?, commission_rate=?, platform_fee=?, seller_earnings=?,
        updated_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).bind(status, commissionRate, fee, earnings, id).run();

  if (["delivered", "completed"].includes(status)) {
    const exists = await env.DB.prepare(`
      SELECT id FROM transactions
      WHERE type='commission' AND reference_id=?
      LIMIT 1
    `).bind(String(id)).first();

    if (!exists && fee > 0) {
      await env.DB.prepare(`
        INSERT INTO transactions
          (user_id, type, amount, currency, status, reference_id, metadata)
        VALUES (?, 'commission', ?, ?, 'paid', ?, ?)
      `).bind(
        sellerId || null,
        fee,
        settings.currency,
        String(id),
        JSON.stringify({ order_id: id, order_code: order.order_code || "" })
      ).run();
    }
  }

  const updated = await env.DB.prepare(
    "SELECT * FROM orders WHERE id=?"
  ).bind(id).first();

  return ok({ order: updated });
}

async function createPromotion(env, user, body) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  const productId = num(body.product_id || body.productId, 0);
  const plan = clean(body.plan || body.type, 20).toLowerCase();

  const product = await getProduct(env, productId);
  if (!product) return fail("Produkti nuk u gjet.", 404);

  if (!isAdmin(user) && Number(product.seller_id) !== Number(user.id)) {
    return fail("Nuk ke leje ta promovosh këtë produkt.", 403);
  }

  const settings = await getPlatformSettings(env);
  const plans = {
    "1d": { type: "promoted", days: 1, price: settings.promo_1_day },
    "7d": { type: "promoted", days: 7, price: settings.promo_7_day },
    "30d": { type: "promoted", days: 30, price: settings.promo_30_day },
    "vip": { type: "vip", days: 7, price: settings.vip_7_day }
  };

  const selected = plans[plan];
  if (!selected) return fail("Plani nuk është i vlefshëm.");

  const result = await env.DB.prepare(`
    INSERT INTO promotions
      (product_id, seller_id, type, price, starts_at, ends_at, status)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 'pending')
  `).bind(
    productId,
    user.id,
    selected.type,
    selected.price,
    addDays(selected.days)
  ).run();

  await env.DB.prepare(`
    INSERT INTO transactions
      (user_id, type, amount, currency, status, reference_id, metadata)
    VALUES (?, ?, ?, ?, 'pending', ?, ?)
  `).bind(
    user.id,
    selected.type === "vip" ? "vip" : "promotion",
    selected.price,
    settings.currency,
    String(result.meta.last_row_id),
    JSON.stringify({ product_id: productId, plan })
  ).run();

  return ok({
    message: "Kërkesa u krijua. Promovimi aktivizohet pasi të konfirmohet pagesa.",
    promotion_id: result.meta.last_row_id,
    status: "pending",
    amount: selected.price,
    currency: settings.currency
  }, 201);
}

async function activatePromotion(env, user, id) {
  if (!isAdmin(user)) return fail("Vetëm administratori mund ta aktivizojë.", 403);

  const promotion = await env.DB.prepare(
    "SELECT * FROM promotions WHERE id=?"
  ).bind(id).first();

  if (!promotion) return fail("Promovimi nuk u gjet.", 404);

  await env.DB.prepare(`
    UPDATE promotions
    SET status='active', starts_at=CURRENT_TIMESTAMP, ends_at=?
    WHERE id=?
  `).bind(
    addDays(promotion.type === "vip" ? 7 :
      promotion.price === 100 ? 1 :
      promotion.price === 300 ? 7 : 30),
    id
  ).run();

  await env.DB.prepare(`
    UPDATE transactions
    SET status='paid'
    WHERE reference_id=? AND type IN ('promotion','vip')
  `).bind(String(id)).run();

  return ok({ message: "Promovimi u aktivizua." });
}

async function adminSettings(env, method, body) {
  if (method === "GET") {
    const settings = await getPlatformSettings(env);

    return ok({
      settings: {
        ...settings,
        platform_name: await getMarketplaceSetting(env, "platform_name", "SHIT.BLEJ"),
        admin_email: await getMarketplaceSetting(env, "admin_email", "admin@shitblej.al")
      }
    });
  }

  const current = await getPlatformSettings(env);

  const commission = body.commission_rate === undefined
    ? current.commission_rate : num(body.commission_rate, -1);
  const promo1 = body.promo_1_day === undefined
    ? current.promo_1_day : num(body.promo_1_day, -1);
  const promo7 = body.promo_7_day === undefined
    ? current.promo_7_day : num(body.promo_7_day, -1);
  const promo30 = body.promo_30_day === undefined
    ? current.promo_30_day : num(body.promo_30_day, -1);
  const vip7 = body.vip_7_day === undefined
    ? current.vip_7_day : num(body.vip_7_day, -1);
  const currency = clean(body.currency ?? current.currency, 10).toUpperCase();

  if (commission < 0 || commission > 100) {
    return fail("Komisioni duhet të jetë nga 0 deri në 100%.");
  }

  if ([promo1, promo7, promo30, vip7].some(v => v < 0)) {
    return fail("Çmimet nuk mund të jenë negative.");
  }

  await env.DB.prepare(`
    UPDATE platform_settings
    SET commission_rate=?, currency=?, promotion_price_1d=?,
        promotion_price_7d=?, promotion_price_30d=?, vip_price_7d=?
    WHERE id=(SELECT id FROM platform_settings ORDER BY id LIMIT 1)
  `).bind(commission, currency || "ALL", promo1, promo7, promo30, vip7).run();

  if (body.platform_name !== undefined) {
    await setMarketplaceSetting(
      env, "platform_name", clean(body.platform_name, 100)
    );
  }

  if (body.admin_email !== undefined) {
    await setMarketplaceSetting(
      env, "admin_email", clean(body.admin_email, 190).toLowerCase()
    );
  }

  return adminSettings(env, "GET", {});
}

async function adminStats(env) {
  const users = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM auth_accounts"
  ).first();

  const products = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM products WHERE COALESCE(blocked,0)=0"
  ).first();

  const blockedProducts = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM products WHERE COALESCE(blocked,0)=1"
  ).first();

  const orders = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM orders"
  ).first();

  const pending = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM orders WHERE status='pending'"
  ).first();

  const revenue = await env.DB.prepare(`
    SELECT COALESCE(SUM(total_price),0) AS n
    FROM orders WHERE status IN ('delivered','completed')
  `).first();

  const fees = await env.DB.prepare(`
    SELECT COALESCE(SUM(platform_fee),0) AS n
    FROM orders WHERE status IN ('delivered','completed')
  `).first();

  const transactionFees = await env.DB.prepare(`
    SELECT COALESCE(SUM(amount),0) AS n
    FROM transactions WHERE type='commission' AND status='paid'
  `).first();

  return ok({
    stats: {
      users: num(users?.n),
      products: num(products?.n),
      blocked_products: num(blockedProducts?.n),
      orders: num(orders?.n),
      pending_orders: num(pending?.n),
      revenue: num(revenue?.n),
      platform_fees: Math.max(num(fees?.n), num(transactionFees?.n))
    }
  });
}

async function adminUsers(env) {
  const result = await env.DB.prepare(`
    SELECT id, name, email, phone, role, blocked, created_at
    FROM auth_accounts
    ORDER BY id DESC
    LIMIT 500
  `).all();

  return json(result.results || []);
}

async function blockUser(env, user, id, body) {
  if (!isAdmin(user)) return fail("Vetëm administratori mund të bllokojë përdorues.", 403);

  const target = await env.DB.prepare(
    "SELECT id, role FROM auth_accounts WHERE id=?"
  ).bind(id).first();

  if (!target) return fail("Përdoruesi nuk u gjet.", 404);
  if (Number(target.id) === Number(user.id)) {
    return fail("Nuk mund të bllokosh llogarinë tënde.", 400);
  }

  const blocked = body.blocked === undefined ? 1 : boolInt(body.blocked);

  await env.DB.prepare(
    "UPDATE auth_accounts SET blocked=? WHERE id=?"
  ).bind(blocked, id).run();

  await env.DB.prepare(`
    INSERT INTO blocked_users (user_id, blocked)
    VALUES (?, ?)
    ON CONFLICT(user_id) DO UPDATE SET blocked=excluded.blocked
  `).bind(id, blocked).run();

  if (blocked) {
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?")
      .bind(id).run();
  }

  return ok({ blocked: !!blocked });
}

async function adminFinance(env) {
  const transactions = await env.DB.prepare(`
    SELECT * FROM transactions ORDER BY id DESC LIMIT 300
  `).all();

  const totals = await env.DB.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN status='paid' THEN amount ELSE 0 END),0) AS paid,
      COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END),0) AS pending
    FROM transactions
  `).first();

  return ok({
    transactions: transactions.results || [],
    totals: {
      paid: num(totals?.paid),
      pending: num(totals?.pending)
    }
  });
}

async function routeApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const user = await currentUser(env, request);

  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS });
  }

  if (path === "/api/health" && method === "GET") {
    return ok({ service: "SHIT.BLEJ", database: "connected" });
  }

  if (path === "/api/auth/register" && method === "POST") {
    return register(env, await readJson(request));
  }

  if (
    ["/api/auth/login", "/api/login"].includes(path) &&
    method === "POST"
  ) {
    return login(env, await readJson(request));
  }

  if (path === "/api/auth/me" && method === "GET") {
    if (!user) return fail("Nuk je i identifikuar.", 401);
    return ok({ user: publicUser(user) });
  }

  if (path === "/api/auth/logout" && method === "POST") {
    const token = tokenFromRequest(request);
    if (token) {
      await env.DB.prepare("DELETE FROM sessions WHERE token=?")
        .bind(token).run();
    }
    return ok({ message: "U çregjistrove." });
  }

  if (path === "/api/products" && method === "GET") {
    return listProducts(env, request, user);
  }

  if (path === "/api/products/search" && method === "GET") {
    return listProducts(env, request, user);
  }

  if (path === "/api/products" && method === "POST") {
    return createProduct(env, user, await readJson(request));
  }

  let match = path.match(/^\/api\/products\/(\d+)\/save$/);
  if (match && ["POST", "DELETE"].includes(method)) {
    return toggleSaved(env, user, Number(match[1]), method);
  }

  match = path.match(/^\/api\/products\/(\d+)\/block$/);
  if (match && ["POST", "PUT", "PATCH"].includes(method)) {
    return blockProduct(env, user, Number(match[1]), await readJson(request));
  }

  match = path.match(/^\/api\/products\/(\d+)$/);
  if (match) {
    const id = Number(match[1]);

    if (method === "GET") {
      const p = await getProduct(env, id);
      if (!p) return fail("Produkti nuk u gjet.", 404);

      if (
        !isAdmin(user) &&
        num(p.blocked) === 1 &&
        Number(p.seller_id) !== Number(user?.id)
      ) {
        return fail("Produkti nuk është i disponueshëm.", 404);
      }

      return ok({ product: formatProduct(p) });
    }

    if (method === "PUT" || method === "PATCH") {
      return updateProduct(env, user, id, await readJson(request));
    }

    if (method === "DELETE") {
      return deleteProduct(env, user, id);
    }
  }

  if (path === "/api/orders" && method === "GET") {
    return listOrders(env, user);
  }

  if (path === "/api/orders" && method === "POST") {
    return createOrder(env, user, await readJson(request));
  }

  match = path.match(/^\/api\/orders\/(\d+)$/);
  if (match && ["PUT", "PATCH", "POST"].includes(method)) {
    return updateOrder(env, user, Number(match[1]), await readJson(request));
  }

  if (path === "/api/promotions" && method === "POST") {
    return createPromotion(env, user, await readJson(request));
  }

  match = path.match(/^\/api\/promotions\/(\d+)\/activate$/);
  if (match && method === "POST") {
    return activatePromotion(env, user, Number(match[1]));
  }

  if (path === "/api/admin/stats" && method === "GET") {
    if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);
    return adminStats(env);
  }

  if (
    path === "/api/admin/settings" &&
    ["GET", "PUT", "POST"].includes(method)
  ) {
    if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);

    return adminSettings(
      env,
      method,
      method === "GET" ? {} : await readJson(request)
    );
  }

  if (path === "/api/admin/finance" && method === "GET") {
    if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);
    return adminFinance(env);
  }

  if (path === "/api/users/all" && method === "GET") {
    if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);
    return adminUsers(env);
  }

  match = path.match(/^\/api\/users\/(\d+)\/block$/);
  if (match && ["POST", "PUT", "PATCH"].includes(method)) {
    if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);

    return blockUser(
      env,
      user,
      Number(match[1]),
      await readJson(request)
    );
  }

  if (path.startsWith("/api/")) {
    return fail("API endpoint nuk u gjet.", 404);
  }

  return null;
}

export default {
  async fetch(request, env) {
    try {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: CORS });
      }

      await ensureDatabase(env);

      const url = new URL(request.url);

      if (url.pathname.startsWith("/api/")) {
        return await routeApi(request, env);
      }

      if (!env.ASSETS) {
        return new Response("Asset binding ASSETS nuk është konfiguruar.", {
          status: 500,
          headers: CORS
        });
      }

      // Hap index.html kur vizitori shkon te faqja kryesore.
      if (url.pathname === "/") {
        url.pathname = "/index.html";
        return env.ASSETS.fetch(new Request(url.toString(), request));
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      return json({
        success: false,
        error: error?.message || "Gabim i brendshëm në server."
      }, 500);
    }
  }
};
