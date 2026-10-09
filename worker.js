
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Auth-Token",
  "Access-Control-Max-Age": "86400"
};

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" }
});

const ok = (data = {}, status = 200) => json({ success: true, ...data }, status);
const fail = (error, status = 400) => json({ success: false, error }, status);
const clean = (v, max = 5000) => String(v ?? "").trim().slice(0, max);
const num = (v, fallback = 0) => Number.isFinite(Number(v)) ? Number(v) : fallback;
const hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, "0")).join("");
const randomToken = (n = 32) => hex(crypto.getRandomValues(new Uint8Array(n)));
const isAdmin = u => !!u && ["admin", "owner"].includes(String(u.role).toLowerCase());

function tokenOf(req) {
  const auth = req.headers.get("Authorization") || "";
  return auth.toLowerCase().startsWith("bearer ")
    ? auth.slice(7).trim()
    : req.headers.get("X-Auth-Token") || "";
}

async function bodyOf(req) {
  try { return await req.json(); } catch { return {}; }
}

function datePlus(days) {
  return new Date(Date.now() + days * 86400000)
    .toISOString().slice(0, 19).replace("T", " ");
}

/* PASSWORDS: PBKDF2-SHA256 */

async function makePassword(password) {
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(String(password)),
    "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: new TextEncoder().encode(salt),
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);

  return { salt, hash: `pbkdf2$100000$${salt}$${hex(bits)}` };
}

async function verifyPassword(password, stored) {
  const p = String(stored || "").split("$");
  if (p.length !== 4 || p[0] !== "pbkdf2") return false;

  const iterations = Number(p[1]);
  if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 1000000) return false;
  if (!/^[0-9a-f]+$/i.test(p[2]) || p[2].length % 2 !== 0) return false;
  if (!/^[0-9a-f]{64}$/i.test(p[3])) return false;

  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(String(password)),
    "PBKDF2", false, ["deriveBits"]
  );

  const saltHex = p[2];
  const salts = [
    new TextEncoder().encode(saltHex),
    new Uint8Array(saltHex.match(/.{2}/g).map(x => parseInt(x, 16)))
  ];

  for (const salt of salts) {
    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2", salt, iterations, hash: "SHA-256"
    }, key, 256);

    if (hex(bits) === p[3].toLowerCase()) return true;
  }
  return false;
}

/* DATABASE: create missing tables and add missing columns.
   Existing rows are not deleted. */

async function addColumn(env, table, column, definition) {
  const allowed = new Set([
    "auth_accounts", "products", "orders", "sessions",
    "saved_listings", "blocked_users", "blocked_listings",
    "marketplace_settings", "platform_settings",
    "promotions", "transactions"
  ]);

  if (!allowed.has(table) || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(column)) {
    throw new Error("Emër tabele ose kolone i pavlefshëm.");
  }

  try {
    await env.DB.prepare(
      `ALTER TABLE "${table}" ADD COLUMN "${column}" ${definition}`
    ).run();
  } catch (e) {
    if (!/duplicate column|already exists/i.test(e.message || "")) throw e;
  }
}

async function setupDB(env) {
  const schemas = [
    `CREATE TABLE IF NOT EXISTS auth_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT DEFAULT '',
      email TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      identifier TEXT DEFAULT '',
      password_hash TEXT NOT NULL DEFAULT '',
      password_salt TEXT NOT NULL DEFAULT '',
      role TEXT DEFAULT 'customer',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      blocked INTEGER DEFAULT 0
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
      PRIMARY KEY(user_id, product_id)
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
    `CREATE TABLE IF NOT EXISTS platform_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      commission_rate REAL DEFAULT 5,
      currency TEXT DEFAULT 'ALL',
      promotion_price_1d REAL DEFAULT 100,
      promotion_price_7d REAL DEFAULT 300,
      promotion_price_30d REAL DEFAULT 700,
      vip_price_7d REAL DEFAULT 500
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
    )`
  ];

  for (const s of schemas) await env.DB.prepare(s).run();

  const columns = {
    auth_accounts: {
      identifier: "TEXT DEFAULT ''",
      password_salt: "TEXT NOT NULL DEFAULT ''",
      blocked: "INTEGER DEFAULT 0"
    },
    products: {
      title: "TEXT NOT NULL DEFAULT ''",
      name: "TEXT DEFAULT ''",
      description: "TEXT DEFAULT ''",
      price: "REAL NOT NULL DEFAULT 0",
      image_url: "TEXT DEFAULT ''",
      image: "TEXT DEFAULT ''",
      seller_id: "INTEGER",
      category: "TEXT DEFAULT 'Të tjera'",
      stock: "INTEGER DEFAULT 0",
      city: "TEXT DEFAULT ''",
      condition: "TEXT DEFAULT 'used'",
      phone: "TEXT DEFAULT ''",
      negotiable: "INTEGER DEFAULT 0",
      blocked: "INTEGER DEFAULT 0"
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
      updated_at: "TEXT"
    }
  };

  for (const [table, cols] of Object.entries(columns)) {
    const info = await env.DB.prepare(`PRAGMA table_info("${table}")`).all();
    const existing = new Set((info.results || []).map(c => c.name));
    for (const [name, definition] of Object.entries(cols)) {
      if (!existing.has(name)) await addColumn(env, table, name, definition);
    }
  }

  await env.DB.prepare(`
    INSERT INTO platform_settings
      (commission_rate,currency,promotion_price_1d,promotion_price_7d,
       promotion_price_30d,vip_price_7d)
    SELECT 5,'ALL',100,300,700,500
    WHERE NOT EXISTS (SELECT 1 FROM platform_settings)
  `).run();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO marketplace_settings(setting_key,setting_value)
    VALUES ('platform_name','SABI Marketplace')
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
}

let dbReady = false;
let setupPromise;

async function ensureDB(env) {
  if (dbReady) return;
  if (!setupPromise) {
    setupPromise = setupDB(env).then(() => { dbReady = true; })
      .catch(e => { setupPromise = null; throw e; });
  }
  await setupPromise;
}

/* AUTH */

function publicUser(u) {
  return {
    id: u.id,
    name: u.name || "",
    email: u.email || "",
    phone: u.phone || "",
    identifier: u.identifier || u.email || "",
    role: u.role || "customer"
  };
}

async function currentUser(env, request) {
  const token = tokenOf(request);
  if (!token) return null;

  const u = await env.DB.prepare(`
    SELECT a.id,a.name,a.email,a.phone,a.identifier,a.role,a.blocked,
           s.expires_at
    FROM sessions s JOIN auth_accounts a ON a.id=s.user_id
    WHERE s.token=? LIMIT 1
  `).bind(token).first();

  if (!u || num(u.blocked) === 1) return null;

  if (u.expires_at) {
    const exp = new Date(String(u.expires_at).replace(" ", "T") + "Z");
    if (!Number.isNaN(exp.getTime()) && exp < new Date()) {
      await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(token).run();
      return null;
    }
  }
  return u;
}

async function newSession(env, id) {
  const token = randomToken();
  await env.DB.prepare(`
    INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)
  `).bind(token, id, datePlus(30)).run();
  return token;
}

async function register(env, b) {
  const name = clean(b.name || b.full_name, 120);
  const email = clean(b.email || "", 190).toLowerCase();
  const identifier = clean(b.identifier || email, 190).toLowerCase();
  const phone = clean(b.phone, 50);
  const password = String(b.password || "");
  let role = clean(b.role || "customer", 20).toLowerCase();

  if (!name || !identifier || !password) {
    return fail("Plotëso emrin, username/email dhe fjalëkalimin.");
  }
  if (password.length < 6) return fail("Fjalëkalimi duhet të ketë të paktën 6 karaktere.");
  if (!["customer", "seller"].includes(role)) role = "customer";

  const found = await env.DB.prepare(`
    SELECT id FROM auth_accounts
    WHERE lower(identifier)=? OR lower(email)=? OR (phone<>'' AND phone=?)
    LIMIT 1
  `).bind(identifier, identifier, phone).first();

  if (found) return fail("Kjo llogari ekziston.", 409);

  const pw = await makePassword(password);
  const result = await env.DB.prepare(`
    INSERT INTO auth_accounts
      (name,email,phone,identifier,password_hash,password_salt,role,blocked)
    VALUES(?,?,?,?,?,?,?,0)
  `).bind(name, email, phone, identifier, pw.hash, pw.salt, role).run();

  const id = result.meta?.last_row_id;
  if (!id) return fail("Regjistrimi nuk u krye.", 500);

  const token = await newSession(env, id);
  return ok({
    user: { id, name, email, phone, identifier, role },
    token
  }, 201);
}

async function login(env, b) {
  const identifier = clean(b.identifier || b.username || b.email || b.phone, 190).toLowerCase();
  const password = String(b.password || "");
  if (!identifier || !password) return fail("Vendos username/email dhe fjalëkalimin.");

  const user = await env.DB.prepare(`
    SELECT * FROM auth_accounts
    WHERE lower(email)=? OR lower(identifier)=? OR phone=?
    LIMIT 1
  `).bind(identifier, identifier, identifier).first();

  if (!user || num(user.blocked) === 1) {
    return fail("Email/username ose fjalëkalim i gabuar.", 401);
  }

  let valid = await verifyPassword(password, user.password_hash);

  // Përputhshmëri me llogaritë e vjetra SHA-256.
  if (!valid && /^[0-9a-f]{64}$/i.test(String(user.password_hash || ""))) {
    const oldHash = hex(await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(password)
    ));
    valid = oldHash === String(user.password_hash).toLowerCase();
    if (valid) {
      const pw = await makePassword(password);
      await env.DB.prepare(`
        UPDATE auth_accounts SET password_hash=?,password_salt=? WHERE id=?
      `).bind(pw.hash, pw.salt, user.id).run();
    }
  }

  if (!valid) return fail("Email/username ose fjalëkalim i gabuar.", 401);

  const token = await newSession(env, user.id);
  return ok({ token, user: publicUser(user) });
}

/* PRODUCTS */

const productSelect = `
  SELECT p.*, a.name AS account_name, a.email AS account_email,
         a.phone AS account_phone
  FROM products p LEFT JOIN auth_accounts a ON a.id=p.seller_id
`;

function formatProduct(p) {
  const title = p.title || p.name || "";
  const image = p.image_url || p.image || "";
  return {
    ...p,
    title,
    name: title,
    price: num(p.price),
    image,
    image_url: image,
    seller: p.account_name || p.seller || "Shitës",
    sellerName: p.account_name || p.sellerName || p.seller || "Shitës",
    sellerPhone: p.account_phone || p.phone || "",
    sellerEmail: p.account_email || "",
    stock: num(p.stock),
    category: p.category || "Të tjera",
    negotiable: num(p.negotiable),
    blocked: num(p.blocked)
  };
}

async function getProduct(env, id) {
  return env.DB.prepare(`${productSelect} WHERE p.id=? LIMIT 1`).bind(id).first();
}

async function listProducts(env, request, user) {
  const url = new URL(request.url);
  const q = clean(url.searchParams.get("q") || url.searchParams.get("search"), 200);
  const category = clean(url.searchParams.get("category"), 100);
  const sellerId = num(url.searchParams.get("seller_id"), 0);
  const limit = Math.max(1, Math.min(100, num(url.searchParams.get("limit"), 60)));

  let sql = productSelect + " WHERE 1=1 ";
  const args = [];

  if (!isAdmin(user)) sql += " AND COALESCE(p.blocked,0)=0 ";
  if (sellerId) { sql += " AND p.seller_id=? "; args.push(sellerId); }

  if (q) {
    sql += " AND (p.title LIKE ? OR p.name LIKE ? OR p.description LIKE ? OR p.category LIKE ? OR p.city LIKE ?) ";
    const term = `%${q}%`;
    args.push(term, term, term, term, term);
  }
  if (category) { sql += " AND p.category=? "; args.push(category); }
  sql += " ORDER BY p.id DESC LIMIT ? ";
  args.push(limit);

  const result = await env.DB.prepare(sql).bind(...args).all();
  return json((result.results || []).map(formatProduct));
}

async function createProduct(env, user, b) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);
  if (!isAdmin(user) && user.role !== "seller") return fail("Duhet llogari shitësi.", 403);

  const title = clean(b.title || b.name, 200);
  const price = num(b.price, -1);
  if (!title || price < 0) return fail("Titulli ose çmimi nuk është i vlefshëm.");

  const sellerId = isAdmin(user) && b.seller_id ? num(b.seller_id, user.id) : user.id;
  const image = clean(b.image_url || b.image, 2000);

  const result = await env.DB.prepare(`
    INSERT INTO products
      (title,name,description,price,image_url,image,seller_id,category,stock,
       city,condition,phone,negotiable,blocked)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)
  `).bind(
    title, title, clean(b.description, 10000), price, image, image,
    sellerId, clean(b.category || "Të tjera", 100),
    Math.max(0, Math.floor(num(b.stock, 1))),
    clean(b.city || b.location, 100), clean(b.condition || "used", 40),
    clean(b.phone || user.phone, 50), b.negotiable ? 1 : 0
  ).run();

  return ok({ product: formatProduct(await getProduct(env, result.meta.last_row_id)) }, 201);
}

async function updateProduct(env, user, id, b) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);
  const old = await getProduct(env, id);
  if (!old) return fail("Produkti nuk u gjet.", 404);
  if (!isAdmin(user) && Number(old.seller_id) !== Number(user.id)) return fail("Nuk ke leje.", 403);

  const title = clean(b.title ?? b.name ?? old.title ?? old.name, 200);
  const price = num(b.price ?? old.price, -1);
  if (!title || price < 0) return fail("Titulli ose çmimi nuk është i vlefshëm.");

  const image = clean(b.image_url ?? b.image ?? old.image_url ?? old.image, 2000);
  await env.DB.prepare(`
    UPDATE products SET title=?,name=?,description=?,price=?,image_url=?,image=?,
      category=?,stock=?,city=?,condition=?,phone=?,negotiable=?
    WHERE id=?
  `).bind(
    title, title, clean(b.description ?? old.description, 10000), price,
    image, image, clean(b.category ?? old.category, 100),
    Math.max(0, Math.floor(num(b.stock ?? old.stock, 0))),
    clean(b.city ?? old.city, 100), clean(b.condition ?? old.condition, 40),
    clean(b.phone ?? old.phone, 50), num(b.negotiable ?? old.negotiable),
    id
  ).run();

  return ok({ product: formatProduct(await getProduct(env, id)) });
}

async function deleteProduct(env, user, id) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);
  const p = await getProduct(env, id);
  if (!p) return fail("Produkti nuk u gjet.", 404);
  if (!isAdmin(user) && Number(p.seller_id) !== Number(user.id)) return fail("Nuk ke leje.", 403);

  // Ruajmë historikun e porosive.
  await env.DB.prepare("DELETE FROM saved_listings WHERE product_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM promotions WHERE product_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM blocked_listings WHERE product_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM products WHERE id=?").bind(id).run();
  return ok({ message: "Produkti u fshi." });
}

/* ORDERS */

async function listOrders(env, user) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  let sql = `
    SELECT o.*, p.title AS product_title, p.name AS product_name,
      p.image_url AS product_image, p.image AS product_image_alt,
      p.price AS product_price,
      b.name AS buyer_name, b.email AS buyer_email, b.phone AS buyer_phone,
      s.name AS seller_name, s.email AS seller_email, s.phone AS seller_phone
    FROM orders o
    LEFT JOIN products p ON p.id=o.product_id
    LEFT JOIN auth_accounts b ON b.id=o.buyer_id
    LEFT JOIN auth_accounts s ON s.id=COALESCE(o.seller_id,p.seller_id)
  `;

  let result;
  if (isAdmin(user)) {
    result = await env.DB.prepare(sql + " ORDER BY o.id DESC LIMIT 500").all();
  } else {
    result = await env.DB.prepare(sql + `
      WHERE o.buyer_id=? OR COALESCE(o.seller_id,p.seller_id)=?
      ORDER BY o.id DESC LIMIT 300
    `).bind(user.id, user.id).all();
  }

  return json((result.results || []).map(o => ({
    ...o,
    code: o.order_code || `ORDER-${o.id}`,
    total: num(o.total_price),
    product: {
      id: o.product_id,
      title: o.product_title || o.product_name || "Produkt",
      image_url: o.product_image || o.product_image_alt || "",
      price: num(o.product_price)
    },
    buyer: {
      id: o.buyer_id,
      name: o.customer_name || o.buyer_name || "",
      email: o.buyer_email || "",
      phone: o.customer_phone || o.buyer_phone || ""
    },
    seller: {
      id: o.seller_id,
      name: o.seller_name || "",
      email: o.seller_email || "",
      phone: o.seller_phone || ""
    }
  })));
}

async function createOrder(env, user, b) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);

  const productId = num(b.product_id || b.productId, 0);
  const quantity = Math.floor(num(b.quantity, 1));
  if (!productId || quantity < 1 || quantity > 100) return fail("Produkt ose sasi e pavlefshme.");

  const p = await getProduct(env, productId);
  if (!p || num(p.blocked) === 1) return fail("Produkti nuk është i disponueshëm.", 404);
  if (Number(p.seller_id) === Number(user.id)) return fail("Nuk mund të blesh produktin tënd.");

  const stock = num(p.stock);
  if (stock > 0) {
    const upd = await env.DB.prepare(
      "UPDATE products SET stock=stock-? WHERE id=? AND stock>=?"
    ).bind(quantity, productId, quantity).run();
    if (upd.meta?.changes !== 1) return fail("Nuk ka stok të mjaftueshëm.", 409);
  }

  const code = "SABI-" + new Date().toISOString().slice(0, 10).replaceAll("-", "") +
    "-" + randomToken(3).toUpperCase();
  const total = num(p.price) * quantity;

  try {
    const result = await env.DB.prepare(`
      INSERT INTO orders
        (order_code,product_id,buyer_id,seller_id,quantity,total_price,
         customer_name,customer_phone,customer_city,customer_address,
         payment_method,status,commission_rate,seller_earnings)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',5,?)
    `).bind(
      code, productId, user.id, p.seller_id, quantity, total,
      clean(b.customer_name || b.name || user.name, 150),
      clean(b.customer_phone || b.phone || user.phone, 60),
      clean(b.customer_city || b.city, 100),
      clean(b.customer_address || b.address, 500),
      clean(b.payment_method || "cash_on_delivery", 50),
      total
    ).run();

    const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?")
      .bind(result.meta.last_row_id).first();
    return ok({ order }, 201);
  } catch (e) {
    if (stock > 0) {
      await env.DB.prepare("UPDATE products SET stock=stock+? WHERE id=?")
        .bind(quantity, productId).run();
    }
    throw e;
  }
}

async function updateOrder(env, user, id, b) {
  if (!user) return fail("Duhet të hysh në llogari.", 401);
  const o = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(id).first();
  if (!o) return fail("Porosia nuk u gjet.", 404);

  const p = o.product_id ? await getProduct(env, o.product_id) : null;
  const sellerId = o.seller_id ?? p?.seller_id;
  const buyer = Number(o.buyer_id) === Number(user.id);
  const seller = Number(sellerId) === Number(user.id);
  const status = clean(b.status, 30).toLowerCase();
  const allowed = ["pending", "confirmed", "shipped", "delivered", "completed", "cancelled"];

  if (!allowed.includes(status)) return fail("Status i pavlefshëm.");
  if (!isAdmin(user)) {
    if (buyer) {
      if (status !== "cancelled" || !["pending", "confirmed"].includes(o.status)) {
        return fail("Nuk mund ta ndryshosh këtë porosi.", 403);
      }
    } else if (seller) {
      if (!["confirmed", "shipped", "delivered", "completed", "cancelled"].includes(status)) {
        return fail("Status i palejuar.", 403);
      }
    } else {
      return fail("Nuk ke leje.", 403);
    }
  }

  if (status === "cancelled" && num(o.stock_restored) === 0 && p && num(o.quantity) > 0) {
    await env.DB.prepare("UPDATE products SET stock=stock+? WHERE id=?")
      .bind(num(o.quantity), o.product_id).run();
    await env.DB.prepare("UPDATE orders SET stock_restored=1 WHERE id=?").bind(id).run();
  }

  const settings = await env.DB.prepare("SELECT commission_rate FROM platform_settings ORDER BY id LIMIT 1").first();
  const rate = num(o.commission_rate, num(settings?.commission_rate, 5));
  const total = num(o.total_price);
  const fee = ["delivered", "completed"].includes(status) ? Math.round(total * rate) / 100 : 0;

  await env.DB.prepare(`
    UPDATE orders SET status=?,commission_rate=?,platform_fee=?,
      seller_earnings=?,updated_at=CURRENT_TIMESTAMP WHERE id=?
  `).bind(status, rate, fee, total - fee, id).run();

  return ok({ order: await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(id).first() });
}

/* ADMIN */

async function adminStats(env) {
  const one = async sql => num((await env.DB.prepare(sql).first())?.n);
  return ok({
    stats: {
      users: await one("SELECT COUNT(*) n FROM auth_accounts"),
      products: await one("SELECT COUNT(*) n FROM products WHERE COALESCE(blocked,0)=0"),
      orders: await one("SELECT COUNT(*) n FROM orders"),
      pending_orders: await one("SELECT COUNT(*) n FROM orders WHERE status='pending'"),
      revenue: await one("SELECT COALESCE(SUM(total_price),0) n FROM orders WHERE status IN ('delivered','completed')"),
      platform_fees: await one("SELECT COALESCE(SUM(platform_fee),0) n FROM orders WHERE status IN ('delivered','completed')")
    }
  });
}

async function adminUsers(env) {
  const r = await env.DB.prepare(`
    SELECT id,name,email,phone,identifier,role,blocked,created_at
    FROM auth_accounts ORDER BY id DESC LIMIT 500
  `).all();
  return json(r.results || []);
}

async function setUserBlocked(env, user, id, b) {
  if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);
  if (Number(user.id) === Number(id)) return fail("Nuk mund të bllokosh veten.");

  const blocked = b.blocked === undefined ? 1 : (b.blocked ? 1 : 0);
  const target = await env.DB.prepare("SELECT id FROM auth_accounts WHERE id=?").bind(id).first();
  if (!target) return fail("Përdoruesi nuk u gjet.", 404);

  await env.DB.prepare("UPDATE auth_accounts SET blocked=? WHERE id=?").bind(blocked, id).run();
  if (blocked) await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();
  return ok({ blocked: !!blocked });
}

/* API ROUTER */

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const user = await currentUser(env, request);

  if (path === "/api/health" && method === "GET") {
    return ok({ service: "SABI Marketplace", database: "connected" });
  }

  if (["/api/auth/register", "/api/register"].includes(path) && method === "POST") {
    return register(env, await bodyOf(request));
  }

  if (["/api/auth/login", "/api/login"].includes(path) && method === "POST") {
    return login(env, await bodyOf(request));
  }

  if (path === "/api/auth/me" && method === "GET") {
    if (!user) return fail("Nuk je i identifikuar.", 401);
    return ok({ user: publicUser(user) });
  }

  if (path === "/api/auth/logout" && method === "POST") {
    const token = tokenOf(request);
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(token).run();
    return ok({ message: "U çregjistrove." });
  }

  if (["/api/products", "/api/products/search"].includes(path) && method === "GET") {
    return listProducts(env, request, user);
  }

  if (path === "/api/products" && method === "POST") {
    return createProduct(env, user, await bodyOf(request));
  }

  let m = path.match(/^\/api\/products\/(\d+)$/);
  if (m) {
    const id = Number(m[1]);
    if (method === "GET") {
      const p = await getProduct(env, id);
      if (!p || (!isAdmin(user) && num(p.blocked) === 1)) return fail("Produkti nuk u gjet.", 404);
      return ok({ product: formatProduct(p) });
    }
    if (["PUT", "PATCH"].includes(method)) return updateProduct(env, user, id, await bodyOf(request));
    if (method === "DELETE") return deleteProduct(env, user, id);
  }

  if (path === "/api/orders" && method === "GET") return listOrders(env, user);
  if (path === "/api/orders" && method === "POST") return createOrder(env, user, await bodyOf(request));

  m = path.match(/^\/api\/orders\/(\d+)$/);
  if (m && ["PUT", "PATCH", "POST"].includes(method)) {
    return updateOrder(env, user, Number(m[1]), await bodyOf(request));
  }

  if (path === "/api/admin/stats" && method === "GET") {
    if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);
    return adminStats(env);
  }

  if (path === "/api/users/all" && method === "GET") {
    if (!isAdmin(user)) return fail("Vetëm administratori ka akses.", 403);
    return adminUsers(env);
  }

  m = path.match(/^\/api\/users\/(\d+)\/block$/);
  if (m && ["POST", "PUT", "PATCH"].includes(method)) {
    return setUserBlocked(env, user, Number(m[1]), await bodyOf(request));
  }

  if (path.startsWith("/api/")) return fail("API endpoint nuk u gjet.", 404);
  return null;
}

/* WORKER */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      await ensureDB(env);
      const url = new URL(request.url);

      if (url.pathname.startsWith("/api/")) {
        return await api(request, env);
      }

      if (!env.ASSETS) {
        return new Response("Mungon binding ASSETS.", {
          status: 500, headers: CORS
        });
      }

      if (url.pathname === "/") {
        url.pathname = "/index.html";
        return env.ASSETS.fetch(new Request(url.toString(), request));
      }

      return env.ASSETS.fetch(request);
    } catch (e) {
      return json({
        success: false,
        error: e?.message || "Gabim i brendshëm në server."
      }, 500);
    }
  }
};
