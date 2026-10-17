

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

// Allow the shop frontend to call this API across domains.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = new Set([
    "https://jkpanel.shop",
    "https://www.jkpanel.shop",
    "https://jkpanel.onrender.com"
  ]);
  if (origin && (allowedOrigins.has(origin) || /^https:\/\/[a-z0-9-]+\.onrender\.com$/i.test(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: "20kb" }));
const imageUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024, files: 1 }, fileFilter: (req, file, cb) => {
  const allowed = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
  cb(allowed.has(file.mimetype) ? null : new Error("Sirf JPG, PNG, WebP ya GIF image upload karein."), allowed.has(file.mimetype));
} });
const videoUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024, files: 1 }, fileFilter: (req, file, cb) => {
  const allowed = new Set(["video/mp4", "video/webm", "video/quicktime"]);
  cb(allowed.has(file.mimetype) ? null : new Error("Sirf MP4, WebM ya MOV video upload karein."), allowed.has(file.mimetype));
} });

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const adminPassword = process.env.ADMIN_PASSWORD;

const supabase =
  supabaseUrl && supabaseKey
    ? createClient(supabaseUrl, supabaseKey, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
      })
    : null;

// Publishable key is safe to use for public Auth endpoints; service-role key stays server-side.
const supabasePublishableKey = process.env.SUPABASE_PUBLISHABLE_KEY ||
  "sb_publishable_nzK0bDW3lAcuPWEgeqWsqg_Zp3vuqe2";
const authClient = supabaseUrl
  ? createClient(supabaseUrl, supabasePublishableKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
    })
  : null;


async function ensureReferralProfile(userId, referralCodeInput = null) {
  const { data: existing, error: lookupError } = await supabase
    .from("referral_profiles")
    .select("user_id, referral_code, referred_by")
    .eq("user_id", userId)
    .maybeSingle();
  if (lookupError) throw lookupError;
  if (existing) return existing;

  let referredBy = null;
  const incomingCode = typeof referralCodeInput === "string" ? referralCodeInput.trim().toUpperCase() : "";
  if (incomingCode) {
    const { data: sponsor } = await supabase
      .from("referral_profiles")
      .select("user_id")
      .eq("referral_code", incomingCode)
      .maybeSingle();
    if (sponsor && sponsor.user_id !== userId) referredBy = sponsor.user_id;
  }

  for (let attempt = 0; attempt < 4; attempt++) {
    const referralCode = crypto.randomBytes(5).toString("hex").toUpperCase();
    const { data, error } = await supabase
      .from("referral_profiles")
      .insert({ user_id: userId, referral_code: referralCode, referred_by: referredBy })
      .select("user_id, referral_code, referred_by")
      .single();
    if (!error) return data;
    if (error.code === "23505") {
      const { data: raced } = await supabase.from("referral_profiles")
        .select("user_id, referral_code, referred_by").eq("user_id", userId).maybeSingle();
      if (raced) return raced;
      continue;
    }
    throw error;
  }
  throw new Error("Could not create referral profile");
}

async function getAuthenticatedUser(req) {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match || !authClient) return null;
  const { data, error } = await authClient.auth.getUser(match[1]);
  if (error || !data?.user) return null;
  return data.user;
}

function signToken(expiry) {
  return crypto
    .createHmac("sha256", adminPassword)
    .update(String(expiry))
    .digest("hex");
}

function isAdmin(req, res, next) {
  const token = req.headers.cookie
    ?.split("; ")
    .find((item) => item.startsWith("jk_admin="))
    ?.split("=")[1];

  if (!token || !adminPassword) {
    return res.status(401).json({ error: "Admin login required" });
  }

  const [expiryText, signature] = token.split(".");
  const expiry = Number(expiryText);

  if (
    !Number.isFinite(expiry) ||
    expiry < Date.now() ||
    !signature ||
    !/^[a-f0-9]{64}$/.test(signature)
  ) {
    return res.status(401).json({ error: "Please log in again" });
  }

  const expected = signToken(expiry);
  const valid = crypto.timingSafeEqual(
    Buffer.from(signature, "hex"),
    Buffer.from(expected, "hex")
  );

  if (!valid) {
    return res.status(401).json({ error: "Invalid admin session" });
  }

  next();
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});


app.post("/api/auth/register", async (req, res) => {
  if (!supabase || !authClient) {
    return res.status(503).json({ error: "Authentication is not configured" });
  }

  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Valid email address enter karein." });
  }
  if (!/^\d{6}$/.test(password)) {
    return res.status(400).json({ error: "Password exactly 6 digits ka hona chahiye." });
  }

  const referralCode = typeof req.body?.referralCode === "string" ? req.body.referralCode : null;

  // Create and auto-confirm the account server-side; no OTP/email confirmation step.
  const { data: created, error: createError } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true
  });

  if (createError) {
    const message = /already|registered|exists/i.test(createError.message || "")
      ? "Is email se account pehle se hai. Login karein."
      : (createError.message || "Registration failed");
    return res.status(400).json({ error: message });
  }

  try {
    await ensureReferralProfile(created.user.id, referralCode);
  } catch (profileError) {
    console.error("Referral profile creation failed:", profileError.message);
  }

  // Sign in immediately so the customer can use the site without a separate login.
  const { data: signedIn, error: signInError } = await authClient.auth.signInWithPassword({
    email,
    password
  });

  if (signInError || !signedIn?.session) {
    return res.status(201).json({
      success: true,
      user: created.user ? { id: created.user.id, email: created.user.email } : null,
      session: null,
      message: "Account ban gaya hai. Ab Login karein."
    });
  }

  return res.status(201).json({
    success: true,
    user: { id: signedIn.user.id, email: signedIn.user.email },
    session: {
      access_token: signedIn.session.access_token,
      refresh_token: signedIn.session.refresh_token,
      expires_at: signedIn.session.expires_at
    },
    requiresEmailConfirmation: false
  });
});

app.post("/api/auth/login", async (req, res) => {
  if (!authClient) return res.status(503).json({ error: "Authentication is not configured" });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(password)) {
    return res.status(400).json({ error: "Email aur 6-digit password sahi enter karein." });
  }
  const { data, error } = await authClient.auth.signInWithPassword({ email, password });
  if (error || !data.session) {
    return res.status(401).json({ error: "Email/password galat hai ya email verify nahi hua." });
  }
  res.json({
    success: true,
    user: { id: data.user.id, email: data.user.email },
    session: {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at
    }
  });
});

app.post("/api/auth/forgot-password", async (req, res) => {
  if (!authClient) return res.status(503).json({ error: "Authentication is not configured" });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Valid email address enter karein." });
  const { error } = await authClient.auth.resetPasswordForEmail(email, { redirectTo: "https://jkpanel.shop/" });
  if (error) { console.error("Password reset request failed:", error.message); return res.status(400).json({ error: "Password reset email nahi bhej paaye. Supabase email settings check karein." }); }
  return res.json({ success: true, message: "Agar is email par account hai, password reset instructions bhej di jayengi. Inbox aur spam folder check karein." });
});

app.post("/api/auth/verify-reset-otp", async (req, res) => {
  if (!authClient) return res.status(503).json({ error: "Authentication is not configured" });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const token = typeof req.body?.token === "string" ? req.body.token.trim() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(token)) return res.status(400).json({ error: "Valid email aur 6-digit OTP enter karein." });
  const { data, error } = await authClient.auth.verifyOtp({ email, token, type: "recovery" });
  if (error || !data?.session?.access_token) return res.status(400).json({ error: "OTP galat hai ya expire ho gaya. Naya OTP mangwayein." });
  return res.json({ success: true, access_token: data.session.access_token });
});

app.post("/api/auth/complete-password-reset", async (req, res) => {
  if (!authClient) return res.status(503).json({ error: "Authentication is not configured" });
  const accessToken = typeof req.body?.accessToken === "string" ? req.body.accessToken : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!accessToken || !/^\d{6}$/.test(password)) return res.status(400).json({ error: "Verified OTP session aur 6-digit naya password required hai." });
  const { data: userData, error: userError } = await authClient.auth.getUser(accessToken);
  if (userError || !userData?.user) return res.status(401).json({ error: "OTP verification session expire ho gaya. Dobara OTP verify karein." });
  const response = await fetch(supabaseUrl.replace(/\/+$/, "") + "/auth/v1/user", { method: "PUT", headers: { "Content-Type": "application/json", "apikey": supabasePublishableKey, "Authorization": "Bearer " + accessToken }, body: JSON.stringify({ password }) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) { const msg = typeof result.msg === "string" ? result.msg : typeof result.message === "string" ? result.message : ""; return res.status(response.status >= 500 ? 502 : 400).json({ error: msg || "Naya password save nahi hua." }); }
  return res.json({ success: true, message: "Password successfully reset ho gaya." });
});
app.post("/api/auth/change-email", async (req, res) => {
  if (!authClient || !supabaseUrl) return res.status(503).json({ error: "Authentication is not configured" });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const newEmail = typeof req.body?.newEmail === "string" ? req.body.newEmail.trim().toLowerCase() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(password) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) return res.status(400).json({ error: "Current email, 6-digit password aur valid new email enter karein." });
  if (email === newEmail) return res.status(400).json({ error: "New email current email se alag hona chahiye." });
  const { data: signedIn, error: signInError } = await authClient.auth.signInWithPassword({ email, password });
  if (signInError || !signedIn?.session?.access_token) return res.status(401).json({ error: "Current email ya password sahi nahi hai." });
  try {
    const response = await fetch(supabaseUrl.replace(/\/+$/, "") + "/auth/v1/user", { method: "PUT", headers: { "Content-Type": "application/json", "apikey": supabasePublishableKey, "Authorization": "Bearer " + signedIn.session.access_token }, body: JSON.stringify({ email: newEmail }) });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) { const msg = typeof result.msg === "string" ? result.msg : typeof result.message === "string" ? result.message : typeof result.error_description === "string" ? result.error_description : ""; return res.status(response.status >= 500 ? 502 : 400).json({ error: msg || "Email change request fail hui. New email ya Supabase email settings check karein." }); }
    return res.json({ success: true, message: "Email change verification request bhej di gayi hai. New email ke inbox aur spam folder mein verification link check karein. Change confirm hone tak purana email kaam karega." });
  } catch (error) { console.error("Email change request failed:", error.message); return res.status(502).json({ error: "Email verification service abhi available nahi hai." }); }
});
app.post("/api/auth/refresh", async (req, res) => {
  if (!authClient) return res.status(503).json({ error: "Authentication is not configured" });
  const refresh_token = typeof req.body?.refresh_token === "string" ? req.body.refresh_token : "";
  if (!refresh_token) return res.status(400).json({ error: "Refresh token missing" });
  const { data, error } = await authClient.auth.refreshSession({ refresh_token });
  if (error || !data.session) return res.status(401).json({ error: "Session expire ho gaya. Dobara login karein." });
  res.json({
    success: true,
    user: { id: data.user.id, email: data.user.email },
    session: {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at
    }
  });
});

app.get("/api/my-account", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const user = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: "Login required" });

  let referralProfile;
  try {
    referralProfile = await ensureReferralProfile(user.id);
  } catch (profileError) {
    console.error("Referral profile load failed:", profileError.message);
    return res.status(500).json({ error: "Referral details load nahi ho sake." });
  }

  const [depositsResult, keysResult, walletResult, transactionsResult, referralsResult, commissionsResult, ordersResult, novapayPaymentsResult] = await Promise.all([
    supabase.from("deposit_requests").select("id, amount, transaction_id, status, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("customer_keys").select("id, product_name, key_value, status, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("wallets").select("balance").eq("user_id", user.id).maybeSingle(),
    supabase.from("wallet_transactions")
      .select("id, amount, transaction_type, status, reference, description, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(200),
    supabase.from("referral_profiles").select("user_id", { count: "exact", head: true }).eq("referred_by", user.id),
    supabase.from("referral_commissions")
      .select("id, referred_user_id, deposit_request_id, deposit_amount, commission_amount, status, created_at")
      .eq("referrer_user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("orders")
      .select('id, created_at, "Product_name", "Amount", "Payment_status", "Order status"')
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("payment_requests")
      .select("id, amount, provider_order_id, provider_payment_id, status, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100)
  ]);
  if (depositsResult.error || keysResult.error || walletResult.error || transactionsResult.error || referralsResult.error || commissionsResult.error || ordersResult.error || novapayPaymentsResult.error) {
    console.error("Customer account query failed:", depositsResult.error?.message || keysResult.error?.message || walletResult.error?.message || transactionsResult.error?.message || referralsResult.error?.message || commissionsResult.error?.message || ordersResult.error?.message || novapayPaymentsResult.error?.message);
    return res.status(500).json({ error: "Account data load nahi ho saka." });
  }
  const deposits = depositsResult.data || [];
  const transactions = transactionsResult.data || [];
  const commissions = commissionsResult.data || [];
  res.json({
    user: { id: user.id, email: user.email },
    walletBalance: Number(walletResult.data?.balance || 0),
    totalDeposited: deposits.filter(d => d.status === "approved").reduce((sum, d) => sum + Number(d.amount || 0), 0),
    pendingDeposits: deposits.filter(d => d.status === "pending").reduce((sum, d) => sum + Number(d.amount || 0), 0),
    totalWithdrawn: transactions.filter(t => t.transaction_type === "debit" && t.status === "completed").reduce((sum, t) => sum + Number(t.amount || 0), 0),
    transactions, deposits, novapayPayments: novapayPaymentsResult.data || [],
    orders: (ordersResult.data || []).map(order => ({
      id: order.id,
      product_name: order.Product_name,
      amount: Number(order.Amount || 0),
      payment_status: order.Payment_status || "pending",
      order_status: order["Order status"] || "pending",
      created_at: order.created_at
    })),
    keys: keysResult.data || [],
    referral: {
      code: referralProfile.referral_code,
      link: "https://jkpanel.shop/?ref=" + encodeURIComponent(referralProfile.referral_code),
      referredUsers: Number(referralsResult.count || 0),
      totalEarned: commissions.reduce((sum, item) => sum + Number(item.commission_amount || 0), 0),
      commissions
    }
  });
});

app.post("/api/auth/logout", (req, res) => {
  res.json({ success: true });
});

app.get("/api/status", (req, res) => {
  res.json({
    status: "ok",
    databaseConfigured: Boolean(supabase)
  });
});

app.get("/admin", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JKPanel Admin</title>
<style>
body{font-family:Arial;background:#080c12;color:white;padding:14px}
main{max-width:850px;margin:auto}
input,button,select,textarea{padding:12px;margin:6px 0;border-radius:6px;max-width:100%;box-sizing:border-box}
input{max-width:100%}
button{cursor:pointer;background:#39f58b;border:0;font-weight:bold}
.card{background:#111923;padding:16px;margin:12px 0;border-radius:10px;overflow-wrap:anywhere}
small{color:#a6b2c0}
.admin-tabs{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin:18px 0}
.admin-tabs button{padding:12px 6px;background:#1e293b;color:#e2e8f0;border:1px solid #334155}
.admin-tabs button.active{background:#39f58b;color:#062012}
.admin-section{display:none}.admin-section.active{display:block}
.search-box{width:100%;background:#0b1220;color:white;border:1px solid #334155;padding:13px;margin:8px 0 14px}
@media(max-width:480px){body{padding:10px}.admin-tabs button{font-size:12px}}
</style>
</head>
<body><main>
<h1>JKPanel <span style="color:#39f58b">Admin</span></h1>
<section id="login">
<h2>Admin Login</h2>
<form id="loginForm">
<input id="password" type="password" placeholder="Admin password" required autocomplete="current-password">
<br><button>Login</button>
</form>
</section>
<section id="dashboard" hidden>
<button id="logout">Logout</button>
<div class="admin-tabs" role="tablist">
 <button type="button" class="active" data-tab="users">Users</button>
 <button type="button" data-tab="products">Products</button>
 <button type="button" data-tab="keys">Keys Management</button>
</div>
<section id="tab-users" class="admin-section active">
 <h2>Users</h2>
 <input id="userSearch" class="search-box" type="search" placeholder="Search users by name, email or ID...">
 <button id="refreshCustomers">Refresh Users</button>
 <div id="customerList"></div>
</section>
<section id="tab-products" class="admin-section">
 <h2>Products</h2>
 <input id="productSearch" class="search-box" type="search" placeholder="Search products...">
 <button id="refreshProducts">Refresh Products</button>
 <h3 style="margin-top:16px">Add / Edit Product</h3>
<div class="card">
 <form id="productForm">
  <input id="productId" type="hidden">
  <label for="productName">Product name</label><br>
  <input id="productName" required maxlength="120" placeholder="Product name" style="width:100%"><br>
  <label for="productPrice">Selling price (₹)</label><br>
  <input id="productPrice" required type="number" min="0" max="1000000" step="0.01" placeholder="30" style="width:100%"><br>
  <label for="productDescription">Product description</label><br>
  <textarea id="productDescription" maxlength="2000" placeholder="Product ke baare mein likhein" style="width:100%;min-height:80px"></textarea><br>
  <label for="productImageFile">Product photo (phone Gallery se)</label><br>
  <input id="productImageFile" type="file" accept="image/jpeg,image/png,image/webp,image/gif" style="width:100%"><br>
  <input id="productImage" type="hidden">
  <small>JPG, PNG, WebP ya GIF • maximum 8 MB</small>
  <p id="imageUploadStatus" role="status"></p>
  <label for="productVideoFile">Product video (phone Gallery se)</label><br>
  <input id="productVideoFile" type="file" accept="video/mp4,video/webm,video/quicktime" style="width:100%"><br>
  <input id="productVideoUrl" type="hidden">
  <small>MP4, WebM ya MOV • maximum 100 MB</small>
  <p id="videoUploadStatus" role="status"></p>
  <label style="display:block;margin:10px 0"><input id="productPublished" type="checkbox" checked> Show on shop</label>
  <button type="submit" id="productSave">Add Product</button>
  <button type="button" id="productCancel" style="background:#475569;color:white">Clear</button>
 </form>
 <p id="productMessage" role="status"></p>
</div>
<div id="productList"></div>
</section>
<section id="tab-keys" class="admin-section">
 <h2>Keys Management</h2>
 <p style="color:#a6b2c0">Key records linked to existing orders/users can be searched here.</p>
 <input id="keySearch" class="search-box" type="search" placeholder="Search key/order records...">
 <button id="refreshKeys">Refresh Key Records</button>
 <div id="keyList"></div>
 <h3 style="margin-top:18px">Add / Edit Key Product</h3>
 <div class="card">
  <form id="keyGroupForm">
   <label for="keyGroupName">Key name</label><br><input id="keyGroupName" required maxlength="100" value="DRIP Wire" placeholder="DRIP Wire" style="width:100%"><br>
   <label for="keyGroupImageFile">Key photo (phone Gallery)</label><br><input id="keyGroupImageFile" type="file" accept="image/jpeg,image/png,image/webp,image/gif" style="width:100%"><input id="keyGroupImageUrl" type="hidden"><small>JPG, PNG, WebP, GIF • max 8 MB</small><p id="keyGroupImageStatus" role="status"></p>
   <label for="keyGroupVideoFile">Key video (phone Gallery)</label><br><input id="keyGroupVideoFile" type="file" accept="video/mp4,video/webm,video/quicktime" style="width:100%"><input id="keyGroupVideoUrl" type="hidden"><small>MP4, WebM, MOV • max 100 MB</small><p id="keyGroupVideoStatus" role="status"></p>
   <h4 style="margin:14px 0 6px">Duration and price options</h4><div id="keyPlanRows"></div>
   <button type="button" id="addKeyPlan" style="background:#334155;color:white">+ Add duration</button>
   <label style="display:block;margin:12px 0"><input id="keyGroupPublished" type="checkbox" checked> Show on shop</label>
   <button type="submit" id="keyGroupSave">Save Key and Durations</button><button type="button" id="keyGroupClear" style="background:#475569;color:white">Clear</button>
  </form><p id="keyGroupMessage" role="status"></p>
 </div>
 <h3 style="margin-top:18px">Saved Key Products</h3><div id="keyGroupList"></div>
 <h3 style="margin-top:18px">Orders / Key Requests</h3><div id="orders"></div>
</section>
</section>
<p id="message" role="status"></p>
<script>
(function(){
 const form=document.getElementById("loginForm");
 if(!form)return;
 form.addEventListener("submit",async function(e){
  if(typeof form.onsubmit==="function")return;
  e.preventDefault();
  const input=document.getElementById("password");
  const button=form.querySelector("button");
  const message=document.getElementById("message");
  button.disabled=true;button.textContent="Logging in...";
  message.textContent="Checking admin login...";
  try{
   const response=await fetch("/api/admin/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:input.value})});
   let data={};try{data=await response.json()}catch(_){}
   if(!response.ok)throw new Error(data.error||("Login failed (HTTP "+response.status+")"));
   document.getElementById("login").hidden=true;
   document.getElementById("dashboard").hidden=false;
   input.value="";
   message.textContent="Login successful. If sections do not load, refresh once.";
  }catch(err){
   message.textContent=err.message||"Login failed. Check password and Render ADMIN_PASSWORD.";
  }finally{button.disabled=false;button.textContent="Login";}
 });
})();
</script>
<script>
const message=document.getElementById("message");
document.querySelectorAll("[data-tab]").forEach(button=>button.addEventListener("click",()=>{
 document.querySelectorAll("[data-tab]").forEach(b=>b.classList.toggle("active",b===button));
 document.querySelectorAll(".admin-section").forEach(section=>section.classList.toggle("active",section.id==="tab-"+button.dataset.tab));
}));
function filterCards(inputId,containerId){
 const input=document.getElementById(inputId),container=document.getElementById(containerId);
 if(!input||!container)return;
 input.addEventListener("input",()=>{
  const q=input.value.trim().toLowerCase();
  container.querySelectorAll(".card").forEach(card=>card.style.display=card.textContent.toLowerCase().includes(q)?"":"none");
 });
}
filterCards("userSearch","customerList");
filterCards("productSearch","productList");
filterCards("keySearch","keyList");
async function api(url,options={}){
 const response=await fetch(url,{...options,headers:{"Content-Type":"application/json",...(options.headers||{})}});
 const data=await response.json();
 if(!response.ok)throw new Error(data.error||"Request failed");
 return data;
}
async function loadOrders(){
 try{
  const data=await api("/api/admin/orders");
  document.getElementById("login").hidden=true;
  document.getElementById("dashboard").hidden=false;
  const root=document.getElementById("orders");
  if(!root){throw new Error("Orders section missing. Page refresh karein.");}
  root.replaceChildren();
  if(!data.orders.length){root.textContent="No orders found.";return;}
  data.orders.forEach(order=>{
   const card=document.createElement("article");
   card.className="card";
   const title=document.createElement("h3");
   title.textContent=order.product_name||"Order";
   const details=document.createElement("p");
   details.textContent="Customer: "+order.customer_name+" | Amount: ₹"+order.amount;
   const id=document.createElement("small");
   id.textContent="Order ID: "+order.id+" | Created: "+(order.created_at||"");
   const payment=document.createElement("p");
   payment.textContent="Payment: "+order.payment_status;
   const supplier=document.createElement("p");
   supplier.textContent="Supplier delivery: "+(order.supplier_status||"not_started")+(order.supplier_duration?" ("+order.supplier_duration+")":"")+(order.supplier_error?" — "+order.supplier_error:"");
   const verifyPayment=document.createElement("button");
   verifyPayment.textContent="Mark payment verified";
   verifyPayment.disabled=order.payment_status==="paid";
   verifyPayment.style.marginRight="8px";
   verifyPayment.onclick=async()=>{
    if(!confirm("Payment ko bank/UPI statement se verify kiya hai? Sirf confirmed payment par OK karein."))return;
    try{
     await api("/api/admin/orders/"+encodeURIComponent(order.id)+"/payment",{method:"PATCH",body:JSON.stringify({payment_status:"paid"})});
     message.textContent="Payment marked paid after manual verification.";
     await loadOrders();
    }catch(e){message.textContent=e.message;}
   };
   const orderStatus=document.createElement("p");
   orderStatus.textContent="Order status: "+order.order_status;
   const select=document.createElement("select");
   ["pending","processing","completed","cancelled"].forEach(status=>{
    const option=document.createElement("option");
    option.value=status;option.textContent=status;
    option.selected=status===order.order_status;select.appendChild(option);
   });
   const save=document.createElement("button");
   save.textContent="Update status";
   save.onclick=async()=>{
    try{
     await api("/api/admin/orders/"+encodeURIComponent(order.id),{
      method:"PATCH",body:JSON.stringify({order_status:select.value})
     });
     message.textContent="Order status updated.";
     await loadOrders();
    }catch(e){message.textContent=e.message;}
   };
   card.append(title,details,id,payment,supplier,verifyPayment,orderStatus,document.createElement("br"),select,save);
   root.appendChild(card);
  });
  message.textContent="";
 }catch(e){
  // Keep the current screen visible when an individual data request fails.
  // Only a failed login should leave the admin on the login screen.
  message.textContent=e.message;
 }
}
document.getElementById("loginForm").onsubmit=async e=>{
 e.preventDefault();
 message.textContent="";
 const passwordInput=document.getElementById("password");
 const loginButton=document.querySelector("#loginForm button");
 loginButton.disabled=true;
 loginButton.textContent="Logging in...";
 try{
  await api("/api/admin/login",{method:"POST",body:JSON.stringify({password:passwordInput.value})});
  passwordInput.value="";
  document.getElementById("login").hidden=true;
  document.getElementById("dashboard").hidden=false;
  message.textContent="Login successful. Admin panel loading...";
  await Promise.allSettled([loadOrders(),loadCustomers(),loadProducts(),loadKeyGroups()]);
  if(!message.textContent) message.textContent="Admin panel ready.";
 }catch(err){
  message.textContent=err.message||"Login failed. Password aur Render environment setting check karein.";
  document.getElementById("dashboard").hidden=true;
  document.getElementById("login").hidden=false;
 }finally{
  loginButton.disabled=false;
  loginButton.textContent="Login";
 }
};


async function loadProducts(){
 try{
  const data=await api("/api/admin/products");
  const root=document.getElementById("productList");
  if(!root){throw new Error("Products section missing. Page refresh karein.");}
  root.replaceChildren();
  if(!data.products.length){root.textContent="No products yet. Add your first product above.";return;}
  data.products.forEach(product=>{
   const card=document.createElement("article");card.className="card";
   const title=document.createElement("h3");title.textContent=product.name;
   const info=document.createElement("p");info.textContent="Price: ₹"+Number(product.price).toFixed(2)+" | "+(product.published?"Published":"Hidden");
   const description=document.createElement("p");description.textContent=product.description||"No description";
   const img=document.createElement("p");img.textContent=product.image_url||"No image URL";
   const video=document.createElement("p");video.textContent=product.video_url?"Video: "+product.video_url:"No video uploaded";
   const edit=document.createElement("button");edit.textContent="Edit";
   edit.onclick=()=>{
    document.getElementById("productId").value=product.id;
    document.getElementById("productName").value=product.name;
    document.getElementById("productPrice").value=product.price;
    document.getElementById("productDescription").value=product.description||"";
    document.getElementById("productImage").value=product.image_url||"";
    document.getElementById("productVideoUrl").value=product.video_url||"";
    document.getElementById("productVideoFile").value="";
    document.getElementById("videoUploadStatus").textContent=product.video_url?"Current video saved. Nayi video select karne par replace hogi.":"";
    document.getElementById("productPublished").checked=Boolean(product.published);
    document.getElementById("productSave").textContent="Save Changes";
    document.getElementById("productMessage").textContent="Editing: "+product.name;
    document.getElementById("productForm").scrollIntoView({behavior:"smooth",block:"center"});
   };
   const toggle=document.createElement("button");toggle.style.marginLeft="8px";toggle.style.background=product.published?"#b45309":"#059669";toggle.style.color="white";toggle.textContent=product.published?"Hide from shop":"Publish";
   toggle.onclick=async()=>{
    try{await api("/api/admin/products/"+encodeURIComponent(product.id),{method:"PATCH",body:JSON.stringify({published:!product.published})});await loadProducts();message.textContent="Product visibility updated.";}
    catch(e){document.getElementById("productMessage").textContent=e.message;}
   };
   card.append(title,info,description,img,video,edit,toggle);root.appendChild(card);
  });
 }catch(e){document.getElementById("productMessage").textContent=e.message;}
}
function clearProductForm(){
 document.getElementById("productForm").reset();
 document.getElementById("productId").value="";
 document.getElementById("productPublished").checked=true;
 document.getElementById("productImage").value="";
 document.getElementById("productImageFile").value="";
 document.getElementById("imageUploadStatus").textContent="";
 document.getElementById("productVideoUrl").value="";
 document.getElementById("productVideoFile").value="";
 document.getElementById("videoUploadStatus").textContent="";
 document.getElementById("productSave").textContent="Add Product";
 document.getElementById("productMessage").textContent="";
}
document.getElementById("productCancel").onclick=clearProductForm;
document.getElementById("productForm").onsubmit=async e=>{
 e.preventDefault();
 const id=document.getElementById("productId").value;
 const status=document.getElementById("productMessage");
 const videoStatus=document.getElementById("videoUploadStatus");
 try{
  status.textContent=id?"Saving changes...":"Adding product...";
  let imageUrl=document.getElementById("productImage").value.trim();
  const imageStatus=document.getElementById("imageUploadStatus");
  const imageFile=document.getElementById("productImageFile").files[0];
  if(imageFile){
   if(imageFile.size>8*1024*1024)throw new Error("Photo 8 MB se chhoti honi chahiye.");
   imageStatus.textContent="Gallery photo upload ho rahi hai...";
   const imageForm=new FormData();imageForm.append("image",imageFile);
   const imageResponse=await fetch("/api/admin/product-image",{method:"POST",body:imageForm});
   const imageText=await imageResponse.text();let imageData={};
   try{imageData=imageText?JSON.parse(imageText):{};}catch{}
   if(!imageResponse.ok)throw new Error(imageData.error||"Photo upload fail hua.");
   imageUrl=imageData.image_url;
   document.getElementById("productImage").value=imageUrl;
   imageStatus.textContent="Photo upload ho gayi.";
  }
  let videoUrl=document.getElementById("productVideoUrl").value.trim();
  const videoFile=document.getElementById("productVideoFile").files[0];
  if(videoFile){
   if(videoFile.size>100*1024*1024)throw new Error("Video 100 MB se chhoti honi chahiye.");
   videoStatus.textContent="Gallery video upload ho rahi hai...";
   const formData=new FormData();formData.append("video",videoFile);
   const uploadResponse=await fetch("/api/admin/product-video",{method:"POST",body:formData});
   const uploadText=await uploadResponse.text();let uploadData={};
   try{uploadData=uploadText?JSON.parse(uploadText):{};}catch{}
   if(!uploadResponse.ok)throw new Error(uploadData.error||"Video upload fail hua.");
   videoUrl=uploadData.video_url;
   document.getElementById("productVideoUrl").value=videoUrl;
   videoStatus.textContent="Video upload ho gaya.";
  }
  const payload={
   name:document.getElementById("productName").value.trim(),
   price:Number(document.getElementById("productPrice").value),
   image_url:imageUrl||null,
   video_url:videoUrl||null,
   published:document.getElementById("productPublished").checked,
   description:document.getElementById("productDescription").value.trim()
  };
  await api(id?"/api/admin/products/"+encodeURIComponent(id):"/api/admin/products",{
   method:id?"PATCH":"POST",body:JSON.stringify(payload)
  });
  clearProductForm();status.textContent="Product saved successfully.";
  await loadProducts();
 }catch(err){status.textContent=err.message;}
};


const keyPlanSeed=[{duration:"6 Hours",price:"70"},{duration:"12 Hours",price:"130"},{duration:"1 Day",price:"250"},{duration:"7 Days",price:"550"}];
function addKeyPlanRow(duration="",price=""){
 const root=document.getElementById("keyPlanRows"),row=document.createElement("div");row.className="card key-plan-row";row.style.cssText="padding:10px;margin:8px 0;border:1px solid #334155";
 const fields=document.createElement("div");fields.style.cssText="display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:8px";
 const time=document.createElement("input");time.className="key-plan-duration";time.required=true;time.maxLength=80;time.placeholder="Duration, e.g. 3 Hours";time.value=duration;time.style.width="100%";
 const cost=document.createElement("input");cost.className="key-plan-price";cost.required=true;cost.type="number";cost.min="0";cost.max="1000000";cost.step="0.01";cost.placeholder="Price ₹";cost.value=price;cost.style.width="100%";
 const remove=document.createElement("button");remove.type="button";remove.textContent="Remove duration";remove.style.cssText="background:#7f1d1d;color:white";remove.onclick=()=>row.remove();
 fields.append(time,cost);row.append(fields,remove);root.appendChild(row);
}
function clearKeyGroupForm(){
 document.getElementById("keyGroupForm").reset();document.getElementById("keyGroupName").value="DRIP Wire";
 ["keyGroupImageUrl","keyGroupVideoUrl","keyGroupImageFile","keyGroupVideoFile","keyGroupImageStatus","keyGroupVideoStatus"].forEach(id=>{const e=document.getElementById(id);if(e)e.value!==undefined?e.value="":e.textContent="";});
 document.getElementById("keyGroupPublished").checked=true;document.getElementById("keyPlanRows").replaceChildren();keyPlanSeed.forEach(p=>addKeyPlanRow(p.duration,p.price));
 document.getElementById("keyGroupSave").textContent="Save Key and Durations";document.getElementById("keyGroupMessage").textContent="";
}
async function uploadKeyGroupMedia(){
 let imageUrl=document.getElementById("keyGroupImageUrl").value.trim(),videoUrl=document.getElementById("keyGroupVideoUrl").value.trim();
 const imageFile=document.getElementById("keyGroupImageFile").files[0],videoFile=document.getElementById("keyGroupVideoFile").files[0];
 if(imageFile){if(imageFile.size>8*1024*1024)throw new Error("Photo 8 MB se chhoti honi chahiye.");const status=document.getElementById("keyGroupImageStatus");status.textContent="Photo upload ho rahi hai...";
  const body=new FormData();body.append("image",imageFile);const r=await fetch("/api/admin/product-image",{method:"POST",body});const raw=await r.text();let d={};try{d=raw?JSON.parse(raw):{};}catch{}if(!r.ok)throw new Error(d.error||"Photo upload fail hua.");imageUrl=d.image_url;document.getElementById("keyGroupImageUrl").value=imageUrl;status.textContent="Photo upload ho gayi.";}
 if(videoFile){if(videoFile.size>100*1024*1024)throw new Error("Video 100 MB se chhoti honi chahiye.");const status=document.getElementById("keyGroupVideoStatus");status.textContent="Video upload ho raha hai...";
  const body=new FormData();body.append("video",videoFile);const r=await fetch("/api/admin/product-video",{method:"POST",body});const raw=await r.text();let d={};try{d=raw?JSON.parse(raw):{};}catch{}if(!r.ok)throw new Error(d.error||"Video upload fail hua.");videoUrl=d.video_url;document.getElementById("keyGroupVideoUrl").value=videoUrl;status.textContent="Video upload ho gaya.";}
 return {imageUrl,videoUrl};
}
async function loadKeyGroups(){
 const root=document.getElementById("keyGroupList");if(!root)return;
 try{const data=await api("/api/admin/products");root.replaceChildren();const products=Array.isArray(data.products)?data.products:[];
  const groups=new Map();products.forEach(p=>{const m=String(p.name||"").match(/^(.*?)\\s*-\\s*(.+)$/);const base=m?m[1].trim():p.name;if(!groups.has(base))groups.set(base,[]);groups.get(base).push(p);});
  if(!groups.size){root.textContent="Abhi koi key product nahi hai.";return;}
  [...groups.entries()].forEach(([base,items])=>{const card=document.createElement("article");card.className="card";const title=document.createElement("h3");title.textContent=base;
   const active=items.filter(p=>p.published);const info=document.createElement("p");info.textContent=active.length+" active duration option(s) · "+items.length+" saved option(s)";
   const options=document.createElement("p");options.style.cssText="white-space:pre-line;line-height:1.8";options.textContent=items.map(p=>String(p.name).slice(base.length).replace(/^\\s*-\\s*/,"")+" — ₹"+Number(p.price).toFixed(2)+(p.published?"":" (hidden)")).join("\n");
   const edit=document.createElement("button");edit.textContent="Edit this key";edit.onclick=()=>{document.getElementById("keyGroupName").value=base;document.getElementById("keyGroupImageUrl").value=(items.find(p=>p.image_url)?.image_url)||"";document.getElementById("keyGroupVideoUrl").value=(items.find(p=>p.video_url)?.video_url)||"";
    document.getElementById("keyGroupImageFile").value="";document.getElementById("keyGroupVideoFile").value="";
    document.getElementById("keyGroupImageStatus").textContent=document.getElementById("keyGroupImageUrl").value?"Current photo saved. Nayi photo select karne par replace hogi.":"";
    document.getElementById("keyGroupVideoStatus").textContent=document.getElementById("keyGroupVideoUrl").value?"Current video saved. Nayi video select karne par replace hogi.":"";
    document.getElementById("keyGroupPublished").checked=active.length>0;document.getElementById("keyPlanRows").replaceChildren();active.forEach(p=>addKeyPlanRow(String(p.name).slice(base.length).replace(/^\\s*-\\s*/,""),String(p.price)));
    document.getElementById("keyGroupSave").textContent="Update Key and Durations";document.getElementById("keyGroupMessage").textContent="Editing: "+base;document.getElementById("keyGroupForm").scrollIntoView({behavior:"smooth",block:"center"});};
   card.append(title,info,options,edit);root.appendChild(card);});
 }catch(e){root.textContent=e.message||"Key products load nahi ho sake.";}
}
document.getElementById("addKeyPlan").onclick=()=>addKeyPlanRow();
document.getElementById("keyGroupClear").onclick=clearKeyGroupForm;
document.getElementById("keyGroupForm").onsubmit=async e=>{
 e.preventDefault();const status=document.getElementById("keyGroupMessage"),base=document.getElementById("keyGroupName").value.trim(),published=document.getElementById("keyGroupPublished").checked;
 const rows=[...document.querySelectorAll("#keyPlanRows .key-plan-row")].map(row=>({duration:row.querySelector(".key-plan-duration").value.trim(),price:Number(row.querySelector(".key-plan-price").value)}));
 if(!base||base.length>100){status.textContent="Valid key name enter karein.";return;}if(!rows.length){status.textContent="Kam se kam ek duration add karein.";return;}
 const seen=new Set();for(const row of rows){const key=row.duration.toLowerCase();if(!row.duration||row.duration.length>80||seen.has(key)){status.textContent="Har duration ka naam bharein aur duplicate duration na rakhein.";return;}if(!Number.isFinite(row.price)||row.price<0||row.price>1000000){status.textContent="Har duration ki valid price enter karein.";return;}seen.add(key);}
 const save=document.getElementById("keyGroupSave");save.disabled=true;
 try{status.textContent="Photo/video aur duration options save ho rahe hain...";const media=await uploadKeyGroupMedia();const current=await api("/api/admin/products"),all=current.products||[];
  const existing=all.filter(p=>String(p.name||"").startsWith(base+" - ")),wanted=new Set(rows.map(p=>(base+" - "+p.duration).toLowerCase()));
  for(const old of existing){if(!wanted.has(String(old.name).toLowerCase())&&old.published)await api("/api/admin/products/"+encodeURIComponent(old.id),{method:"PATCH",body:JSON.stringify({published:false})});}
  for(const plan of rows){const name=base+" - "+plan.duration,old=all.find(p=>String(p.name||"").toLowerCase()===name.toLowerCase());
   const payload={name,price:plan.price,image_url:media.imageUrl||null,video_url:media.videoUrl||null,published,description:""};
   if(old)await api("/api/admin/products/"+encodeURIComponent(old.id),{method:"PATCH",body:JSON.stringify(payload)});else await api("/api/admin/products",{method:"POST",body:JSON.stringify(payload)});
  }
  status.textContent="Key aur "+rows.length+" duration option(s) Supabase mein save ho gaye.";clearKeyGroupForm();await Promise.all([loadKeyGroups(),loadProducts()]);
 }catch(err){status.textContent=err.message||"Key save nahi ho saki.";}finally{save.disabled=false;}
};

async function loadCustomers(){
 try{
  const data=await api("/api/admin/customers");
  const root=document.getElementById("customerList");
  if(!root){throw new Error("Users section missing. Page refresh karein.");}
  root.replaceChildren();
  const summary=document.createElement("p");
  summary.textContent="Registered customers: "+data.customers.length+" | Old/guest deposits: "+data.unlinkedDeposits.length;
  root.appendChild(summary);
  data.customers.forEach(customer=>{
   const card=document.createElement("article");card.className="card";
   const title=document.createElement("h3");title.textContent=customer.email||"No email";
   const info=document.createElement("p");
   info.textContent="Joined: "+(customer.created_at||"")+" | Email verified: "+(customer.confirmed?"Yes":"No")+" | Approved deposits: ₹"+Number(customer.totalDeposited||0).toFixed(2)+" | Pending: ₹"+Number(customer.pendingDeposits||0).toFixed(2);
   card.append(title,info);
   const creditTitle=document.createElement("h4");creditTitle.textContent="Manual Wallet Credit";card.appendChild(creditTitle);
   const creditForm=document.createElement("form");
   const creditAmount=document.createElement("input");creditAmount.type="number";creditAmount.min="1";creditAmount.max="50000";creditAmount.step="0.01";creditAmount.required=true;creditAmount.placeholder="Amount (₹)";creditAmount.style.width="100%";
   const creditReason=document.createElement("input");creditReason.type="text";creditReason.minLength=3;creditReason.maxLength=200;creditReason.required=true;creditReason.placeholder="Reason (Bonus / Promotion / Correction)";creditReason.style.width="100%";
   const creditButton=document.createElement("button");creditButton.type="submit";creditButton.textContent="Add Balance";
   const creditStatus=document.createElement("p");creditStatus.setAttribute("role","status");
   creditForm.append(creditAmount,creditReason,creditButton,creditStatus);
   creditForm.onsubmit=async ev=>{
    ev.preventDefault();
    const amount=Number(creditAmount.value),reason=creditReason.value.trim();
    if(!Number.isFinite(amount)||amount<=0||amount>50000||Math.round(amount*100)!==amount*100){creditStatus.textContent="Amount ₹1 se ₹50,000 tak aur maximum 2 decimal places hona chahiye.";return;}
    if(reason.length<3){creditStatus.textContent="Reason kam se kam 3 characters ka likhein.";return;}
    if(!confirm(customer.email+" ke wallet mein ₹"+amount.toFixed(2)+" add karna hai?"))return;
    creditButton.disabled=true;creditStatus.textContent="Balance add ho raha hai...";
    try{
     const result=await api("/api/admin/wallet-credit",{method:"POST",body:JSON.stringify({user_id:customer.id,amount,reason})});
     creditStatus.textContent="Added ₹"+Number(result.credited_amount).toFixed(2)+" | New balance: ₹"+Number(result.wallet_balance).toFixed(2);
     creditAmount.value="";creditReason.value="";
    }catch(err){creditStatus.textContent=err.message;}
    finally{creditButton.disabled=false;}
   };
   card.appendChild(creditForm);
   const depositsTitle=document.createElement("h4");depositsTitle.textContent="Deposit history ("+customer.deposits.length+")";card.appendChild(depositsTitle);
   customer.deposits.forEach(d=>{
    const p=document.createElement("p");
    p.textContent="₹"+d.amount+" | "+d.status+" | UTR: "+d.transaction_id+" | "+(d.created_at||"");
    card.appendChild(p);
   });
   const keysTitle=document.createElement("h4");keysTitle.textContent="Customer keys ("+customer.keys.length+")";keysTitle.style.marginTop="10px";card.appendChild(keysTitle);
   if(!customer.keys.length){const none=document.createElement("p");none.textContent="No keys assigned.";card.appendChild(none);}
   customer.keys.forEach(k=>{
    const p=document.createElement("p");p.textContent=k.product_name+" | KEY: "+k.key_value+" | "+k.status+" | "+(k.created_at||"");card.appendChild(p);
   });
   root.appendChild(card);
  });
  if(data.unlinkedDeposits.length){
   const old=document.createElement("article");old.className="card";
   const heading=document.createElement("h3");heading.textContent="Old / unlinked deposit requests";
   old.appendChild(heading);
   data.unlinkedDeposits.forEach(d=>{const p=document.createElement("p");p.textContent=(d.customer_email||"Guest")+" | ₹"+d.amount+" | "+d.status+" | UTR: "+d.transaction_id;old.appendChild(p);});
   root.appendChild(old);
  }
 }catch(e){message.textContent=e.message;}
}

document.getElementById("refreshCustomers").onclick=async()=>{await loadCustomers();};
document.getElementById("refreshProducts").onclick=async()=>{await loadProducts();};
document.getElementById("refreshKeys").onclick=async()=>{await loadCustomers();await loadKeyGroups();};
document.getElementById("logout").onclick=async()=>{
 try{await api("/api/admin/logout",{method:"POST"});}catch(e){}
 document.getElementById("dashboard").hidden=true;
 document.getElementById("login").hidden=false;
 message.textContent="Logged out.";
};
loadOrders();
loadCustomers();
loadProducts();
loadKeyGroups();
clearKeyGroupForm();
</script>
</main></body></html>`);
});

app.post("/api/admin/login", (req, res) => {
  if (!adminPassword) {
    return res.status(503).json({ error: "Admin password is not configured" });
  }

  const password = req.body?.password;
  if (typeof password !== "string" || password.length > 200) {
    return res.status(400).json({ error: "Enter a valid password" });
  }

  const submitted = Buffer.from(password);
  const expected = Buffer.from(adminPassword);
  const valid =
    submitted.length === expected.length &&
    crypto.timingSafeEqual(submitted, expected);

  if (!valid) {
    return res.status(401).json({ error: "Incorrect password" });
  }

  const expiry = Date.now() + 2 * 60 * 60 * 1000;
  const token = expiry + "." + signToken(expiry);

  res.setHeader(
    "Set-Cookie",
    "jk_admin=" + token +
      "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=7200"
  );

  res.json({ success: true });
});

app.post("/api/admin/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "jk_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
  );
  res.json({ success: true });
});

app.get("/api/admin/orders", isAdmin, async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Database is not configured" });
  }

  const { data, error } = await supabase
    .from("orders")
    .select('id, created_at, customer_name:"Customer_name", product_name:"Product_name", amount:"Amount", payment_status:"Payment_status", order_status:"Order status", supplier_status, supplier_duration, supplier_error')
    .order("created_at", { ascending: false }).limit(100);

  if (error) {
    console.error("Admin order query failed:", error.message);
    return res.status(500).json({ error: "Could not load orders" });
  }

  res.json({ orders: data });
});

function dripWireDuration(productName) {
  const original = String(productName || "").trim();
  const name = original.toLowerCase().replace(/\s+/g, " ");
  if (name === "drip wire - 6 hours") return "6 Hours";
  if (name === "drip wire - 12 hours") return "12 Hours";
  if (name === "drip wire - 1 day") return "1 Day";
  if (name === "drip wire - 7 days") return "7 Days";
  const match = original.match(/^DRIP Wire\s*-\s*(.+)$/i);
  return match ? match[1].trim() : null;
}
function aimHackDuration(productName) {
  const name = String(productName || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (name === "aim hack ff" || name === "aim hack ff - 1 hour") return "1 Hour";
  if (name === "aim hack ff - 3 hours") return "3 Hours";
  if (name === "aim hack ff - 6 hours") return "6 Hours";
  if (name === "aim hack ff - 12 hours") return "12 Hours";
  if (name === "aim hack ff - 1 day") return "1 Day";
  if (name === "aim hack ff - 3 days") return "3 Days";
  if (name === "aim hack ff - 7 days") return "7 Days";
  if (name === "aim hack ff - 30 days") return "30 Days";
  return null;
}

async function purchaseDripWireKey({ orderId, userId, productName, duration, supplierProductId = "150" }) {
  const apiKey = String(process.env.RESELLER_API_KEY || "").trim();
  const masterKey = String(process.env.RESELLER_ACCESS_TOKEN || "").trim();
  if (!apiKey || !masterKey) {
    throw new Error("Supplier API credentials missing in backend environment.");
  }

  const body = new URLSearchParams({
    api_key: apiKey,
    action: "buy",
    product_id: String(supplierProductId),
    duration,
    quantity: "1"
  });
  const response = await fetch("https://bantibhaiya.to/api/reseller_v1.php", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "x-master-key": masterKey,
      "Accept": "application/json"
    },
    body,
    signal: AbortSignal.timeout(25000)
  });
  const raw = await response.text();
  let result;
  try { result = raw ? JSON.parse(raw) : {}; }
  catch { throw new Error("Supplier returned an invalid response."); }

  if (!response.ok || result.success === false || result.status === "error" || !Array.isArray(result.keys) || result.keys.length < 1) {
    // Log only response metadata, never credentials or any returned key material.
    console.error("Supplier API response diagnostic:", JSON.stringify({
      httpStatus: response.status,
      responseFields: result && typeof result === "object" ? Object.keys(result).slice(0, 30) : [],
      success: typeof result?.success === "boolean" ? result.success : null,
      status: typeof result?.status === "string" ? result.status.slice(0, 80) : null,
      error: typeof result?.error === "string" ? result.error.slice(0, 200) : null,
      message: typeof result?.message === "string" ? result.message.slice(0, 200) : null,
      msg: typeof result?.msg === "string" ? result.msg.slice(0, 200) : null,
      keysCount: Array.isArray(result?.keys) ? result.keys.length : null
    }));
    const message = typeof result.error === "string" ? result.error :
      typeof result.message === "string" ? result.message :
      typeof result.msg === "string" ? result.msg :
      "Supplier did not return any keys.";
    throw new Error(message.slice(0, 300));
  }

  const keys = result.keys.map(item => {
    if (typeof item === "string") return item.trim();
    if (item && typeof item === "object") {
      return String(item.key || item.license_key || item.code || item.key_value || "").trim();
    }
    return "";
  }).filter(Boolean);

  if (!keys.length) throw new Error("Supplier response contained no usable keys.");

  const rows = keys.map(keyValue => ({
    user_id: userId,
    order_id: orderId,
    product_name: productName,
    key_value: keyValue,
    status: "active"
  }));
  const { error: keysError } = await supabase.from("customer_keys").insert(rows);
  if (keysError) throw new Error("Supplier purchase may have succeeded, but saving keys failed. Admin must check supplier order before retrying.");

  const { error: updateError } = await supabase.from("orders").update({
    supplier_status: "completed",
    supplier_duration: duration,
    supplier_error: null,
    supplier_keys: keys,
    "Order status": "completed"
  }).eq("id", orderId);
  if (updateError) {
    console.error("Supplier keys saved but order status update failed:", updateError.message);
    throw new Error("Keys were saved to customer account, but order status update failed.");
  }
  return { keyCount: keys.length };
}

app.patch("/api/admin/orders/:id/payment", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  if (req.body?.payment_status !== "paid") {
    return res.status(400).json({ error: "Only verified payment can be marked paid." });
  }

  const { data: existing, error: lookupError } = await supabase.from("orders")
    .select('id, user_id, "Product_name", "Payment_status", supplier_status')
    .eq("id", req.params.id).maybeSingle();
  if (lookupError) {
    console.error("Order payment lookup failed:", lookupError.message);
    return res.status(500).json({ error: "Could not verify order payment" });
  }
  if (!existing || existing.Payment_status !== "pending") {
    return res.status(409).json({ error: "Order not found or payment is not pending." });
  }

  const productName = existing["Product_name"] || "";
  const isDripWire = /^DRIP Wire - /i.test(productName);
  const isAimHack = /^AIM HACK FF(?: - |$)/i.test(productName);
  const duration = isDripWire ? dripWireDuration(productName) : (isAimHack ? aimHackDuration(productName) : null);
  const usesSupplier = isDripWire || isAimHack;
  const supplierProductId = isAimHack ? "133" : "150";
  const nextSupplierStatus = usesSupplier ? (duration ? "processing" : "failed") : "not_applicable";

  const { data, error } = await supabase.from("orders")
    .update({
      "Payment_status": "paid",
      supplier_status: nextSupplierStatus,
      supplier_duration: duration,
      supplier_error: usesSupplier && !duration ? "Unsupported supplier product duration." : null
    })
    .eq("id", req.params.id)
    .eq("Payment_status", "pending")
    .select('id, "Payment_status", supplier_status, supplier_duration')
    .maybeSingle();
  if (error) {
    console.error("Order payment update failed:", error.message);
    return res.status(500).json({ error: "Could not update payment status" });
  }
  if (!data) return res.status(409).json({ error: "Order not found or payment is not pending." });

  if (!usesSupplier) {
    return res.json({ success: true, order: data, message: "Payment verified. This product does not use the automatic supplier." });
  }
  if (!duration) {
    return res.status(422).json({ success: false, order: data, error: "Payment verified, but this supplier duration is not configured. Contact admin." });
  }

  try {
    const delivered = await purchaseDripWireKey({
      orderId: existing.id,
      userId: existing.user_id,
      productName,
      duration,
      supplierProductId
    });
    const { data: finalOrder } = await supabase.from("orders")
      .select('id, "Payment_status", supplier_status, supplier_duration, "Order status"')
      .eq("id", existing.id).maybeSingle();
    return res.json({
      success: true,
      order: finalOrder || data,
      supplier: { status: "completed", keyCount: delivered.keyCount },
      message: "Payment verified and key delivered to My Account."
    });
  } catch (purchaseError) {
    const safeMessage = String(purchaseError?.message || "Supplier purchase failed").slice(0, 300);
    console.error("DRIP Wire supplier purchase failed:", safeMessage);
    await supabase.from("orders").update({
      supplier_status: "failed",
      supplier_error: safeMessage
    }).eq("id", existing.id);
    return res.status(502).json({
      success: false,
      order: { ...data, supplier_status: "failed" },
      error: "Payment verified, but supplier key delivery failed. Check supplier status before attempting any retry."
    });
  }
});

app.patch("/api/admin/orders/:id", isAdmin, async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Database is not configured" });
  }
  const { order_status } = req.body || {};
  const allowed = ["pending", "processing", "completed", "cancelled"];
  if (!allowed.includes(order_status)) {
    return res.status(400).json({ error: "Invalid order status" });
  }
  if (["processing", "completed"].includes(order_status)) {
    const { data: existing, error: lookupError } = await supabase.from("orders")
      .select('"Payment_status"').eq("id", req.params.id).maybeSingle();
    if (lookupError) return res.status(500).json({ error: "Could not verify order payment" });
    if (!existing) return res.status(404).json({ error: "Order not found" });
    if (existing.Payment_status !== "paid") {
      return res.status(409).json({ error: "Payment verify hone ke baad hi order processing/completed karein." });
    }
  }
  const { data, error } = await supabase.from("orders")
    .update({ "Order status": order_status })
    .eq("id", req.params.id)
    .select('id, "Order status"')
    .maybeSingle();
  if (error) {
    console.error("Order update failed:", error.message);
    return res.status(500).json({ error: "Could not update order" });
  }
  if (!data) return res.status(404).json({ error: "Order not found" });
  res.json({ order: data });
});


app.get("/api/admin/customers", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  try {
    const [usersResult, depositsResult, keysResult] = await Promise.all([
      supabase.auth.admin.listUsers({ page: 1, perPage: 1000 }),
      supabase.from("deposit_requests")
        .select("id, user_id, customer_email, amount, transaction_id, status, created_at")
        .order("created_at", { ascending: false }).limit(1000),
      supabase.from("customer_keys")
        .select("id, user_id, product_name, key_value, status, created_at")
        .order("created_at", { ascending: false }).limit(1000)
    ]);
    if (usersResult.error || depositsResult.error || keysResult.error) {
      console.error("Admin customer data failed:", usersResult.error?.message || depositsResult.error?.message || keysResult.error?.message);
      return res.status(500).json({ error: "Customer/deposit/key data load nahi ho saka." });
    }
    const users = usersResult.data?.users || [];
    const deposits = depositsResult.data || [];
    const keys = keysResult.data || [];
    const customers = users.map(user => {
      const userDeposits = deposits.filter(d => d.user_id === user.id);
      const userKeys = keys.filter(k => k.user_id === user.id);
      return {
        id: user.id,
        email: user.email || "",
        created_at: user.created_at,
        confirmed: Boolean(user.email_confirmed_at),
        totalDeposited: userDeposits.filter(d => d.status === "approved").reduce((sum,d) => sum + Number(d.amount || 0), 0),
        pendingDeposits: userDeposits.filter(d => d.status === "pending").reduce((sum,d) => sum + Number(d.amount || 0), 0),
        deposits: userDeposits,
        keys: userKeys
      };
    });
    const unlinkedDeposits = deposits.filter(d => !d.user_id).map(d => ({
      ...d, customer_email: d.customer_email || "Old/guest request"
    }));
    res.json({ customers, unlinkedDeposits });
  } catch (e) {
    console.error("Admin customer data exception:", e.message);
    res.status(500).json({ error: "Customer data load nahi ho saka." });
  }
});

app.post("/api/admin/wallet-credit", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const userId = typeof req.body?.user_id === "string" ? req.body.user_id.trim() : "";
  const amount = Number(req.body?.amount);
  const reason = typeof req.body?.reason === "string" ? req.body.reason.trim() : "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) {
    return res.status(400).json({ error: "Valid customer account required" });
  }
  if (!Number.isFinite(amount) || amount <= 0 || amount > 50000 || Math.round(amount * 100) !== amount * 100) {
    return res.status(400).json({ error: "Amount ₹1 se ₹50,000 tak aur maximum 2 decimal places hona chahiye." });
  }
  if (reason.length < 3 || reason.length > 200) {
    return res.status(400).json({ error: "Reason 3 se 200 characters ka hona chahiye." });
  }
  try {
    const { data, error } = await supabase.rpc("admin_add_wallet_credit", {
      p_user_id: userId, p_amount: amount, p_reason: reason
    });
    if (error) {
      console.error("Admin wallet credit failed:", error.message);
      return res.status(500).json({ error: "Wallet credit nahi ho saka. Database function/schema check karein." });
    }
    return res.json({ success: true, ...data });
  } catch (e) {
    console.error("Admin wallet credit exception:", e.message);
    return res.status(500).json({ error: "Wallet credit nahi ho saka." });
  }
});


function safeTokenEqual(received, expected) {
  if (typeof received !== "string" || typeof expected !== "string" || !received || !expected) return false;
  const a = Buffer.from(received);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function novapayPost(url, fields) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) body.set(key, String(value ?? ""));
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const raw = await response.text();
  let data;
  try { data = raw ? JSON.parse(raw) : {}; }
  catch { throw new Error("Payment gateway returned an invalid response"); }
  if (!response.ok) throw new Error("Payment gateway request failed");
  return data;
}

async function verifyNovapayOrder(orderId, expectedAmount) {
  const token = process.env.NOVAPAY_USER_TOKEN;
  if (!token) throw new Error("Payment gateway is not configured");
  const data = await novapayPost("https://novaapay.shop/api/check-order-status", {
    user_token: token,
    order_id: orderId
  });
  const result = data?.result || {};
  // NovaPay can report the final state as COMPLETE as well as COMPLETED/SUCCESS.
  // Check all known status fields instead of letting an earlier non-final field mask the final one.
  const statuses = [
    data?.status,
    data?.payment_status,
    data?.txnStatus,
    result?.status,
    result?.payment_status,
    result?.paymentStatus,
    result?.txnStatus,
    result?.transaction_status
  ].map(value => String(value ?? "").trim().toUpperCase());
  const paidStatuses = new Set(["COMPLETE", "COMPLETED", "SUCCESS", "PAID"]);
  const apiAccepted = data?.status === true || data?.success === true || statuses.some(value => paidStatuses.has(value));
  const paid = apiAccepted && statuses.some(value => paidStatuses.has(value));
  const gatewayAmount = Number(result.amount ?? result.txnAmount ?? result.transaction_amount ?? data.amount);
  if (!paid) return { paid: false, data };
  if (!Number.isFinite(gatewayAmount) || Math.round(gatewayAmount * 100) !== Math.round(Number(expectedAmount) * 100)) {
    throw new Error("Payment amount mismatch");
  }
  return { paid: true, data, utr: result.utr || result.txnId || result.paymentId || result.transaction_id || null };
}

async function creditVerifiedNovapayPayment(orderId, amount, utr, payload) {
  const { data, error } = await supabase.rpc("complete_novapay_payment", {
    p_order_id: orderId,
    p_amount: amount,
    p_utr: utr || null,
    p_gateway_payload: payload || {}
  });
  if (error) {
    console.error("Verified payment wallet credit failed:", error.message);
    throw new Error("Payment verify ho gaya, lekin wallet credit finalize nahi hua. Admin se contact karein.");
  }
  return data;
}

app.post("/api/payments/novapay/create-order", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const user = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: "Deposit ke liye pehle login karein." });

  const amount = Number(req.body?.amount);
  const mobile = String(req.body?.customer_mobile || "").replace(/\D/g, "");
  if (!Number.isInteger(amount) || amount < 1 || amount > 50000) {
    return res.status(400).json({ error: "₹1 se ₹50,000 tak valid amount enter karein." });
  }
  if (!/^[6-9]\d{9}$/.test(mobile)) {
    return res.status(400).json({ error: "Valid 10-digit Indian mobile number enter karein." });
  }

  const token = process.env.NOVAPAY_USER_TOKEN;
  if (!token) return res.status(503).json({ error: "Gateway setup pending hai. Admin Render Environment Variables mein NOVAPAY_USER_TOKEN set karein." });

  const orderId = "JK" + Date.now().toString() + crypto.randomBytes(4).toString("hex").toUpperCase();
  const { data: pending, error: insertError } = await supabase.from("payment_requests").insert({
    user_id: user.id,
    amount,
    provider: "novapay",
    provider_order_id: orderId,
    status: "pending"
  }).select("id, provider_order_id, amount, status").single();

  if (insertError || !pending) {
    console.error("Payment request insert failed:", insertError?.message);
    return res.status(500).json({ error: "Payment request create nahi ho saki." });
  }

  try {
    const gateway = await novapayPost("https://novaapay.shop/api/create-order", {
      customer_mobile: mobile,
      user_token: token,
      amount,
      order_id: orderId,
      redirect_url: "https://jkpanel.onrender.com/?payment=success&order_id=" + encodeURIComponent(orderId),
      callback_url: "https://jkpanel-backend.onrender.com/api/payments/novapay/webhook",
      remark1: "JK PANEL SHOP wallet deposit",
      remark2: user.id
    });
    const paymentUrl = gateway?.result?.payment_url;
    if (gateway?.status !== true || typeof paymentUrl !== "string" || !/^https:\/\//i.test(paymentUrl)) {
      await supabase.from("payment_requests").update({ status: "failed", updated_at: new Date().toISOString() }).eq("id", pending.id).eq("status", "pending");
      console.error("NovaPay create order rejected:", JSON.stringify({ status: gateway?.status, message: gateway?.message }));
      return res.status(502).json({ error: gateway?.message || "Gateway payment link create nahi kar saka." });
    }
    res.json({ success: true, order_id: orderId, amount, payment_url: paymentUrl });
  } catch (error) {
    await supabase.from("payment_requests").update({ status: "failed", updated_at: new Date().toISOString() }).eq("id", pending.id).eq("status", "pending");
    console.error("NovaPay create order failed:", error.message);
    res.status(502).json({ error: "Payment gateway se order create nahi hua. Thodi der baad try karein." });
  }
});

app.post("/api/payments/novapay/check-status", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const user = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: "Pehle login karein." });
  const orderId = String(req.body?.order_id || "").trim();
  if (!/^JK\d{13}[A-F0-9]{8}$/.test(orderId)) return res.status(400).json({ error: "Invalid payment order ID." });

  const { data: request, error } = await supabase.from("payment_requests")
    .select("id, user_id, amount, provider, provider_order_id, status")
    .eq("provider", "novapay").eq("provider_order_id", orderId).eq("user_id", user.id).maybeSingle();
  if (error) return res.status(500).json({ error: "Payment request load nahi hui." });
  if (!request) return res.status(404).json({ error: "Payment request nahi mili." });
  if (request.status === "paid") return res.json({ success: true, paid: true, message: "Payment pehle hi verify ho chuka hai." });

  try {
    const verified = await verifyNovapayOrder(orderId, Number(request.amount));
    if (!verified.paid) return res.json({ success: true, paid: false, message: "Payment abhi confirm nahi hui. Payment ke baad dobara check karein." });
    await creditVerifiedNovapayPayment(orderId, Number(request.amount), verified.utr, { source: "status_check", gateway: verified.data });
    return res.json({ success: true, paid: true, message: "Payment verify ho gaya. Wallet balance update ho gaya." });
  } catch (error) {
    console.error("NovaPay status verification failed:", error.message);
    return res.status(502).json({ error: error.message || "Payment status verify nahi ho saka." });
  }
});

app.post("/api/payments/novapay/webhook", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const token = process.env.NOVAPAY_USER_TOKEN;
  if (!token || !safeTokenEqual(req.body?.user_token, token)) {
    return res.status(401).json({ error: "Invalid webhook authentication" });
  }
  const event = String(req.body?.event || "");
  const callbackStatus = String(req.body?.status || "").toUpperCase();
  const orderId = String(req.body?.order_id || "").trim();
  const amount = Number(req.body?.amount);
  if (event !== "payment.success" || callbackStatus !== "SUCCESS" || !orderId || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: "Invalid payment webhook payload" });
  }

  const { data: request, error } = await supabase.from("payment_requests")
    .select("id, user_id, amount, provider, provider_order_id, status")
    .eq("provider", "novapay").eq("provider_order_id", orderId).maybeSingle();
  if (error) return res.status(500).json({ error: "Payment request lookup failed" });
  if (!request) return res.status(404).json({ error: "Payment order not found" });
  if (Math.round(Number(request.amount) * 100) !== Math.round(amount * 100)) {
    return res.status(400).json({ error: "Payment amount mismatch" });
  }
  if (request.status === "paid") return res.json({ success: true, already_paid: true });

  try {
    const verified = await verifyNovapayOrder(orderId, Number(request.amount));
    if (!verified.paid) return res.status(409).json({ error: "Gateway status is not completed yet" });
    await creditVerifiedNovapayPayment(orderId, Number(request.amount), req.body?.utr || verified.utr, {
      source: "webhook",
      gateway: verified.data,
      callback: { event, status: callbackStatus, order_id: orderId, amount }
    });
    return res.json({ success: true });
  } catch (error) {
    console.error("NovaPay webhook verification failed:", error.message);
    return res.status(502).json({ error: error.message || "Payment verification failed" });
  }
});

app.post("/api/deposit-requests", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Database is not configured" });
  }

  const user = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: "Deposit submit karne ke liye pehle login karein." });

  const amount = Number(req.body?.amount);
  const transactionId = typeof req.body?.transaction_id === "string" ? req.body.transaction_id.trim() : "";

  if (!Number.isInteger(amount) || amount < 1 || amount > 50000) {
    return res.status(400).json({ error: "Invalid deposit amount" });
  }

  if (
    typeof transactionId !== "string" ||
    transactionId.length < 6 ||
    transactionId.length > 100
  ) {
    return res.status(400).json({ error: "Invalid transaction ID" });
  }

  const { data, error } = await supabase
    .from("deposit_requests")
    .insert({
      user_id: user.id,
      customer_email: user.email || null,
      amount,
      transaction_id: transactionId,
      status: "pending"
    })
    .select("id, amount, status, created_at")
    .single();

  if (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "This transaction ID has already been submitted"
      });
    }

    console.error("Deposit submission failed:", error.message);
    return res.status(500).json({
      error: "Could not submit deposit request"
    });
  }

  res.status(201).json({
    success: true,
    message: "Deposit request submitted for verification",
    request: data
  });
});

app.get("/api/admin/deposit-requests", isAdmin, async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Database is not configured" });
  }

  const { data, error } = await supabase
    .from("deposit_requests")
    .select("id, amount, transaction_id, status, created_at")
    .order("created_at", { ascending: false })
    .limit(100);

  if (error) {
    console.error("Deposit list failed:", error.message);
    return res.status(500).json({ error: "Could not load deposits" });
  }

  res.json({ requests: data });
});

app.patch("/api/admin/deposit-requests/:id", isAdmin, async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Database is not configured" });
  }

  const status = req.body?.status;

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  if (status === "rejected") {
    const { data, error } = await supabase
      .from("deposit_requests")
      .update({ status: "rejected" })
      .eq("id", req.params.id)
      .eq("status", "pending")
      .select("id, amount, status")
      .maybeSingle();

    if (error) {
      console.error("Deposit rejection failed:", error.message);
      return res.status(500).json({ error: "Could not update deposit" });
    }
    if (!data) return res.status(404).json({ error: "Pending request not found" });
    return res.json({ success: true, request: data });
  }

  const { data, error } = await supabase.rpc("approve_deposit_with_referral", {
    p_deposit_id: req.params.id
  });
  if (error) {
    console.error("Deposit approval failed:", error.message);
    if (/Pending request not found/i.test(error.message || "")) {
      return res.status(404).json({ error: "Pending request not found" });
    }
    return res.status(500).json({ error: "Could not approve deposit or credit referral commission" });
  }
  res.json({
    success: true,
    request: data.request,
    commission: Number(data.commission || 0),
    commissionCredited: Boolean(data.commissionCredited)
  });
});


app.get("/api/products", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const { data, error } = await supabase.from("products")
    .select("id, name, price, image_url, video_url, description").eq("published", true).order("created_at", { ascending: false });
  if (error) {
    console.error("Public products load failed:", error.message);
    return res.status(500).json({ error: "Products load nahi ho sake." });
  }
  res.json({ products: data || [] });
});

app.post("/api/orders", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const user = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: "Order banane ke liye pehle login karein." });

  const productId = typeof req.body?.product_id === "string" ? req.body.product_id.trim() : "";
  if (!productId || productId.length > 100) {
    return res.status(400).json({ error: "Valid product select karein." });
  }

  const { data: product, error: productError } = await supabase.from("products")
    .select("id, name, price").eq("id", productId).eq("published", true).maybeSingle();
  if (productError) {
    console.error("Order product lookup failed:", productError.message);
    return res.status(500).json({ error: "Product verify nahi ho saka." });
  }
  if (!product) return res.status(404).json({ error: "Product available nahi hai. Page refresh karein." });

  const amount = Number(product.price);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) {
    return res.status(400).json({ error: "Is product ki price admin panel mein sahi set karein." });
  }

  const isDripWire = /^DRIP Wire - /i.test(product.name || "");
  const isAimHack = /^AIM HACK FF(?: - |$)/i.test(product.name || "");
  if (isDripWire || isAimHack) {
    const duration = isDripWire ? dripWireDuration(product.name) : aimHackDuration(product.name);
    const supplierProductId = isAimHack ? "133" : "150";
    if (!duration) return res.status(400).json({ error: "Product duration configured nahi hai." });

    const { data: purchase, error: walletError } = await supabase.rpc("create_wallet_product_order", {
      p_user_id: user.id,
      p_product_id: product.id
    });
    if (walletError) {
      const message = String(walletError.message || "");
      if (message.includes("INSUFFICIENT_WALLET_BALANCE")) {
        return res.status(402).json({ error: "Wallet balance kam hai. Pehle wallet mein deposit karein." });
      }
      if (message.includes("WALLET_NOT_FOUND")) {
        return res.status(402).json({ error: "Wallet nahi mila. Pehle wallet mein deposit add karein." });
      }
      if (message.includes("PRODUCT_UNAVAILABLE")) return res.status(404).json({ error: "Product ab available nahi hai." });
      console.error("Wallet purchase order creation failed:", message);
      return res.status(500).json({ error: "Wallet order create nahi hua. Balance check karke hi dobara try karein." });
    }

    const orderId = purchase?.order_id;
    if (!orderId) {
      console.error("Wallet purchase RPC returned no order id");
      return res.status(500).json({ error: "Order confirm nahi hua. Support se contact karein." });
    }
    try {
      const delivered = await purchaseDripWireKey({
        orderId,
        userId: user.id,
        productName: product.name,
        duration,
        supplierProductId
      });
      const { data: finalOrder } = await supabase.from("orders")
        .select('id, created_at, "Product_name", "Amount", "Payment_status", "Order status", supplier_status')
        .eq("id", orderId).maybeSingle();
      return res.status(201).json({
        success: true,
        order: {
          id: orderId,
          product_name: product.name,
          amount,
          payment_status: "paid",
          order_status: finalOrder?.["Order status"] || "completed",
          supplier_status: "completed",
          key_count: delivered.keyCount,
          wallet_balance: Number(purchase.wallet_balance),
          created_at: finalOrder?.created_at || new Date().toISOString()
        },
        message: "Wallet se payment ho gayi aur key My Account mein deliver kar di gayi."
      });
    } catch (supplierError) {
      const safeMessage = String(supplierError?.message || "Supplier delivery failed").slice(0, 250);
      console.error("DRIP Wire wallet purchase delivery failed:", safeMessage);
      const { data: refunded, error: refundError } = await supabase.rpc("refund_wallet_product_order", {
        p_order_id: orderId,
        p_user_id: user.id,
        p_reason: safeMessage
      });
      if (refundError) console.error("Wallet refund failed; admin must reconcile:", refundError.message);
      return res.status(502).json({
        success: false,
        refunded: refunded === true,
        error: refunded === true
          ? "Supplier key nahi de saka. Paisa wallet mein wapas kar diya gaya."
          : "Supplier delivery fail hui. Wallet/order status admin se verify karwayein; abhi dobara buy na karein."
      });
    }
  }

  const { data: order, error: orderError } = await supabase.from("orders").insert({
    user_id: user.id,
    "Customer_name": user.email || "Customer",
    "Product_name": product.name,
    "Amount": amount,
    "Payment_status": "pending",
    "Order status": "pending"
  }).select('id, created_at, "Product_name", "Amount", "Payment_status", "Order status"').single();

  if (orderError) {
    console.error("Order creation failed:", orderError.message);
    return res.status(500).json({ error: "Order save nahi ho saka. Admin database ke orders table columns check karein." });
  }

  return res.status(201).json({
    success: true,
    order: {
      id: order.id,
      product_name: order.Product_name,
      amount: Number(order.Amount),
      payment_status: order.Payment_status,
      order_status: order["Order status"],
      created_at: order.created_at
    }
  });
});

app.get("/api/admin/products", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const { data, error } = await supabase.from("products")
    .select("id, name, price, image_url, video_url, published, description, created_at, updated_at")
    .order("created_at", { ascending: false });
  if (error) {
    console.error("Admin products load failed:", error.message);
    return res.status(500).json({ error: "Products load nahi ho sake." });
  }
  res.json({ products: data || [] });
});

app.post("/api/admin/product-image", isAdmin, (req, res) => {
  imageUpload.single("image")(req, res, async (uploadError) => {
    if (uploadError) return res.status(400).json({ error: uploadError.message || "Photo upload failed." });
    if (!supabase) return res.status(503).json({ error: "Database is not configured" });
    if (!req.file) return res.status(400).json({ error: "Phone Gallery se photo select karein." });
    try {
      const bucket = "product-images";
      const { data: buckets, error: bucketListError } = await supabase.storage.listBuckets();
      if (bucketListError) throw bucketListError;
      if (!(buckets || []).some(item => item.name === bucket)) {
        const { error: createError } = await supabase.storage.createBucket(bucket, {
          public: true, fileSizeLimit: "8MB",
          allowedMimeTypes: ["image/jpeg", "image/png", "image/webp", "image/gif"]
        });
        if (createError && !/already exists/i.test(createError.message || "")) throw createError;
      } else {
        const { error: updateBucketError } = await supabase.storage.updateBucket(bucket, {
          public: true, fileSizeLimit: "8MB",
          allowedMimeTypes: ["image/jpeg", "image/png", "image/webp", "image/gif"]
        });
        if (updateBucketError) throw updateBucketError;
      }
      const extByType = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" };
      const fileName = crypto.randomUUID() + "." + extByType[req.file.mimetype];
      const { error: uploadError } = await supabase.storage.from(bucket).upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype, upsert: false
      });
      if (uploadError) throw uploadError;
      const { data: publicUrl } = supabase.storage.from(bucket).getPublicUrl(fileName);
      return res.status(201).json({ success: true, image_url: publicUrl.publicUrl });
    } catch (e) {
      console.error("Product image upload failed:", e.message);
      return res.status(500).json({ error: /maximum allowed size|exceeded.*size|file size|too large/i.test(e.message || "") ? "Photo 8 MB se chhoti rakhein; Supabase ki global upload limit bhi check karein." : "Photo upload fail hua: " + (e.message || "Storage error") });
    }
  });
});

app.post("/api/admin/product-video", isAdmin, (req, res) => {
  videoUpload.single("video")(req, res, async (uploadError) => {
    if (uploadError) return res.status(400).json({ error: uploadError.message || "Video upload failed." });
    if (!supabase) return res.status(503).json({ error: "Database is not configured" });
    if (!req.file) return res.status(400).json({ error: "Gallery se video select karein." });
    try {
      const bucket = "product-videos";
      const { data: buckets, error: bucketListError } = await supabase.storage.listBuckets();
      if (bucketListError) throw bucketListError;
      if (!(buckets || []).some(item => item.name === bucket)) {
        const { error: createError } = await supabase.storage.createBucket(bucket, {
          public: true, fileSizeLimit: "50MB",
          allowedMimeTypes: ["video/mp4", "video/webm", "video/quicktime"]
        });
        if (createError && !/already exists/i.test(createError.message || "")) throw createError;
      } else {
        const { error: updateBucketError } = await supabase.storage.updateBucket(bucket, {
          public: true, fileSizeLimit: "50MB",
          allowedMimeTypes: ["video/mp4", "video/webm", "video/quicktime"]
        });
        if (updateBucketError) throw updateBucketError;
      }
      const extByType = { "video/mp4": "mp4", "video/webm": "webm", "video/quicktime": "mov" };
      const fileName = crypto.randomUUID() + "." + extByType[req.file.mimetype];
      const { error: uploadError } = await supabase.storage.from(bucket).upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype, upsert: false
      });
      if (uploadError) throw uploadError;
      const { data: publicUrl } = supabase.storage.from(bucket).getPublicUrl(fileName);
      return res.status(201).json({ success: true, video_url: publicUrl.publicUrl });
    } catch (e) {
      console.error("Product video upload failed:", e.message);
      return res.status(500).json({ error: /maximum allowed size|exceeded.*size|file size|too large/i.test(e.message || "") ? "Supabase Storage limit reject kar raha hai: " + (e.message || "upload limit error") : "Video upload fail hua: " + (e.message || "Storage error") });
    }
  });
});

app.post("/api/admin/products", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const price = Number(req.body?.price);
  const imageUrl = typeof req.body?.image_url === "string" ? req.body.image_url.trim() : "";
  const videoUrl = typeof req.body?.video_url === "string" ? req.body.video_url.trim() : "";
  const published = req.body?.published === true;
  const description = typeof req.body?.description === "string" ? req.body.description.trim() : "";
  if (description.length > 2000) return res.status(400).json({ error: "Description 2000 characters se kam rakhein." });
  if (!name || name.length > 120 || !Number.isFinite(price) || price < 0 || price > 1000000) {
    return res.status(400).json({ error: "Product name aur valid price enter karein." });
  }
  if (imageUrl && (imageUrl.length > 1000 || !/^https:\/\//i.test(imageUrl))) {
    return res.status(400).json({ error: "Image URL https:// se shuru hona chahiye." });
  }
  if (videoUrl && (videoUrl.length > 2000 || !/^https:\/\//i.test(videoUrl))) return res.status(400).json({ error: "Video URL https:// se shuru hona chahiye." });
  const { data, error } = await supabase.from("products")
    .insert({ name, price, image_url: imageUrl || null, video_url: videoUrl || null, published, description })
    .select("id, name, price, image_url, video_url, published, description").single();
  if (error) {
    console.error("Product create failed:", error.message);
    return res.status(500).json({ error: "Product save nahi ho saka." });
  }
  res.status(201).json({ success: true, product: data });
});

app.patch("/api/admin/products/:id", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const updates = {};
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "description")) {
    if (typeof req.body.description !== "string" || req.body.description.trim().length > 2000)
      return res.status(400).json({ error: "Description 2000 characters se kam rakhein." });
    updates.description = req.body.description.trim();
  }
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "name")) {
    if (typeof req.body.name !== "string" || !req.body.name.trim() || req.body.name.trim().length > 120)
      return res.status(400).json({ error: "Valid product name enter karein." });
    updates.name = req.body.name.trim();
  }
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "price")) {
    const price = Number(req.body.price);
    if (!Number.isFinite(price) || price < 0 || price > 1000000)
      return res.status(400).json({ error: "Valid product price enter karein." });
    updates.price = price;
  }
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "image_url")) {
    const imageUrl = typeof req.body.image_url === "string" ? req.body.image_url.trim() : "";
    if (imageUrl && (imageUrl.length > 1000 || !/^https:\/\//i.test(imageUrl)))
      return res.status(400).json({ error: "Image URL https:// se shuru hona chahiye." });
    updates.image_url = imageUrl || null;
  }
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "video_url")) {
    const videoUrl = typeof req.body.video_url === "string" ? req.body.video_url.trim() : "";
    if (videoUrl && (videoUrl.length > 2000 || !/^https:\/\//i.test(videoUrl))) return res.status(400).json({ error: "Video URL https:// se shuru hona chahiye." });
    updates.video_url = videoUrl || null;
  }
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "published")) {
    if (typeof req.body.published !== "boolean") return res.status(400).json({ error: "Invalid published value." });
    updates.published = req.body.published;
  }
  if (!Object.keys(updates).length) return res.status(400).json({ error: "Koi product change nahi mila." });
  updates.updated_at = new Date().toISOString();
  const { data, error } = await supabase.from("products").update(updates)
    .eq("id", req.params.id).select("id, name, price, image_url, video_url, published, description").maybeSingle();
  if (error) {
    console.error("Product update failed:", error.message);
    return res.status(500).json({ error: "Product update nahi ho saka." });
  }
  if (!data) return res.status(404).json({ error: "Product nahi mila." });
  res.json({ success: true, product: data });
});

app.listen(PORT, () => {
  console.log("JKPanel server running on port " + PORT);
});
