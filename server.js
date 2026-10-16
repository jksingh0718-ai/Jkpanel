

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
const videoUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024, files: 1 }, fileFilter: (req, file, cb) => {
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

  const [depositsResult, keysResult, walletResult, referralsResult, commissionsResult] = await Promise.all([
    supabase.from("deposit_requests").select("id, amount, transaction_id, status, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("customer_keys").select("id, product_name, key_value, status, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("wallets").select("balance").eq("user_id", user.id).maybeSingle(),
    supabase.from("referral_profiles").select("user_id", { count: "exact", head: true }).eq("referred_by", user.id),
    supabase.from("referral_commissions")
      .select("id, referred_user_id, deposit_request_id, deposit_amount, commission_amount, status, created_at")
      .eq("referrer_user_id", user.id).order("created_at", { ascending: false }).limit(100)
  ]);
  if (depositsResult.error || keysResult.error || referralsResult.error || commissionsResult.error) {
    console.error("Customer account query failed:", depositsResult.error?.message || keysResult.error?.message || referralsResult.error?.message || commissionsResult.error?.message);
    return res.status(500).json({ error: "Account data load nahi ho saka." });
  }
  const deposits = depositsResult.data || [];
  const commissions = commissionsResult.data || [];
  res.json({
    user: { id: user.id, email: user.email },
    walletBalance: Number(walletResult.data?.balance || 0),
    totalDeposited: deposits.filter(d => d.status === "approved").reduce((sum, d) => sum + Number(d.amount || 0), 0),
    pendingDeposits: deposits.filter(d => d.status === "pending").reduce((sum, d) => sum + Number(d.amount || 0), 0),
    deposits,
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
body{font-family:Arial;background:#080c12;color:white;padding:24px}
main{max-width:850px;margin:auto}
input,button,select{padding:12px;margin:6px 0;border-radius:6px}
input{max-width:100%}
button{cursor:pointer;background:#39f58b;border:0;font-weight:bold}
.card{background:#111923;padding:16px;margin:12px 0;border-radius:10px;overflow-wrap:anywhere}
small{color:#a6b2c0}
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
<button id="refresh">Refresh Orders</button>
<button id="refreshCustomers">Customers / Deposits / Keys</button>
<button id="logout">Logout</button>
<div id="orders"></div>

<h2 style="margin-top:24px">Manage Products</h2>
<div class="card">
 <form id="productForm">
  <input id="productId" type="hidden">
  <label for="productName">Product name</label><br>
  <input id="productName" required maxlength="120" placeholder="Product name" style="width:100%"><br>
  <label for="productPrice">Selling price (₹)</label><br>
  <input id="productPrice" required type="number" min="0" max="1000000" step="0.01" placeholder="30" style="width:100%"><br>
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

<h2 style="margin-top:24px">Customers, Deposits & Keys</h2>
<div id="customerList"></div>
</section>
<p id="message" role="status"></p>
<script>
const message=document.getElementById("message");
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
   card.append(title,details,id,payment,orderStatus,document.createElement("br"),select,save);
   root.appendChild(card);
  });
  message.textContent="";
 }catch(e){
  document.getElementById("dashboard").hidden=true;
  document.getElementById("login").hidden=false;
  message.textContent=e.message;
 }
}
document.getElementById("loginForm").onsubmit=async e=>{
 e.preventDefault();message.textContent="";
 try{
  await api("/api/admin/login",{method:"POST",body:JSON.stringify({password:document.getElementById("password").value})});
  document.getElementById("password").value="";
  await loadOrders();
  await loadCustomers();
  await loadProducts();
 }catch(err){message.textContent=err.message;}
};


async function loadProducts(){
 try{
  const data=await api("/api/admin/products");
  const root=document.getElementById("productList");
  root.replaceChildren();
  if(!data.products.length){root.textContent="No products yet. Add your first product above.";return;}
  data.products.forEach(product=>{
   const card=document.createElement("article");card.className="card";
   const title=document.createElement("h3");title.textContent=product.name;
   const info=document.createElement("p");info.textContent="Price: ₹"+Number(product.price).toFixed(2)+" | "+(product.published?"Published":"Hidden");
   const img=document.createElement("p");img.textContent=product.image_url||"No image URL";\n   const video=document.createElement("p");video.textContent=product.video_url?"Video: "+product.video_url:"No video uploaded";
   const edit=document.createElement("button");edit.textContent="Edit";
   edit.onclick=()=>{
    document.getElementById("productId").value=product.id;
    document.getElementById("productName").value=product.name;
    document.getElementById("productPrice").value=product.price;
    document.getElementById("productImage").value=product.image_url||"";\n    document.getElementById("productVideoUrl").value=product.video_url||"";\n    document.getElementById("productVideoFile").value="";\n    document.getElementById("videoUploadStatus").textContent=product.video_url?"Current video saved. Nayi video select karne par replace hogi.":"";
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
   card.append(title,info,img,video,edit,toggle);root.appendChild(card);
  });
 }catch(e){document.getElementById("productMessage").textContent=e.message;}
}
function clearProductForm(){
 document.getElementById("productForm").reset();
 document.getElementById("productId").value="";
 document.getElementById("productPublished").checked=true;\n document.getElementById("productImage").value="";\n document.getElementById("productImageFile").value="";\n document.getElementById("imageUploadStatus").textContent="";\n document.getElementById("productVideoUrl").value="";\n document.getElementById("productVideoFile").value="";\n document.getElementById("videoUploadStatus").textContent="";
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
   published:document.getElementById("productPublished").checked
  };
  await api(id?"/api/admin/products/"+encodeURIComponent(id):"/api/admin/products",{
   method:id?"PATCH":"POST",body:JSON.stringify(payload)
  });
  clearProductForm();status.textContent="Product saved successfully.";
  await loadProducts();
 }catch(err){status.textContent=err.message;}
};

async function loadCustomers(){
 try{
  const data=await api("/api/admin/customers");
  const root=document.getElementById("customerList");
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

document.getElementById("refreshCustomers").onclick=async()=>{await loadCustomers();await loadProducts();};
document.getElementById("refresh").onclick=async()=>{await loadOrders();await loadCustomers();await loadProducts();};
document.getElementById("logout").onclick=async()=>{
 try{await api("/api/admin/logout",{method:"POST"});}catch(e){}
 document.getElementById("dashboard").hidden=true;
 document.getElementById("login").hidden=false;
 message.textContent="Logged out.";
};
loadOrders();
loadCustomers();
loadProducts();
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
    .select('id, created_at, customer_name:"Customer_name", product_name:"Product_name", amount:"Amount", payment_status:"Payment_status", order_status:"Order status"')
    .order("created_at", { ascending: false }).limit(100);

  if (error) {
    console.error("Admin order query failed:", error.message);
    return res.status(500).json({ error: "Could not load orders" });
  }

  res.json({ orders: data });
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

  const { data, error } = await supabase
    .from("orders")
    .update({ "Order status": order_status })
    .eq("id", req.params.id)
    .select('id, "Order status"')
    .maybeSingle();

  if (error) {
    console.error("Order update failed:", error.message);
    return res.status(500).json({ error: "Could not update order" });
  }

  if (!data) {
    return res.status(404).json({ error: "Order not found" });
  }

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
    .select("id, name, price, image_url, video_url").eq("published", true).order("created_at", { ascending: false });
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
    .select("id, name, price, image_url, video_url, published, created_at, updated_at")
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
          public: true, fileSizeLimit: "100MB",
          allowedMimeTypes: ["video/mp4", "video/webm", "video/quicktime"]
        });
        if (createError && !/already exists/i.test(createError.message || "")) throw createError;
      } else {
        const { error: updateBucketError } = await supabase.storage.updateBucket(bucket, {
          public: true, fileSizeLimit: "100MB",
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
      return res.status(500).json({ error: /maximum allowed size|exceeded.*size|file size|too large/i.test(e.message || "") ? "Video 100 MB limit se bada hai ya Supabase ki global upload limit kam hai. Video 100 MB se chhoti rakhein." : "Video upload fail hua: " + (e.message || "Storage error") });
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
  if (!name || name.length > 120 || !Number.isFinite(price) || price < 0 || price > 1000000) {
    return res.status(400).json({ error: "Product name aur valid price enter karein." });
  }
  if (imageUrl && (imageUrl.length > 1000 || !/^https:\/\//i.test(imageUrl))) {
    return res.status(400).json({ error: "Image URL https:// se shuru hona chahiye." });
  }
  if (videoUrl && (videoUrl.length > 2000 || !/^https:\/\//i.test(videoUrl))) return res.status(400).json({ error: "Video URL https:// se shuru hona chahiye." });
  const { data, error } = await supabase.from("products")
    .insert({ name, price, image_url: imageUrl || null, video_url: videoUrl || null, published })
    .select("id, name, price, image_url, video_url, published").single();
  if (error) {
    console.error("Product create failed:", error.message);
    return res.status(500).json({ error: "Product save nahi ho saka." });
  }
  res.status(201).json({ success: true, product: data });
});

app.patch("/api/admin/products/:id", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const updates = {};
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
    .eq("id", req.params.id).select("id, name, price, image_url, video_url, published").maybeSingle();
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
