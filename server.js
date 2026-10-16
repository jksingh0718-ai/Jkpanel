

const express = require("express");
const path = require("path");
const crypto = require("crypto");
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

  const [depositsResult, keysResult, walletResult] = await Promise.all([
    supabase.from("deposit_requests").select("id, amount, transaction_id, status, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("customer_keys").select("id, product_name, key_value, status, created_at")
      .eq("user_id", user.id).order("created_at", { ascending: false }).limit(100),
    supabase.from("wallets").select("balance").eq("user_id", user.id).maybeSingle()
  ]);
  if (depositsResult.error || keysResult.error) {
    console.error("Customer account query failed:", depositsResult.error?.message || keysResult.error?.message);
    return res.status(500).json({ error: "Account data load nahi ho saka." });
  }
  const deposits = depositsResult.data || [];
  res.json({
    user: { id: user.id, email: user.email },
    walletBalance: Number(walletResult.data?.balance || 0),
    totalDeposited: deposits.filter(d => d.status === "approved").reduce((sum, d) => sum + Number(d.amount || 0), 0),
    pendingDeposits: deposits.filter(d => d.status === "pending").reduce((sum, d) => sum + Number(d.amount || 0), 0),
    deposits,
    keys: keysResult.data || []
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
 }catch(err){message.textContent=err.message;}
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

document.getElementById("refreshCustomers").onclick=loadCustomers;
document.getElementById("refresh").onclick=async()=>{await loadOrders();await loadCustomers();};
document.getElementById("logout").onclick=async()=>{
 try{await api("/api/admin/logout",{method:"POST"});}catch(e){}
 document.getElementById("dashboard").hidden=true;
 document.getElementById("login").hidden=false;
 message.textContent="Logged out.";
};
loadOrders();
loadCustomers();
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
    .select('id, created_at, "Customer_name", "Product_name", "Amount", "Payment_status", "Order status"')
    .limit(100);

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

  const { data, error } = await supabase
    .from("deposit_requests")
    .update({ status })
    .eq("id", req.params.id)
    .eq("status", "pending")
    .select("id, amount, status")
    .maybeSingle();

  if (error) {
    console.error("Deposit update failed:", error.message);
    return res.status(500).json({ error: "Could not update deposit" });
  }

  if (!data) {
    return res.status(404).json({
      error: "Pending request not found"
    });
  }

  res.json({ success: true, request: data });
});

app.listen(PORT, () => {
  console.log("JKPanel server running on port " + PORT);
});
