
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "20kb" }));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const adminPassword = process.env.ADMIN_PASSWORD;

const supabase =
  supabaseUrl && supabaseKey
    ? createClient(supabaseUrl, supabaseKey)
    : null;

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
<button id="logout">Logout</button>
<div id="orders"></div>
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
 }catch(err){message.textContent=err.message;}
};
document.getElementById("refresh").onclick=loadOrders;
document.getElementById("logout").onclick=async()=>{
 try{await api("/api/admin/logout",{method:"POST"});}catch(e){}
 document.getElementById("dashboard").hidden=true;
 document.getElementById("login").hidden=false;
 message.textContent="Logged out.";
};
loadOrders();
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
    .select("id,created_at,customer_name,product_name,amount,payment_status,order_status")
    .order("created_at", { ascending: false })
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
    .update({ order_status })
    .eq("id", req.params.id)
    .select("id,order_status")
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

app.listen(PORT, () => {
  console.log("JKPanel server running on port " + PORT);
});
