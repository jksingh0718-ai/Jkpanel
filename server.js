

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
  if (!/^\d{6,18}$/.test(password)) {
    return res.status(400).json({ error: "Password 6 se 18 digits ka hona chahiye." });
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
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6,18}$/.test(password)) {
    return res.status(400).json({ error: "Email aur 6–18 digit password sahi enter karein." });
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

app.post("/api/auth/change-password", async (req, res) => {
  if (!authClient || !supabaseUrl) return res.status(503).json({ error: "Authentication is not configured" });
  const accessToken = typeof req.body?.accessToken === "string" ? req.body.accessToken : "";
  const currentPassword = typeof req.body?.currentPassword === "string" ? req.body.currentPassword : "";
  const newPassword = typeof req.body?.newPassword === "string" ? req.body.newPassword : "";
  if (!accessToken || !/^\d{6,18}$/.test(currentPassword) || !/^\d{6,18}$/.test(newPassword)) {
    return res.status(400).json({ error: "Current aur new password 6 se 18 digits ke hone chahiye." });
  }
  if (currentPassword === newPassword) return res.status(400).json({ error: "Naya password current password se alag hona chahiye." });
  const { data: userData, error: userError } = await authClient.auth.getUser(accessToken);
  const email = userData?.user?.email;
  if (userError || !email) return res.status(401).json({ error: "Session expire ho gaya. Dobara login karein." });
  const { error: verifyError } = await authClient.auth.signInWithPassword({ email, password: currentPassword });
  if (verifyError) return res.status(401).json({ error: "Current password sahi nahi hai." });
  try {
    const response = await fetch(supabaseUrl.replace(/\/+$/, "") + "/auth/v1/user", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "apikey": supabasePublishableKey, "Authorization": "Bearer " + accessToken },
      body: JSON.stringify({ password: newPassword })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      const msg = typeof result.msg === "string" ? result.msg : typeof result.message === "string" ? result.message : "";
      return res.status(response.status >= 500 ? 502 : 400).json({ error: msg || "Password change nahi hua. Dobara try karein." });
    }
    return res.json({ success: true, message: "Password successfully change ho gaya." });
  } catch (error) {
    console.error("Customer password change failed:", error.message);
    return res.status(502).json({ error: "Password service abhi available nahi hai." });
  }
});


// Password reset uses Brevo transactional email and short-lived one-time codes.
const brevoApiKey = process.env.BREVO_API_KEY || "";
const resetPepper = process.env.PASSWORD_RESET_PEPPER || process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const hashResetValue = (value) => crypto.createHmac("sha256", resetPepper).update(String(value)).digest("hex");
async function findAuthUserByEmail(email) {
  if (!supabase) return null;
  for (let page = 1; page <= 10; page++) {
    const { data, error } = await supabase.auth.admin.listUsers({ page, perPage: 1000 });
    if (error) throw error;
    const users = data?.users || [];
    const found = users.find((u) => (u.email || "").toLowerCase() === email);
    if (found) return found;
    if (users.length < 1000) return null;
  }
  return null;
}
app.post("/api/auth/forgot-password", async (req, res) => {
  if (!supabase || !brevoApiKey || !resetPepper) return res.status(503).json({ error: "Password reset email service abhi configure nahi hai." });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) return res.status(400).json({ error: "Valid email address enter karein." });
  try {
    const user = await findAuthUserByEmail(email);
    // Same response for unknown emails to avoid exposing which accounts exist.
    if (!user) return res.json({ success: true, message: "Agar is email par account hai, OTP bhej diya jayega. Inbox aur spam folder check karein." });
    const { data: previous, error: previousError } = await supabase.from("password_reset_otps").select("last_sent_at").eq("email", email).maybeSingle();
    if (previousError) throw previousError;
    if (previous?.last_sent_at && Date.now() - new Date(previous.last_sent_at).getTime() < 60_000) {
      return res.status(429).json({ error: "Naya OTP mangwane se pehle 60 second wait karein." });
    }
    const otp = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
    const { error: saveError } = await supabase.from("password_reset_otps").upsert({
      email, otp_hash: hashResetValue("otp:" + email + ":" + otp),
      expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      attempts: 0, verified_token_hash: null, verified_until: null,
      last_sent_at: new Date().toISOString(), created_at: new Date().toISOString()
    }, { onConflict: "email" });
    if (saveError) throw saveError;
    const mailResponse = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "accept": "application/json", "api-key": brevoApiKey, "content-type": "application/json" },
      body: JSON.stringify({
        sender: { name: "JK PANEL SHOP", email: "jksingh0718@gmail.com" },
        to: [{ email }],
        subject: "JK PANEL SHOP - Password Reset OTP",
        textContent: "Aapka JK PANEL SHOP password reset OTP hai: " + otp + "\\n\\nYeh code 10 minute mein expire ho jayega. Agar aapne request nahi ki, is email ko ignore karein.",
        htmlContent: "<div style=\"font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0b0f19;color:#fff;border-radius:14px\"><h2 style=\"color:#38bdf8\">JK PANEL SHOP</h2><p>Password reset karne ke liye ye OTP enter karein:</p><div style=\"font-size:32px;font-weight:bold;letter-spacing:8px;padding:16px;background:#111827;border-radius:10px;text-align:center\">" + otp + "</div><p>Ye code <b>10 minute</b> mein expire ho jayega. Agar aapne request nahi ki, is email ko ignore karein.</p></div>"
      })
    });
    if (!mailResponse.ok) {
      await supabase.from("password_reset_otps").delete().eq("email", email);
      const details = await mailResponse.text().catch(() => "");
      console.error("Brevo password reset email failed:", mailResponse.status, details.slice(0, 300));
      return res.status(502).json({ error: "OTP email nahi bhej paaye. Brevo sender verification aur API key check karein." });
    }
    return res.json({ success: true, message: "Agar is email par account hai, OTP bhej diya jayega. Inbox aur spam folder check karein." });
  } catch (error) {
    console.error("Password reset request failed:", error.message);
    return res.status(500).json({ error: "Password reset request abhi complete nahi ho saki. Thodi der baad try karein." });
  }
});
app.post("/api/auth/verify-reset-otp", async (req, res) => {
  if (!supabase || !resetPepper) return res.status(503).json({ error: "Authentication is not configured" });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const token = typeof req.body?.token === "string" ? req.body.token.trim() : "";
  if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email) || !/^\\d{6}$/.test(token)) return res.status(400).json({ error: "Valid email aur 6-digit OTP enter karein." });
  try {
    const { data: row, error } = await supabase.from("password_reset_otps").select("*").eq("email", email).maybeSingle();
    if (error) throw error;
    if (!row || new Date(row.expires_at).getTime() < Date.now() || row.attempts >= 6 || row.verified_token_hash) {
      return res.status(400).json({ error: "OTP galat hai ya expire ho gaya. Naya OTP mangwayein." });
    }
    const supplied = hashResetValue("otp:" + email + ":" + token);
    const correct = supplied.length === row.otp_hash.length && crypto.timingSafeEqual(Buffer.from(supplied, "hex"), Buffer.from(row.otp_hash, "hex"));
    if (!correct) {
      await supabase.from("password_reset_otps").update({ attempts: Math.min(6, row.attempts + 1) }).eq("email", email);
      return res.status(400).json({ error: "OTP galat hai ya expire ho gaya. Dobara check karein." });
    }
    const resetToken = crypto.randomBytes(32).toString("hex");
    const { error: updateError } = await supabase.from("password_reset_otps").update({
      verified_token_hash: hashResetValue("reset:" + resetToken),
      verified_until: new Date(Date.now() + 10 * 60_000).toISOString(),
      otp_hash: "consumed", expires_at: new Date(0).toISOString()
    }).eq("email", email).eq("otp_hash", row.otp_hash);
    if (updateError) throw updateError;
    return res.json({ success: true, access_token: resetToken });
  } catch (error) {
    console.error("Password reset OTP verification failed:", error.message);
    return res.status(500).json({ error: "OTP verify nahi ho saka. Dobara try karein." });
  }
});
app.post("/api/auth/complete-password-reset", async (req, res) => {
  if (!supabase || !resetPepper) return res.status(503).json({ error: "Authentication is not configured" });
  const resetToken = typeof req.body?.accessToken === "string" ? req.body.accessToken : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!resetToken || !/^[a-f0-9]{64}$/.test(resetToken) || !/^\\d{6,18}$/.test(password)) {
    return res.status(400).json({ error: "Verified OTP aur 6–18 digit naya password required hai." });
  }
  try {
    const resetHash = hashResetValue("reset:" + resetToken);
    const { data: rows, error } = await supabase.from("password_reset_otps").select("email,verified_token_hash,verified_until").eq("verified_token_hash", resetHash).limit(1);
    if (error) throw error;
    const row = rows?.[0];
    if (!row || !row.verified_until || new Date(row.verified_until).getTime() < Date.now()) {
      return res.status(401).json({ error: "OTP verification expire ho gaya. Dobara OTP verify karein." });
    }
    const user = await findAuthUserByEmail(row.email);
    if (!user) return res.status(400).json({ error: "Account nahi mila. Support se contact karein." });
    const { error: passwordError } = await supabase.auth.admin.updateUserById(user.id, { password });
    if (passwordError) {
      console.error("Password reset update failed:", passwordError.message);
      return res.status(400).json({ error: "Naya password save nahi hua. Dobara try karein." });
    }
    await supabase.from("password_reset_otps").delete().eq("email", row.email).eq("verified_token_hash", resetHash);
    return res.json({ success: true, message: "Password successfully reset ho gaya." });
  } catch (error) {
    console.error("Password reset completion failed:", error.message);
    return res.status(500).json({ error: "Password reset abhi complete nahi ho saka." });
  }
});
app.post("/api/auth/change-email", async (req, res) => {
  if (!authClient || !supabaseUrl) return res.status(503).json({ error: "Authentication is not configured" });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const newEmail = typeof req.body?.newEmail === "string" ? req.body.newEmail.trim().toLowerCase() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6,18}$/.test(password) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) return res.status(400).json({ error: "Current email, 6–18 digit password aur valid new email enter karein." });
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
    supabase.from("referral_profiles").select("user_id").eq("referred_by", user.id),
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
  const includeReferralDetails = req.query.includeReferral === "true";
  const { data: resellerAccount, error: resellerStatusError } = await supabase.from("reseller_accounts")
    .select("user_id, is_active, activation_price").eq("user_id", user.id).maybeSingle();
  if (resellerStatusError) console.error("Customer reseller status lookup failed:", resellerStatusError.message);
  res.json({
    user: { id: user.id, email: user.email },
    isReseller: Boolean(resellerAccount?.is_active),
    resellerActivationPrice: Number((await supabase.from("reseller_settings").select("activation_price").eq("id",1).maybeSingle()).data?.activation_price ?? 99),
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
      referredUsers: (referralsResult.data || []).length,
      // Fetch each referred user's auth record only on the referral page.
      // Profile, keys and history screens don't need this extra series of network calls.
      referredUsersList: includeReferralDetails ? await Promise.all((referralsResult.data || []).map(async (profile) => {
        const { data: referredAuth, error: referredAuthError } = await supabase.auth.admin.getUserById(profile.user_id);
        if (referredAuthError || !referredAuth?.user) return { name: "User", email: "", created_at: null };
        const email = referredAuth.user.email || "";
        return { name: email ? email.split("@")[0] : "User", email, created_at: referredAuth.user.created_at || null };
      })) : [],
      totalEarned: commissions.reduce((sum, item) => sum + Number(item.commission_amount || 0), 0),
      commissions
    }
  });
});
// =========================================================
// BANTI BHAIYA API INTEGRATION (BUY KEY ROUTE)
// =========================================================
app.post("/api/buy-key", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  
  // 1. User check karo (Login hai ya nahi)
  const user = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: "Login required" });

  const { productId, duration, price, productName } = req.body;
  const buyPrice = Number(price);

  if (!productId || !duration || !buyPrice) {
    return res.status(400).json({ error: "Product, duration aur price required hai." });
  }

  try {
    // 2. Wallet Check
    const { data: wallet, error: walletErr } = await supabase
      .from("wallets")
      .select("balance")
      .eq("user_id", user.id)
      .maybeSingle();

    if (walletErr || !wallet) return res.status(400).json({ error: "Wallet not found." });
    if (Number(wallet.balance) < buyPrice) return res.status(400).json({ error: "Insufficient wallet balance." });

    // 3. Paisa Kato (Temporary Hold)
    const newBalance = Number(wallet.balance) - buyPrice;
    await supabase.from("wallets").update({ balance: newBalance }).eq("user_id", user.id);

    // 4. Banti Bhaiya API Call
    const params = new URLSearchParams();
    params.append('api_key', process.env.RESELLER_ACCESS_TOKEN);
    params.append('action', 'buy');
    params.append('product_id', productId);
    params.append('duration', duration);
    params.append('quantity', 1);
    // Agar device bound product hai to android_id chahiye hoga, filhal normal bhej rahe hain

    const apiResponse = await fetch("https://bantibhaiya.to/api/reseller_v1.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-master-key": process.env.BANTI_MASTER_KEY // Green color wali master key
      },
      body: params.toString()
    });

    const responseData = await apiResponse.json().catch(() => null);

    // 5. Check karo ki key mili ya nahi
    // API doc ke mutabik agar success hoga to "keys" ka array aayega
    if (responseData && responseData.keys && responseData.keys.length > 0) {
      const originalKey = responseData.keys[0];

      // 6. Database mein Key save karo (customer_keys table mein)
      await supabase.from("customer_keys").insert({
        user_id: user.id,
        product_name: productName,
        key_value: originalKey,
        status: "active"
      });

      // Order history mein save karo
      await supabase.from("orders").insert({
        user_id: user.id,
        "Product_name": productName,
        "Amount": buyPrice,
        "Payment_status": "completed",
        "Order status": "completed"
      });

      return res.json({ success: true, key: originalKey, message: "Key delivered successfully!" });

    } else {
      // Agar API ne error diya
      throw new Error(responseData?.message || "No keys received from supplier");
    }

  } catch (error) {
    console.error("Supplier API Error:", error.message);
    
    // 7. REFUND LOGIC (Agar API fail hui to paisa wapas wallet mein daalo)
    // Note: Yahan hum original balance wapas update kar rahe hain
    if (user) {
        await supabase.from("wallets").update({ balance: wallet.balance }).eq("user_id", user.id);
    }
    
    return res.status(500).json({ error: "Supplier API failed or out of stock. Wallet balance refunded." });
  }
});
// =========================================================
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
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JKPanel Admin</title>
<style>
body{font-family:Arial;background:#080c12;color:white;padding:14px;padding-bottom:100px}
main{max-width:850px;margin:auto}
input,button,select,textarea{padding:12px;margin:6px 0;border-radius:6px;max-width:100%;box-sizing:border-box}
input{max-width:100%}
button{cursor:pointer;background:#39f58b;border:0;font-weight:bold}
.card{background:#111923;padding:16px;margin:12px 0;border-radius:10px;overflow-wrap:anywhere}
small{color:#a6b2c0}
.admin-tabs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin:10px 0 18px}.admin-tabs button{padding:12px 6px;background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:7px}.admin-tabs button.active{background:#39f58b;color:#062012}
#adminTitle{display:flex;align-items:center;gap:10px;margin:8px 0 18px}
#adminMenuToggle:not([hidden]){display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;background:#1e293b;color:#e2e8f0;border:1px solid #334155;padding:8px 11px;font-size:20px;line-height:1;border-radius:8px;min-width:42px;min-height:40px}#adminMenuToggle[hidden]{display:none!important}#adminMenuToggle{display:inline-flex!important;align-items:center;justify-content:center;flex:0 0 auto;background:#1e293b;color:#e2e8f0;border:1px solid #334155;padding:8px 11px;font-size:22px;line-height:1;border-radius:8px;min-width:44px;min-height:42px}
#adminMenu{display:none;background:#111923;border:1px solid #334155;border-radius:10px;margin:0 0 10px;padding:5px}
#adminMenu.open{display:block}
#adminMenu button{display:block;width:100%;text-align:left;margin:3px 0;padding:11px;background:transparent;color:#e2e8f0;border-radius:7px}
#adminMenu button.active{background:#10251b;color:#39f58b}
#adminMenu button[data-action="logout"]{color:#fca5a5}
#refreshCustomers{padding:7px 10px;font-size:12px;border-radius:6px}
.admin-bottom-nav{display:none}
@media(max-width:700px){body{padding-bottom:95px}#adminTitle{gap:10px}.admin-bottom-nav{position:fixed;z-index:9999;left:0;right:0;bottom:0;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:0;background:#0d141e;border-top:1px solid #334155;padding:7px 4px calc(7px + env(safe-area-inset-bottom));box-shadow:0 -4px 18px #0008}.admin-bottom-nav button{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;margin:0;padding:5px 2px;background:transparent;color:#a6b2c0;font-size:11px;border-radius:8px}.admin-bottom-nav button .nav-icon{font-size:21px;line-height:1}.admin-bottom-nav button.active{color:#39f58b;background:#10251b}}
@media(min-width:701px){.admin-bottom-nav{display:flex;gap:8px;margin:14px 0}.admin-bottom-nav button{display:flex;align-items:center;gap:7px;padding:10px 14px;background:#1e293b;color:#e2e8f0;border-radius:7px}.admin-bottom-nav button.active{background:#39f58b;color:#062012}.admin-bottom-nav .nav-icon{font-size:18px}}
.admin-tabs button{padding:12px 6px;background:#1e293b;color:#e2e8f0;border:1px solid #334155}
.admin-tabs button.active{background:#39f58b;color:#062012}
/* Colorful but lightweight admin controls; no animations that can stall mobile devices. */
.admin-tabs button:nth-child(2n){border-color:#6366f1}.admin-tabs button:nth-child(2n):not(.active){background:#252044}
.admin-bottom-nav button:nth-child(2){color:#60a5fa}.admin-bottom-nav button:nth-child(3){color:#c084fc}.admin-bottom-nav button:nth-child(4){color:#34d399}.admin-bottom-nav button:nth-child(5){color:#fbbf24}
#tab-products #showProductForm{background:linear-gradient(135deg,#38bdf8,#6366f1);color:#fff}
#tab-keys #showKeyForm{background:linear-gradient(135deg,#c084fc,#7c3aed);color:#fff}
#tab-resellers button{border-radius:9px}#tab-resellers #saveDripResellerPrices{background:linear-gradient(135deg,#fb923c,#f43f5e);color:#fff}
.admin-section{display:none}.admin-section.active{display:block}
/* Compact single-line product controls and varied button colors, without animations. */
#tab-products .search-box{width:100%;box-sizing:border-box}
#tab-products #refreshProducts,#tab-products #showProductForm{display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;width:auto;min-height:40px;margin:6px 6px 10px 0;padding:9px 13px;border:0;border-radius:10px;white-space:nowrap}
#tab-products #refreshProducts{background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff}
#tab-products #showProductForm{background:linear-gradient(135deg,#38bdf8,#6366f1);color:#fff}
#tab-products #productSave{background:linear-gradient(135deg,#22c55e,#0d9488);color:#fff}
#tab-products #productCancel{background:linear-gradient(135deg,#64748b,#475569);color:#fff}
#tab-products #addProductPlan{background:linear-gradient(135deg,#c084fc,#7c3aed)!important;color:#fff!important;border:0;border-radius:9px}
#adminMenu button:nth-child(1){background:linear-gradient(135deg,#0ea5e9,#2563eb);color:#fff}#adminMenu button:nth-child(2){background:linear-gradient(135deg,#8b5cf6,#6d28d9);color:#fff}#adminMenu button:nth-child(3){background:linear-gradient(135deg,#ec4899,#be185d);color:#fff}#adminMenu button:nth-child(4){background:linear-gradient(135deg,#10b981,#047857);color:#fff}#adminMenu button:nth-child(5){background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff}#adminMenu button[data-action="logout"]{background:linear-gradient(135deg,#f87171,#dc2626);color:#fff}
.search-box{width:100%;background:#0b1220;color:white;border:1px solid #334155;padding:13px;margin:8px 0 14px}
@media(max-width:480px){body{padding:10px}.admin-tabs button{font-size:12px}}
</style>
</head>
<body><main>
<h1 id="adminTitle"><button type="button" id="adminMenuToggle" aria-label="Open navigation menu" aria-expanded="false">☰</button> <span>JKPanel <span style="color:#39f58b">Admin</span></span></h1>
<section id="login">
<h2>Admin Login</h2>
<form id="loginForm" autocomplete="off" onsubmit="return window.jkAdminLogin(event)">
<input id="adminLoginPassword" name="jkpanel-secret-entry" type="password" placeholder="Admin password" required autocomplete="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true">
<br><button>Login</button>
</form>
</section>
<section id="dashboard" hidden>
<nav id="adminMenu" aria-label="Admin navigation"><button type="button" class="active" data-tab="users">Home</button><button type="button" data-tab="products">Products</button><button type="button" data-tab="keys">Keys Management</button><button type="button" data-tab="resellers">Resellers</button><button type="button" data-tab="profile">Profile</button><button type="button" data-action="logout">Logout</button></nav>
<button id="logout" hidden>Logout</button>
<section id="tab-users" class="admin-section active">

 <input id="userSearch" class="search-box" type="search" placeholder="Search users by name, email or ID...">
 <button id="refreshCustomers">Refresh Users</button>
 <div id="customerList"></div>
</section>
<section id="tab-products" class="admin-section">
 <h2>Products</h2>
 <input id="productSearch" class="search-box" type="search" placeholder="Search products...">
 <button id="refreshProducts">Refresh Products</button>
 <button type="button" id="testAllProducts" style="margin:8px 0;background:#0f766e;color:white">✓ Test All Products</button>
 <p style="font-size:12px;opacity:.8;margin:0 0 8px">Free setup check · No purchase or wallet deduction</p>
 <div id="productHealthResults" aria-live="polite"></div>
 <style>
 #productHealthResults{margin:8px 0 14px}
 #productHealthResults .health-panel{border:1px solid #263449;border-radius:12px;padding:10px;background:#0d1421}
 #productHealthResults .health-summary{font-size:14px;margin-bottom:8px}
 #productHealthResults .health-stats{display:flex;gap:5px;flex-wrap:wrap}
 #productHealthResults .health-stat{font-size:11px;padding:4px 7px;border-radius:7px;background:#1b2637;color:#dce7f5}
 #productHealthResults .health-note{font-size:11px;line-height:1.4;opacity:.8;margin:8px 0}
 #productHealthResults .health-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:9px}
 #productHealthResults .health-row{padding:11px;border:1px solid #d7e0ea;border-radius:12px;background:#fff;color:#172334;box-shadow:0 2px 7px #1723340a}
 #productHealthResults .health-row-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}
 #productHealthResults .health-name{font-size:13px;line-height:1.35;overflow-wrap:anywhere;flex:1;color:#172334}
 #productHealthResults .health-badge{font-size:9px;font-weight:800;white-space:nowrap;border-radius:6px;padding:5px 7px;letter-spacing:.2px}
 #productHealthResults .health-ok{background:#d9f7e8;color:#17633f}
 #productHealthResults .health-manual{background:#fff0c2;color:#7a5200}
 #productHealthResults .health-warn{background:#ffe0e3;color:#9c2435}
 #productHealthResults .health-durations{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
 #productHealthResults .health-duration{font-size:11px;line-height:1.2;padding:6px 8px;border-radius:7px;border:1px solid #dce4ed}
 #productHealthResults .duration-ok{background:#e6f8ee;border-color:#b7e7cb;color:#17633f}
 #productHealthResults .duration-manual{background:#fff6dc;border-color:#f0d990;color:#795300}
 #productHealthResults .duration-warn{background:#fff0f1;border-color:#f2bec5;color:#9c2435}
 #productHealthResults .health-meta{font-size:10px;color:#627186;margin-top:7px;overflow-wrap:anywhere}
 #productHealthResults .health-detail{font-size:10px;line-height:1.35;margin:7px 0 0;color:#9c2435}
 </style>
 <button type="button" id="showProductForm" style="margin:10px 0">＋ Add Product</button>
<div id="productEditor" hidden><h3 style="margin-top:16px">Add / Edit Product</h3>
<div class="card">
 <form id="productForm">
  <input id="productId" type="hidden">
  <label for="productName">Product name</label><br>
  <input id="productName" required maxlength="120" placeholder="Product name" style="width:100%"><br>
  <h4 style="margin:14px 0 6px">All durations & prices for this product</h4>
  <div style="padding:10px 12px;margin:8px 0 10px;background:#172554;border:1px solid #3b82f6;border-radius:10px;color:#dbeafe;font-size:13px;line-height:1.6">Product ka naam sirf ek baar likhein. Neeche <b>+ Add duration</b> se 6 Hours, 12 Hours, 1 Day, 7 Days jaise sabhi plans aur unki prices add karein. Shop mein ye sab ek hi product card ke andar dikhenge. Alag-alag product banane ki zarurat nahi.</div>
  <div id="productPlanRows"></div>
  <button type="button" id="addProductPlan" style="background:#334155;color:white">+ Add duration</button><br><small>Existing product ko edit karne par uske sabhi durations ek saath load honge. Yahan se plans update kar sakte hain.</small><br>
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
</div></div>
<div id="productList"></div>
</section>
<section id="tab-keys" class="admin-section">
 <h2>Keys Management</h2>
 <p style="color:#a6b2c0">Key records linked to existing orders/users can be searched here.</p>
 <input id="keySearch" class="search-box" type="search" placeholder="Search key/order records...">
 <button id="refreshKeys">Refresh Key Records</button>
 <div id="keyList"></div>
 <button type="button" id="showKeyForm" style="margin:10px 0">＋ Add Keys</button>
 <div id="keyEditor" hidden><h3 style="margin-top:18px">Add / Edit Key Product</h3>
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
 </div></div>
 <h3 style="margin-top:18px">Saved Key Products</h3><div id="keyGroupList"></div>
 <h3 style="margin-top:18px">Orders / Key Requests</h3><div id="orders"></div>
</section>
<section id="tab-resellers" class="admin-section">
 <h2>Reseller Management</h2>
 <div class="card"><h3>Reseller banne ka price</h3><label for="resellerActivationPrice">Activation price (₹)</label><br><input id="resellerActivationPrice" type="number" min="0" max="1000000" step="0.01" value="0" style="width:100%"><label for="setupWhatsappLink">Check Update Profile — Download Link</label><br><input id="setupWhatsappLink" type="url" placeholder="https://... download/profile link" style="width:100%"><button type="button" id="saveResellerSettings">Save settings</button><p id="resellerSettingsMessage" role="status"></p><small>Shop ke Check Update Profile button par yahi HTTPS link khulega. Trusted direct download/profile link hi daalein.</small></div>
 <div class="card"><h3>Customer ko reseller banayein</h3><label for="resellerCustomer">Customer</label><br><select id="resellerCustomer" style="width:100%"><option value="">Loading customers...</option></select><br><button type="button" id="assignReseller">Make Reseller</button><p id="assignResellerMessage" role="status"></p></div>
 <div class="card"><h3>Product reseller prices</h3><p style="margin:6px 0 10px">Sabhi products yahan chhote list mein hain. Duration aur reseller price badalne ke liye us product ke <b>Edit price details</b> par click karein.</p><input id="resellerProductsSearch" class="search-box" type="search" placeholder="Search product or duration..."><div id="dripResellerPriceRows"><p>Product prices loading...</p></div><button type="button" id="saveDripResellerPrices">Save all reseller prices</button><p id="dripResellerPriceMessage" role="status"></p></div>
 <h3>Current resellers</h3><div id="resellerList"></div>
</section>
<section id="tab-profile" class="admin-section"><h2>Admin Profile</h2><div class="card"><p>JK PANEL SHOP Admin</p><small>Admin dashboard account</small><p>Account security ke liye kaam khatam hone par Logout karein.</p><button type="button" onclick="document.getElementById('logout').click()">Logout</button></div></section>
<nav class="admin-bottom-nav" aria-label="Bottom navigation"><button type="button" class="active" data-tab="users"><span class="nav-icon">⌂</span><span>Home</span></button><button type="button" data-tab="products"><span class="nav-icon">▣</span><span>Products</span></button><button type="button" data-tab="keys"><span class="nav-icon">⚿</span><span>Keys</span></button><button type="button" data-tab="resellers"><span class="nav-icon">♧</span><span>Resellers</span></button><button type="button" data-tab="profile"><span class="nav-icon">♙</span><span>Profile</span></button></nav>
</section>
<p id="message" role="status"></p>

<script>
window.jkAdminLogin=async function(event){
 event.preventDefault();
 event.stopImmediatePropagation();
 const form=document.getElementById("loginForm");
 const input=document.getElementById("adminLoginPassword");
 const button=form.querySelector("button");
 const message=document.getElementById("message");
 const attempted=String(input.value||"");
 if(!attempted){message.textContent="Admin password enter karein.";input.focus();return false;}
 button.disabled=true;button.textContent="Logging in...";message.textContent="";
 try{
  const response=await fetch("/api/admin/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:attempted})});
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(data.error||"Login failed.");
  document.getElementById("login").hidden=true;
  document.getElementById("dashboard").hidden=false;
  message.textContent="Login successful. Admin panel loading...";
  for(const name of ["loadOrders","loadCustomers","loadProducts","loadKeyGroups","loadResellers"]){
   if(typeof window[name]==="function"){try{await window[name]();}catch(e){}}
  }
  if(message.textContent==="Login successful. Admin panel loading...")message.textContent="Admin panel ready.";
 }catch(error){
  document.getElementById("dashboard").hidden=true;
  document.getElementById("login").hidden=false;
  message.textContent=error.message||"Login failed. Check password and try again.";
  input.value=attempted;
  input.focus();
 }finally{
  button.disabled=false;button.textContent="Login";
 }
 return false;
};
</script>
<script>
/* Fallback handlers: keep navigation and refresh controls responsive even if an earlier inline handler failed. */
window.addEventListener("error",function(event){
 const m=document.getElementById("message");
 if(m && !m.textContent) m.textContent="Admin script error: "+String(event.message||"unknown error").slice(0,180);
});
document.addEventListener("click",function(event){
 const button=event.target.closest("button");
 if(!button)return;
 if(button.matches("[data-tab]"))return;
 if(button.id==="refreshProducts"){event.preventDefault();loadProducts().catch(e=>{document.getElementById("message").textContent=e.message;});}
 if(button.id==="refreshCustomers"){event.preventDefault();Promise.allSettled([loadCustomers(),loadResellers()]);}
 if(button.id==="refreshKeys"){event.preventDefault();Promise.allSettled([loadCustomers(),loadKeyGroups()]);}
 if(button.id==="showProductForm"){event.preventDefault();const editor=document.getElementById("productEditor");if(editor)editor.hidden=!editor.hidden;}
},true);
/* Reliable admin tab navigation, independent of the rest of the dashboard script. */
document.addEventListener("click",function(event){
 const button=event.target.closest("button[data-tab]");
 if(!button)return;
 event.preventDefault();
 event.stopImmediatePropagation();
 const tab=button.getAttribute("data-tab");
 document.querySelectorAll("button[data-tab]").forEach(function(item){
  item.classList.toggle("active",item.getAttribute("data-tab")===tab);
 });
 document.querySelectorAll(".admin-section").forEach(function(section){
  section.classList.toggle("active",section.id==="tab-"+tab);
 });
 const jobs={
  users:["loadCustomers"],
  products:["loadProducts"],
  keys:["loadKeyGroups","loadOrders"],
  resellers:["loadResellers"],
  profile:[]
 };
 (jobs[tab]||[]).forEach(function(name){
  if(typeof window[name]==="function")window[name]().catch(function(error){
   const message=document.getElementById("message");
   if(message)message.textContent=error.message||"Section load nahi hua. Refresh karein.";
  });
 });
 const menu=document.getElementById("adminMenu");
 const toggle=document.getElementById("adminMenuToggle");
 if(menu)menu.classList.remove("open");
 if(toggle)toggle.setAttribute("aria-expanded","false");
},true);
</script>
<script>
const loginForm=document.getElementById("loginForm");
const message=document.getElementById("message");
loginForm.addEventListener("submit",async e=>{
 e.preventDefault();
 e.stopPropagation();
 const passwordInput=document.getElementById("adminLoginPassword");
 const attemptedPassword=String(passwordInput.value||"");
 if(!attemptedPassword){message.textContent="Admin password enter karein.";passwordInput.focus();return;}
 const loginButton=loginForm.querySelector("button");
 loginButton.disabled=true;
 loginButton.textContent="Logging in...";
 message.textContent="";
 let authenticated=false;
 try{
  await api("/api/admin/login",{method:"POST",body:JSON.stringify({password:attemptedPassword})});
  authenticated=true;
  document.getElementById("login").hidden=true;
  document.getElementById("dashboard").hidden=false;
  message.textContent="Login successful. Admin panel loading...";
  await Promise.allSettled([loadOrders(),loadCustomers(),loadProducts(),loadKeyGroups(),loadResellers()]);
  if(message.textContent==="Login successful. Admin panel loading...") message.textContent="Admin panel ready.";
 }catch(err){
  document.getElementById("dashboard").hidden=true;
  document.getElementById("login").hidden=false;
  message.textContent=err.message||"Login failed. Password aur Render environment setting check karein.";
  passwordInput.value=attemptedPassword;
  requestAnimationFrame(()=>{passwordInput.focus();passwordInput.setSelectionRange(passwordInput.value.length,passwordInput.value.length);});
 }finally{
  loginButton.disabled=false;
  loginButton.textContent="Login";
  if(!authenticated && passwordInput.value!==attemptedPassword) passwordInput.value=attemptedPassword;
 }
});

document.querySelectorAll("[data-tab]").forEach(button=>button.addEventListener("click",()=>{
 document.querySelectorAll("[data-tab]").forEach(b=>b.classList.toggle("active",b.dataset.tab===button.dataset.tab));
 document.querySelectorAll(".admin-section").forEach(section=>section.classList.toggle("active",section.id==="tab-"+button.dataset.tab));
 if(button.dataset.tab==="resellers"){loadResellers();}
 const menu=document.getElementById("adminMenu");if(menu){menu.classList.remove("open");document.getElementById("adminMenuToggle").setAttribute("aria-expanded","false");}
}));
document.getElementById("adminMenuToggle").addEventListener("click",()=>{const menu=document.getElementById("adminMenu");const open=menu.classList.toggle("open");document.getElementById("adminMenuToggle").setAttribute("aria-expanded",String(open));});
document.querySelector('[data-action="logout"]').addEventListener("click",()=>document.getElementById("logout").click());
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
 const controller=new AbortController();
 const timeout=setTimeout(()=>controller.abort(),15000);
 let response,data;
 try{
  response=await fetch(url,{...options,signal:controller.signal,credentials:"same-origin",headers:{"Content-Type":"application/json",...(options.headers||{})}});
  const raw=await response.text();
  try{data=raw?JSON.parse(raw):{};}catch{throw new Error("Server se valid response nahi mila ("+response.status+"). Page refresh karke dobara try karein.");}
  if(!response.ok)throw new Error(data.error||("Request failed ("+response.status+")"));
  return data;
 }catch(error){
  if(error.name==="AbortError")throw new Error("Server response mein 15 second se zyada lag rahe hain. Dobara try karein.");
  throw error;
 }finally{clearTimeout(timeout);}
}
async function loadOrders(){
 try{
  const data=await api("/api/admin/orders");
  document.getElementById("login").hidden=true;
  document.getElementById("dashboard").hidden=false;
  const root=document.getElementById("orders");
  if(!root){throw new Error("Orders section missing. Page refresh karein.");}
  root.replaceChildren();
  if(!Array.isArray(data.orders)||!data.orders.length){root.textContent="No orders found.";return;}
  data.orders.forEach(order=>{
   const card=document.createElement("article");
   card.className="card";
   const orderState=String(order.order_status||"pending").toLowerCase();
   const paymentState=String(order.payment_status||"pending").toLowerCase();
   const isComplete=orderState==="completed"||orderState==="complete";
   const isCancelled=orderState==="cancelled"||orderState==="canceled"||paymentState==="refunded";
   const accent=isComplete?"#34d399":isCancelled?"#fb7185":"#60a5fa";
   card.style.cssText="padding:9px 10px;margin:7px 0;border-radius:10px;border:1px solid #26364b;border-left:3px solid "+accent+";background:linear-gradient(110deg,#111c2d,#101827);box-shadow:0 3px 10px #02061722";
   const heading=document.createElement("div");
   heading.style.cssText="display:flex;align-items:center;justify-content:space-between;gap:7px";
   const summary=document.createElement("div");
   summary.style.cssText="min-width:0;flex:1";
   const title=document.createElement("h3");
   title.textContent=order.product_name||"Order";
   title.style.cssText="font-size:13px;line-height:1.3;margin:0 0 3px;overflow-wrap:anywhere;color:#f1f5f9";
   const details=document.createElement("p");
   details.textContent=(order.customer_name||"Unknown")+" · ₹"+Number(order.amount||0).toLocaleString("en-IN");
   details.style.cssText="font-size:11px;line-height:1.35;color:#cbd5e1;margin:0;overflow-wrap:anywhere";
   const statusLine=document.createElement("p");
   statusLine.textContent="Order: "+(order.order_status||"pending")+" · Payment: "+(order.payment_status||"pending");
   statusLine.style.cssText="font-size:10px;line-height:1.35;color:"+accent+";margin:4px 0 0;overflow-wrap:anywhere";
   summary.append(title,details,statusLine);
   const toggle=document.createElement("button");
   toggle.type="button";toggle.textContent="View details";toggle.setAttribute("aria-expanded","false");
   toggle.style.cssText="padding:7px 9px;font-size:10px;flex-shrink:0;background:#243449;color:#e2e8f0;border:1px solid #34465e;border-radius:8px";
   heading.append(summary,toggle);
   const panel=document.createElement("div");
   panel.hidden=true;
   panel.style.cssText="display:none;margin-top:12px;padding-top:10px;border-top:1px solid #263247";
   toggle.onclick=()=>{
    const open=panel.style.display==="none";
    panel.style.display=open?"block":"none";panel.hidden=!open;
    toggle.textContent=open?"Hide details":"View details";
    toggle.setAttribute("aria-expanded",String(open));
   };
   const id=document.createElement("small");
   id.textContent="Order ID: "+order.id+" · Created: "+(order.created_at||"");
   id.style.cssText="display:block;overflow-wrap:anywhere;color:#94a3b8;font-size:10px;margin-bottom:8px";
   const payment=document.createElement("p");
   payment.textContent="Payment: "+(order.payment_status||"pending");
   const supplier=document.createElement("p");
   supplier.textContent="Supplier delivery: "+(order.supplier_status||"not_started")+(order.supplier_duration?" ("+order.supplier_duration+")":"")+(order.supplier_error?" — "+order.supplier_error:"");
   supplier.style.cssText="font-size:12px;overflow-wrap:anywhere";
   const verifyPayment=document.createElement("button");
   verifyPayment.textContent="Mark payment verified";
   verifyPayment.disabled=order.payment_status==="paid";
   verifyPayment.style.cssText="margin:0 8px 8px 0;padding:9px;font-size:11px";
   verifyPayment.onclick=async()=>{
    if(!confirm("Payment ko bank/UPI statement se verify kiya hai? Sirf confirmed payment par OK karein."))return;
    try{
     await api("/api/admin/orders/"+encodeURIComponent(order.id)+"/payment",{method:"PATCH",body:JSON.stringify({payment_status:"paid"})});
     message.textContent="Payment marked paid after manual verification.";
     await loadOrders();
    }catch(e){message.textContent=e.message;}
   };
   const orderStatus=document.createElement("p");
   orderStatus.textContent="Order status: "+(order.order_status||"pending");
   orderStatus.style.cssText="font-size:12px;margin-bottom:6px";
   const select=document.createElement("select");
   select.style.cssText="max-width:100%;margin:0 8px 8px 0";
   ["pending","processing","completed","cancelled"].forEach(status=>{
    const option=document.createElement("option");
    option.value=status;option.textContent=status;
    option.selected=status===(order.order_status||"pending");select.appendChild(option);
   });
   const save=document.createElement("button");
   save.textContent="Update status";save.style.cssText="padding:9px;font-size:11px";
   save.onclick=async()=>{
    try{
     await api("/api/admin/orders/"+encodeURIComponent(order.id),{method:"PATCH",body:JSON.stringify({order_status:select.value})});
     message.textContent="Order status updated.";
     await loadOrders();
    }catch(e){message.textContent=e.message;}
   };
   panel.append(id,payment,supplier,verifyPayment,orderStatus,select,save);
   card.append(heading,panel);
   root.appendChild(card);
  });
  message.textContent="";
 }catch(e){
  message.textContent=e.message;
 }
}



function adminProductNameInfo(name){
 const raw=String(name||"").trim();
 if(/^prime\s*hook(?:\b|$)/i.test(raw)){
  const prefix=/^prime\s*hook\s+ff\s+nonroot\s+android\b/i.test(raw)?/^prime\s*hook\s+ff\s+nonroot\s+android/i:/^prime\s*hook/i;
  const duration=raw.replace(prefix,"").replace(/^\s*[-–:|]\s*/,"").trim().replace(/^[[(]/,"").replace(/[)\]]+$/,"").trim();
  return {base:"PRIME HOOK FF NONROOT ANDROID",duration:duration||"Standard"};
 }
 const match=raw.match(/^(.*?)\s*-\s*(.+)$/);
 return {base:match?match[1].trim():raw,duration:match?match[2].trim():"Standard"};
}

document.getElementById("testAllProducts")?.addEventListener("click", async () => {
 const button=document.getElementById("testAllProducts"), root=document.getElementById("productHealthResults");
 if(!button||!root)return;
 button.disabled=true;button.textContent="Checking…";root.replaceChildren();
 const loading=document.createElement("p");loading.className="health-note";loading.textContent="Checking setup — no purchase or wallet deduction.";root.appendChild(loading);
 try{
  const report=await api("/api/admin/product-health-check");root.replaceChildren();
  const panel=document.createElement("div");panel.className="health-panel";
  const head=document.createElement("div");head.className="health-summary";
  const total=document.createElement("strong");total.textContent=report.total+" plans checked";head.appendChild(total);
  const stats=document.createElement("div");stats.className="health-stats";
  [["Setup OK",report.summary.mapping_ok],["Fix needed",report.summary.config_error+report.summary.duration_error],["Manual",report.summary.manual]].forEach(([label,n])=>{const s=document.createElement("span");s.className="health-stat";s.textContent=label+" · "+n;stats.appendChild(s)});
  panel.append(head,stats);
  const note=document.createElement("p");note.className="health-note";note.textContent="Grouped by product. Setup check only — key validity is not tested.";panel.appendChild(note);
  const groups=new Map();
  (report.products||[]).forEach(p=>{const info=adminProductNameInfo(p.name);if(!groups.has(info.base))groups.set(info.base,[]);groups.get(info.base).push({...p,duration:info.duration!=="Standard"?info.duration:(p.duration||"Standard")})});
  const list=document.createElement("div");list.className="health-list";
  groups.forEach((plans,name)=>{
   const row=document.createElement("section");row.className="health-row";
   const top=document.createElement("div");top.className="health-row-top";
   const title=document.createElement("strong");title.className="health-name";title.textContent=name;
   const bad=plans.filter(p=>p.status!=="mapping_ok");
   const badge=document.createElement("span");badge.className="health-badge "+(bad.length===0?"health-ok":bad.every(p=>p.status==="manual")?"health-manual":"health-warn");
   badge.textContent=bad.length===0?"SETUP OK":bad.every(p=>p.status==="manual")?"MANUAL":"CHECK";
   top.append(title,badge);row.appendChild(top);
   const chips=document.createElement("div");chips.className="health-durations";
   plans.forEach(p=>{const chip=document.createElement("span");chip.className="health-duration "+(p.status==="mapping_ok"?"duration-ok":p.status==="manual"?"duration-manual":"duration-warn");chip.textContent=p.duration;chip.title=p.detail;chips.appendChild(chip)});
   row.appendChild(chips);
   const issues=plans.filter(p=>p.status!=="mapping_ok");
   if(issues.length){const detail=document.createElement("p");detail.className="health-detail";detail.textContent=[...new Set(issues.map(p=>p.status==="manual"?"Supplier mapping not detected":p.status==="config_error"?"Supplier credentials may be missing":"Duration mapping needs fixing"))].join(" · ");row.appendChild(detail)}
   const ids=[...new Set(plans.map(p=>p.supplier_id).filter(Boolean))];
   if(ids.length){const meta=document.createElement("div");meta.className="health-meta";meta.textContent="Supplier PID "+ids.join(", ");row.appendChild(meta)}
   list.appendChild(row);
  });
  panel.appendChild(list);root.appendChild(panel);
 }catch(e){root.replaceChildren();const err=document.createElement("p");err.className="health-note";err.textContent="Check failed: "+(e.message||"Unknown error");root.appendChild(err)}
 finally{button.disabled=false;button.textContent="✓ Test All Products"}
});

async function loadProducts(){
 try{
  const data=await api("/api/admin/products");
  const root=document.getElementById("productList");
  if(!root){throw new Error("Products section missing. Page refresh karein.");}
  root.replaceChildren();
  const products=Array.isArray(data.products)?data.products:[];
  if(!products.length){root.textContent="Abhi koi product nahi hai. Upar se product add karein.";return;}
  const groups=new Map();
  const productNameInfo=adminProductNameInfo;
  products.forEach(p=>{const info=productNameInfo(p.name);if(!groups.has(info.base))groups.set(info.base,[]);groups.get(info.base).push(p);});
  groups.forEach((items,base)=>{
   const card=document.createElement("article");card.className="card";
   const title=document.createElement("h3");title.textContent=base;
   const titleRow=document.createElement("div");titleRow.style.cssText="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:10px";
   title.style.cssText="margin:0;min-width:0;overflow-wrap:anywhere";
   const options=document.createElement("div");options.hidden=true;options.style.cssText="white-space:pre-line;line-height:1.8;margin:8px 0";
   options.textContent=items.map(p=>productNameInfo(p.name).duration+" — ₹"+Number(p.price).toFixed(2)+(p.published?"":" (hidden)")).join("\\n");
   const description=document.createElement("p");description.hidden=true;description.textContent=items.find(p=>p.description)?.description||"No description";
   const media=document.createElement("p");media.hidden=true;media.textContent=(items.find(p=>p.image_url)?.image_url||"No image")+(items.find(p=>p.video_url)?" · Video uploaded":"");
   const edit=document.createElement("button");edit.textContent="✎ Edit product details";edit.style.cssText="background:linear-gradient(135deg,#38bdf8,#6366f1);color:#fff;border:0;border-radius:9px;margin:4px 6px 0 0";
   edit.onclick=()=>{
    document.getElementById("productId").value=items[0].id;
    document.getElementById("productName").value=base;
    document.getElementById("productDescription").value=items.find(p=>p.description)?.description||"";
    document.getElementById("productImage").value=items.find(p=>p.image_url)?.image_url||"";
    document.getElementById("productVideoUrl").value=items.find(p=>p.video_url)?.video_url||"";
    document.getElementById("productVideoFile").value="";
    document.getElementById("videoUploadStatus").textContent=items.find(p=>p.video_url)?"Current video saved. Nayi video select karne par replace hogi.":"";
    document.getElementById("productImageFile").value="";
    document.getElementById("imageUploadStatus").textContent=items.find(p=>p.image_url)?"Current photo saved. Nayi photo select karne par replace hogi.":"";
    document.getElementById("productPublished").checked=items.some(p=>p.published);
    const rows=document.getElementById("productPlanRows");rows.replaceChildren();
    items.forEach(p=>addProductPlanRow(productNameInfo(p.name).duration,String(p.price)));
    document.getElementById("productEditor").hidden=false;
    document.getElementById("productSave").textContent="Update Product and Durations";
    document.getElementById("productMessage").textContent="Editing: "+base;
    document.getElementById("productForm").scrollIntoView({behavior:"smooth",block:"center"});
   };
   const visibility=document.createElement("button");visibility.style.cssText="background:linear-gradient(135deg,#fb923c,#f43f5e);color:#fff;border:0;border-radius:9px;margin:4px 0 0";visibility.textContent=items.some(p=>p.published)?"Hide from Shop":"Show in Shop";
   const linksBox=document.createElement("div");linksBox.style.cssText="margin-top:12px;padding:10px;border:1px solid #155e75;border-radius:10px;background:#071923";
   const linksTitle=document.createElement("strong");linksTitle.textContent="Per-product Check Update File links";linksTitle.style.cssText="display:block;margin-bottom:8px;color:#67e8f9";linksBox.appendChild(linksTitle);
   const line=document.createElement("div");line.style.cssText="display:grid;grid-template-columns:minmax(0,1fr);gap:6px;padding:8px 0;border-top:1px solid #263247";
   const label=document.createElement("label");label.textContent=base;label.style.cssText="font-size:12px;font-weight:bold;overflow-wrap:anywhere";
   const savedItem=items.find(p=>String(p.download_url||"").trim());const savedLink=savedItem?savedItem.download_url:"";
   const input=document.createElement("input");input.type="url";input.value=savedLink;input.placeholder="https:// download link";input.style.cssText="width:100%;box-sizing:border-box";
   const saveLink=document.createElement("button");saveLink.type="button";saveLink.textContent="Save product link";saveLink.style.cssText="background:#0891b2;color:#fff";
   saveLink.onclick=async()=>{saveLink.disabled=true;try{const value=input.value.trim();if(value&&!value.toLowerCase().startsWith("https://"))throw new Error("Link https:// se shuru hona chahiye.");for(const p of items){await api("/api/admin/products/"+encodeURIComponent(p.id),{method:"PATCH",body:JSON.stringify({download_url:value})});p.download_url=value||null;}saveLink.textContent="Saved ✓";}catch(e){document.getElementById("productMessage").textContent=e.message;saveLink.textContent="Retry save";}finally{saveLink.disabled=false;}};
   line.append(label,input,saveLink);linksBox.appendChild(line);
   const activity=document.createElement("button");activity.type="button";activity.textContent="See Activity";activity.style.cssText="background:linear-gradient(135deg,#c084fc,#7c3aed);color:#fff;border:0;border-radius:9px;margin:4px 0 0";
   activity.onclick=()=>{options.hidden=!options.hidden;description.hidden=options.hidden;media.hidden=options.hidden;activity.textContent=options.hidden?"See Activity":"Hide Activity";};
   visibility.onclick=async()=>{visibility.disabled=true;try{const publish=!items.some(p=>p.published);for(const p of items)await api("/api/admin/products/"+encodeURIComponent(p.id),{method:"PATCH",body:JSON.stringify({published:publish})});await loadProducts();}catch(e){document.getElementById("productMessage").textContent=e.message;}finally{visibility.disabled=false;}};
   titleRow.append(title);card.append(titleRow,edit,visibility,activity,options,description,media,linksBox);root.appendChild(card);
  });
 }catch(e){document.getElementById("productMessage").textContent=e.message;}
}
const productPlanSeed=[{duration:"",price:""}];
function addProductPlanRow(duration="",price=""){
 const root=document.getElementById("productPlanRows"),row=document.createElement("div");row.className="card product-plan-row";row.style.cssText="padding:10px;margin:8px 0;border:1px solid #334155";
 const fields=document.createElement("div");fields.style.cssText="display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:8px";
 const time=document.createElement("input");time.className="product-plan-duration";time.required=true;time.maxLength=80;time.placeholder="Duration, e.g. 6 Hours";time.value=duration;time.style.width="100%";
 const cost=document.createElement("input");cost.className="product-plan-price";cost.required=true;cost.type="number";cost.min="0";cost.max="1000000";cost.step="0.01";cost.placeholder="Price ₹";cost.value=price;cost.style.width="100%";
 const remove=document.createElement("button");remove.type="button";remove.textContent="Remove duration";remove.style.cssText="background:#7f1d1d;color:white";remove.onclick=()=>row.remove();
 fields.append(time,cost);row.append(fields,remove);root.appendChild(row);
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
 document.getElementById("productPlanRows").replaceChildren();productPlanSeed.forEach(p=>addProductPlanRow(p.duration,p.price));
 document.getElementById("productSave").textContent="Add Product";
 document.getElementById("productMessage").textContent="";
 document.getElementById("productEditor").hidden=true;
}
document.getElementById("showProductForm").addEventListener("click",()=>{const editor=document.getElementById("productEditor");if(editor.hidden){clearProductForm();editor.hidden=false;}else{editor.hidden=false;}const rows=document.getElementById("productPlanRows");if(rows&&!rows.querySelector(".product-plan-row"))addProductPlanRow();document.getElementById("productName").focus({preventScroll:true});editor.scrollIntoView({behavior:"smooth",block:"start"});});
document.getElementById("showKeyForm").onclick=()=>{const editor=document.getElementById("keyEditor");if(editor.hidden){clearKeyGroupForm();editor.hidden=false;document.getElementById("keyGroupName").focus();}else{editor.hidden=true;}};
document.getElementById("addProductPlan").onclick=()=>addProductPlanRow();
productPlanSeed.forEach(p=>addProductPlanRow(p.duration,p.price));
document.getElementById("productCancel").onclick=clearProductForm;
document.getElementById("productForm").onsubmit=async e=>{
 e.preventDefault();
 const id=document.getElementById("productId").value;
 const status=document.getElementById("productMessage");
 const videoStatus=document.getElementById("videoUploadStatus");
 try{
  const base=document.getElementById("productName").value.trim();
  const rows=[...document.querySelectorAll("#productPlanRows .product-plan-row")].map(row=>({duration:row.querySelector(".product-plan-duration").value.trim(),price:Number(row.querySelector(".product-plan-price").value)}));
  if(!base||base.length>100)throw new Error("Valid product name enter karein.");
  if(!rows.length)throw new Error("Kam se kam ek duration-price option add karein.");
  const seen=new Set();for(const row of rows){const key=row.duration.toLowerCase();if(!row.duration||row.duration.length>80||seen.has(key))throw new Error("Har duration bharein aur duplicate duration na rakhein.");if(!Number.isFinite(row.price)||row.price<0||row.price>1000000)throw new Error("Har duration ki valid price enter karein.");seen.add(key);}
  status.textContent=id?"Product aur durations update ho rahe hain...":"Product aur durations add ho rahe hain...";
  let imageUrl=document.getElementById("productImage").value.trim();
  const imageStatus=document.getElementById("imageUploadStatus"),imageFile=document.getElementById("productImageFile").files[0];
  if(imageFile){if(imageFile.size>8*1024*1024)throw new Error("Photo 8 MB se chhoti honi chahiye.");imageStatus.textContent="Gallery photo upload ho rahi hai...";const imageForm=new FormData();imageForm.append("image",imageFile);const r=await fetch("/api/admin/product-image",{method:"POST",body:imageForm});const raw=await r.text();let d={};try{d=raw?JSON.parse(raw):{};}catch{}if(!r.ok)throw new Error(d.error||"Photo upload fail hua.");imageUrl=d.image_url;document.getElementById("productImage").value=imageUrl;imageStatus.textContent="Photo upload ho gayi.";}
  let videoUrl=document.getElementById("productVideoUrl").value.trim();const videoFile=document.getElementById("productVideoFile").files[0];
  if(videoFile){if(videoFile.size>100*1024*1024)throw new Error("Video 100 MB se chhoti honi chahiye.");videoStatus.textContent="Gallery video upload ho rahi hai...";const formData=new FormData();formData.append("video",videoFile);const r=await fetch("/api/admin/product-video",{method:"POST",body:formData});const raw=await r.text();let d={};try{d=raw?JSON.parse(raw):{};}catch{}if(!r.ok)throw new Error(d.error||"Video upload fail hua.");videoUrl=d.video_url;document.getElementById("productVideoUrl").value=videoUrl;videoStatus.textContent="Video upload ho gaya.";}
  const current=await api("/api/admin/products"),all=Array.isArray(current.products)?current.products:[];
  const isPrimeHook=/^prime\s*hook(?:\s+ff\s+nonroot\s+android)?$/i.test(base);
  const existing=all.filter(p=>{
   const name=String(p.name||"").trim();
   return isPrimeHook?/^prime\s*hook(?:\b|$)/i.test(name):(name.toLowerCase()===base.toLowerCase()||name.toLowerCase().startsWith((base+" - ").toLowerCase()));
  });
  const durationKey=value=>String(value||"").toLowerCase().replace(/[^a-z0-9]/g,"");
  const wanted=new Set(rows.map(p=>durationKey(p.duration)));
  const matchedIds=new Set();
  for(const plan of rows){
   const name=base+" - "+plan.duration;
   const planKey=durationKey(plan.duration);
   const old=existing.find(p=>!matchedIds.has(p.id)&&durationKey(adminProductNameInfo(p.name).duration)===planKey);
   const payload={name,price:plan.price,image_url:imageUrl||null,video_url:videoUrl||null,published:document.getElementById("productPublished").checked,description:document.getElementById("productDescription").value.trim()};
   if(old){matchedIds.add(old.id);await api("/api/admin/products/"+encodeURIComponent(old.id),{method:"PATCH",body:JSON.stringify(payload)});}else{await api("/api/admin/products",{method:"POST",body:JSON.stringify(payload)});}
  }
  for(const old of existing){if(!matchedIds.has(old.id)&&old.published)await api("/api/admin/products/"+encodeURIComponent(old.id),{method:"PATCH",body:JSON.stringify({published:false})});}
  clearProductForm();status.textContent="Product aur "+rows.length+" duration-price option(s) Supabase mein save ho gaye.";await loadProducts();
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
 document.getElementById("keyEditor").hidden=true;
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
 try{
  const data=await api("/api/admin/products");
  root.replaceChildren();
  const products=Array.isArray(data.products)?data.products:[];
  const groups=new Map();
  products.forEach(p=>{const m=String(p.name||"").match(/^(.*?)\\s*-\\s*(.+)$/);const base=m?m[1].trim():String(p.name||"Unnamed key");if(!groups.has(base))groups.set(base,[]);groups.get(base).push(p);});
  if(!groups.size){root.textContent="Abhi koi key product nahi hai.";return;}
  [...groups.entries()].sort((a,b)=>a[0].localeCompare(b[0],"en",{numeric:true,sensitivity:"base"})).forEach(([base,items])=>{
   const card=document.createElement("article");card.className="card";card.style.cssText="padding:14px;margin:10px 0;border:1px solid #273548;border-radius:12px;background:#101722";
   const header=document.createElement("div");header.style.cssText="display:flex;align-items:flex-start;justify-content:space-between;gap:10px";
   const titleWrap=document.createElement("div");titleWrap.style.cssText="min-width:0;flex:1";
   const title=document.createElement("h3");title.textContent=base;title.style.cssText="font-size:16px;line-height:1.35;margin:0 0 6px;overflow-wrap:anywhere";
   const active=items.filter(p=>p.published);
   const info=document.createElement("p");info.textContent=active.length+" active · "+items.length+" saved";info.style.cssText="font-size:12px;color:#9caec1;margin:0";
   titleWrap.append(title,info);
   const toggle=document.createElement("button");toggle.type="button";toggle.textContent="View durations & prices";toggle.setAttribute("aria-expanded","false");toggle.style.cssText="flex:0 0 auto;max-width:48%;padding:9px 10px;font-size:11px;line-height:1.3;background:#1d3540;color:#a5f3fc;border:1px solid #285563;border-radius:8px";
   header.append(titleWrap,toggle);
   const panel=document.createElement("div");panel.hidden=true;panel.style.cssText="margin-top:12px";
   const planList=document.createElement("div");planList.style.cssText="display:grid;gap:7px";
   const durationRank=label=>{const d=String(label||"").toLowerCase();const h=d.match(/(\d+(?:\\.\d+)?)\\s*(?:h|hr|hrs|hour|hours)\\b/);if(h)return Number(h[1]);const day=d.match(/(\d+(?:\\.\d+)?)\\s*(?:d|day|days)\\b/);if(day)return Number(day[1])*24;const m=d.match(/(\d+(?:\\.\d+)?)\\s*(?:m|min|mins|minute|minutes)\\b/);return m?Number(m[1])/60:999999;};
   [...items].sort((a,b)=>durationRank(String(a.name||"").slice(base.length).replace(/^\\s*-\\s*/,""))-durationRank(String(b.name||"").slice(base.length).replace(/^\\s*-\\s*/,""))).forEach(p=>{
    const row=document.createElement("div");row.style.cssText="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 11px;border:1px solid #263449;border-radius:9px;background:#0b111b";
    const left=document.createElement("div");left.style.cssText="min-width:0;flex:1";
    const duration=document.createElement("p");duration.textContent=String(p.name||"").slice(base.length).replace(/^\\s*-\\s*/,"")||"Standard";duration.style.cssText="font-size:13px;font-weight:700;color:#f1f5f9;overflow-wrap:anywhere";
    const price=document.createElement("p");price.textContent="₹"+Number(p.price||0).toLocaleString("en-IN",{maximumFractionDigits:2});price.style.cssText="font-size:12px;color:#6ee7b7;margin-top:4px";
    left.append(duration,price);
    const status=document.createElement("span");status.textContent=p.published?"ACTIVE":"HIDDEN";status.style.cssText="flex:0 0 auto;font-size:10px;font-weight:700;color:"+(p.published?"#86efac":"#fca5a5")+";background:"+(p.published?"#123323":"#3a2027")+";padding:5px 7px;border-radius:6px";
    row.append(left,status);planList.appendChild(row);
   });
   const edit=document.createElement("button");edit.type="button";edit.textContent="Edit key, durations & prices";edit.style.cssText="width:100%;margin-top:10px;padding:11px;font-size:12px;background:#39f58b;color:#062012;border-radius:8px;font-weight:700";
   edit.onclick=()=>{
    document.getElementById("keyGroupName").value=base;
    document.getElementById("keyGroupImageUrl").value=(items.find(p=>p.image_url)?.image_url)||"";
    document.getElementById("keyGroupVideoUrl").value=(items.find(p=>p.video_url)?.video_url)||"";
    document.getElementById("keyGroupImageFile").value="";document.getElementById("keyGroupVideoFile").value="";
    document.getElementById("keyGroupImageStatus").textContent=document.getElementById("keyGroupImageUrl").value?"Current photo saved. Nayi photo select karne par replace hogi.":"";
    document.getElementById("keyGroupVideoStatus").textContent=document.getElementById("keyGroupVideoUrl").value?"Current video saved. Nayi video select karne par replace hogi.":"";
    document.getElementById("keyGroupPublished").checked=active.length>0;document.getElementById("keyPlanRows").replaceChildren();
    active.forEach(p=>addKeyPlanRow(String(p.name).slice(base.length).replace(/^\\s*-\\s*/,""),String(p.price)));
    document.getElementById("keyEditor").hidden=false;document.getElementById("keyGroupSave").textContent="Update Key and Durations";
    document.getElementById("keyGroupMessage").textContent="Editing: "+base;document.getElementById("keyGroupForm").scrollIntoView({behavior:"smooth",block:"center"});
   };
   panel.append(planList,edit);
   toggle.onclick=()=>{const open=panel.hidden;panel.hidden=!open;toggle.setAttribute("aria-expanded",String(open));toggle.textContent=open?"Hide durations & prices":"View durations & prices";};
   card.append(header,panel);root.appendChild(card);
  });
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

function formatIndiaDate(value){
 try{if(!value)return "—";return new Date(value).toLocaleString("en-IN",{timeZone:"Asia/Kolkata",day:"2-digit",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:true});}
 catch{return value||"—";}
}
async function loadCustomers(){
 try{
  const data=await api("/api/admin/customers");
  const root=document.getElementById("customerList");
  if(!root)throw new Error("Users section missing. Page refresh karein.");
  root.replaceChildren();
  const summary=document.createElement("p");
  summary.textContent="Registered users: "+data.customers.length;
  root.appendChild(summary);
  data.customers.forEach(customer=>{
   const card=document.createElement("article");card.className="card";
   card.style.padding="14px";
   const title=document.createElement("h3");
   title.textContent=customer.name||"Customer";
   title.style.cssText="margin:0;min-width:0;overflow-wrap:anywhere";
   const titleRow=document.createElement("div");titleRow.style.cssText="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap";
   const balance=document.createElement("strong");
   balance.textContent="₹"+Number(customer.walletBalance||0).toLocaleString("en-IN",{minimumFractionDigits:2,maximumFractionDigits:2});
   balance.style.cssText="color:#6ee7b7;white-space:nowrap;font-size:13px";
   const toggle=document.createElement("button");
   toggle.type="button";toggle.textContent="See Details";toggle.style.cssText="width:auto;white-space:nowrap;background:linear-gradient(135deg,#c084fc,#7c3aed);color:#fff;border:0;border-radius:9px";
   const details=document.createElement("div");
   details.hidden=true;details.style.marginTop="14px";details.style.borderTop="1px solid #334155";details.style.paddingTop="10px";
   toggle.onclick=()=>{details.hidden=!details.hidden;toggle.textContent=details.hidden?"See Details":"Hide Details";};
   titleRow.append(title,balance,toggle);card.append(titleRow,details);
   const line=(label,value)=>{
    const row=document.createElement("p");row.style.cssText="font-size:12px;line-height:1.35;margin:4px 0;padding:4px 0 5px;border-bottom:1px solid #263247;overflow-wrap:anywhere";
    const strong=document.createElement("strong");strong.textContent=label+": ";
    const span=document.createElement("span");span.textContent=String(value??"—");
    row.append(strong,span);details.appendChild(row);
   };
   line("Email",customer.email||"No email");
   line("Joined",customer.created_at||"—");
   line("Email verified",customer.confirmed?"Yes":"No");
   line("Approved deposits","₹"+Number(customer.totalDeposited||0).toFixed(2));
   line("Pending deposits","₹"+Number(customer.pendingDeposits||0).toFixed(2));
   const creditTitle=document.createElement("h4");creditTitle.textContent="Manual Wallet Credit";details.appendChild(creditTitle);
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
    if(!confirm((customer.name||customer.email)+" ke wallet mein ₹"+amount.toFixed(2)+" add karna hai?"))return;
    creditButton.disabled=true;creditStatus.textContent="Balance add ho raha hai...";
    try{
     const result=await api("/api/admin/wallet-credit",{method:"POST",body:JSON.stringify({user_id:customer.id,amount,reason})});
     creditStatus.textContent="Added ₹"+Number(result.credited_amount).toFixed(2)+" | New balance: ₹"+Number(result.wallet_balance).toFixed(2);
     creditAmount.value="";creditReason.value="";
    }catch(err){creditStatus.textContent=err.message;}
    finally{creditButton.disabled=false;}
   };
   details.appendChild(creditForm);
   const depositsTitle=document.createElement("h4");depositsTitle.textContent="Deposit history ("+customer.deposits.length+")";details.appendChild(depositsTitle);
   if(!customer.deposits.length)line("Deposit history","No deposits yet");
   customer.deposits.forEach(d=>{
    line("Deposit","₹"+d.amount);
    line("Deposit status",d.status);
    line("Transaction ID",d.transaction_id||"—");
    line("Deposit date",d.created_at||"—");
   });
   line("Current wallet balance","₹"+Number(customer.walletBalance||0).toFixed(2));
   const keysTitle=document.createElement("h4");keysTitle.textContent="🌈 Purchase History ("+customer.keys.length+")";keysTitle.style.cssText="margin:8px 0;color:#c4b5fd;font-size:13px";details.appendChild(keysTitle);
   if(!customer.keys.length)line("Purchases","No keys purchased yet");
   customer.keys.forEach(k=>{
    const item=document.createElement("div");item.style.cssText="display:flex;flex-wrap:wrap;align-items:center;gap:3px 7px;padding:7px 9px;margin:5px 0;border-radius:9px;background:linear-gradient(110deg,rgba(99,102,241,.18),rgba(6,182,212,.10));border-left:3px solid #a78bfa;font-size:11px;line-height:1.35;overflow-wrap:anywhere";
    const key=document.createElement("span");key.textContent="🔑 "+(k.key_value||"Key pending");key.style.cssText="font-family:monospace;font-weight:700;color:#f0abfc;flex:1 1 145px";
    const status=document.createElement("span");status.textContent=String(k.status||"").toLowerCase()==="active"?"Active":(k.status||"Pending");status.style.cssText="color:#34d399;font-size:10px;font-weight:700;background:rgba(16,185,129,.12);padding:2px 6px;border-radius:10px";
    const product=document.createElement("span");product.textContent=k.product_name||"Product";product.style.cssText="color:#bae6fd;flex:1 1 100%";
    const when=document.createElement("span");when.textContent="🇮🇳 "+formatIndiaDate(k.created_at);when.style.cssText="color:#94a3b8;font-size:10px;flex:1 1 100%";
    item.append(key,status,product,when);details.appendChild(item);
   });
   root.appendChild(card);
  });
 }catch(e){message.textContent=e.message;}
}

async function loadResellers(){
 try{
  const data=await api("/api/admin/resellers");
  document.getElementById("resellerActivationPrice").value=Number(data.settings?.activation_price||0);document.getElementById("setupWhatsappLink").value=String(data.settings?.whatsapp_group_url||"");
  const customerSelect=document.getElementById("resellerCustomer");
  if(!customerSelect)throw new Error("Reseller customer selector missing. Admin page refresh karein.");
  const prev=customerSelect.value;customerSelect.replaceChildren();
  (data.customers||[]).forEach(c=>{const o=document.createElement("option");o.value=c.id;o.textContent=(c.name||c.email)+" ("+c.email+")";customerSelect.appendChild(o);});
  if(prev)customerSelect.value=prev;
  const dripRoot=document.getElementById("dripResellerPriceRows");if(!dripRoot)throw new Error("Reseller price section missing. Admin page refresh karein.");dripRoot.replaceChildren();
  const allProducts=[...(data.products||[])].sort((a,b)=>String(a.name||"").localeCompare(String(b.name||""),"en",{numeric:true,sensitivity:"base"}));
  const groups=new Map();
  allProducts.forEach(p=>{const name=String(p.name||"Unnamed product");const match=name.match(/^(.*?)\\s+-\\s+(.+)$/);const base=match?match[1].trim():name;const duration=match?match[2].trim():"Standard";if(!groups.has(base))groups.set(base,[]);groups.get(base).push({...p,_duration:duration});});
  const durationRank=value=>{const v=String(value||"").toLowerCase().replace(/\\s+/g,"");const m=v.match(/(\d+(?:\\.\d+)?)(h|hr|hrs|hour|hours|d|day|days|w|week|weeks|m|month|months)/);if(!m)return 999999;let n=Number(m[1]);const unit=m[2];if(["h","hr","hrs","hour","hours"].includes(unit))return n;if(["d","day","days"].includes(unit))return n*24;if(["w","week","weeks"].includes(unit))return n*168;if(["m","month","months"].includes(unit))return n*720;return 999999;};
  if(!allProducts.length){dripRoot.textContent="Abhi koi product nahi hai. Products ya Keys Management mein product add karein.";}
  [...groups.entries()].sort((a,b)=>a[0].localeCompare(b[0],"en",{numeric:true,sensitivity:"base"})).forEach(([base,plans])=>{
   plans.sort((a,b)=>durationRank(a._duration)-durationRank(b._duration)||a._duration.localeCompare(b._duration,"en",{numeric:true,sensitivity:"base"}));
   const card=document.createElement("article");card.className="card reseller-product-price-row";card.dataset.search=(base+" "+plans.map(p=>p._duration).join(" ")).toLowerCase();card.style.margin="8px 0";card.style.padding="12px";
   const heading=document.createElement("div");heading.style.fontWeight="700";heading.style.marginBottom="4px";heading.textContent=base;
   const toggle=document.createElement("button");toggle.type="button";toggle.textContent="✎ Edit price details";toggle.style.width="auto";toggle.style.marginLeft="12px";toggle.style.padding="8px 12px";toggle.style.background="linear-gradient(135deg,#38bdf8,#6366f1)";toggle.style.color="#fff";toggle.style.borderRadius="9px";toggle.style.whiteSpace="nowrap";toggle.setAttribute("aria-expanded","false");
   const details=document.createElement("div");details.hidden=true;details.style.marginTop="10px";
   plans.forEach(p=>{const line=document.createElement("div");line.style.display="grid";line.style.gridTemplateColumns="minmax(0,1fr) minmax(90px,0.8fr)";line.style.gap="8px";line.style.alignItems="center";line.style.padding="9px 0";line.style.borderTop="1px solid #334155";
    const info=document.createElement("div");const duration=document.createElement("div");duration.style.fontWeight="600";duration.textContent=p._duration;const shop=document.createElement("small");shop.textContent="Shop ₹"+Number(p.price||0).toFixed(2);shop.style.display="block";info.append(duration,shop);
    const input=document.createElement("input");input.type="number";input.min="0";input.max="1000000";input.step="0.01";input.value=String(p.reseller_price===null||p.reseller_price===undefined?p.price:p.reseller_price);input.dataset.productId=p.id;input.style.width="100%";input.setAttribute("aria-label",base+" "+p._duration+" reseller price");input.title="Reseller price in rupees";line.append(info,input);details.appendChild(line);
   });
   toggle.onclick=()=>{details.hidden=!details.hidden;toggle.textContent=details.hidden?"Edit price details":"Hide price details";toggle.setAttribute("aria-expanded",String(!details.hidden));};
   const titleRow=document.createElement("div");titleRow.style.display="flex";titleRow.style.alignItems="center";titleRow.style.justifyContent="space-between";titleRow.style.gap="8px";titleRow.style.flexWrap="wrap";heading.style.marginBottom="0";titleRow.append(heading,toggle);card.append(titleRow,details);dripRoot.appendChild(card);
  });
  const priceSearch=document.getElementById("resellerProductsSearch");if(priceSearch){priceSearch.value="";priceSearch.oninput=()=>{const q=priceSearch.value.trim().toLowerCase();dripRoot.querySelectorAll(".reseller-product-price-row").forEach(row=>row.style.display=row.dataset.search.includes(q)?"":"none");};}const root=document.getElementById("resellerList");if(!root)throw new Error("Reseller list section missing. Admin page refresh karein.");root.replaceChildren();const list=(data.customers||[]).filter(c=>c.is_reseller);
  if(!list.length){root.textContent="Abhi koi reseller nahi hai.";return;}
  list.forEach(c=>{const card=document.createElement("article");card.className="card";const title=document.createElement("h3");title.textContent=c.name||c.email;const email=document.createElement("p");email.textContent=c.email+" · Activation ₹"+Number(c.activation_price||0).toFixed(2);const status=document.createElement("p");status.textContent=c.reseller_active?"Active reseller":"Inactive reseller";const toggle=document.createElement("button");toggle.type="button";toggle.textContent=c.reseller_active?"Remove reseller access":"Activate reseller";toggle.onclick=async()=>{toggle.disabled=true;try{await api("/api/admin/resellers/assign",{method:"POST",body:JSON.stringify({user_id:c.id,active:!c.reseller_active})});await loadResellers();document.getElementById("assignResellerMessage").textContent="Reseller status saved.";}catch(e){document.getElementById("assignResellerMessage").textContent=e.message;}finally{toggle.disabled=false;}};card.append(title,email,status,toggle);root.appendChild(card);});
 }catch(e){
  const msg=e.message||"Reseller data load nahi hua.";
  document.getElementById("resellerSettingsMessage").textContent="Load error: "+msg;
  const c=document.getElementById("resellerCustomer");if(c){c.replaceChildren();const o=document.createElement("option");o.value="";o.textContent="Customer load error — Refresh karein";c.appendChild(o);}
  const d=document.getElementById("dripResellerPriceRows");if(d)d.textContent="Load error: "+msg;
 }
}
document.getElementById("saveResellerSettings").onclick=async()=>{const b=document.getElementById("saveResellerSettings"),m=document.getElementById("resellerSettingsMessage"),price=Number(document.getElementById("resellerActivationPrice").value);if(!Number.isFinite(price)||price<0||price>1000000){m.textContent="Valid activation price enter karein.";return;}b.disabled=true;try{const whatsapp_group_url=document.getElementById("setupWhatsappLink").value.trim();await api("/api/admin/resellers/settings",{method:"POST",body:JSON.stringify({activation_price:price,whatsapp_group_url})});m.textContent="Settings save ho gayi.";}catch(e){m.textContent=e.message;}finally{b.disabled=false;}};
document.getElementById("assignReseller").onclick=async()=>{const userId=document.getElementById("resellerCustomer").value,m=document.getElementById("assignResellerMessage"),b=document.getElementById("assignReseller");if(!userId){m.textContent="Pehle customer select karein.";return;}b.disabled=true;try{await api("/api/admin/resellers/assign",{method:"POST",body:JSON.stringify({user_id:userId,active:true})});m.textContent="Customer reseller ban gaya; status save ho gaya.";await loadResellers();}catch(e){m.textContent=e.message;}finally{b.disabled=false;}};
document.getElementById("saveDripResellerPrices").onclick=async()=>{
 const button=document.getElementById("saveDripResellerPrices"),status=document.getElementById("dripResellerPriceMessage");
 const fields=Array.from(document.querySelectorAll("#dripResellerPriceRows input[data-product-id]"));
 if(!fields.length){status.textContent="Koi product nahi mila. Pehle product add karein.";return;}
 for(const field of fields){const value=Number(field.value);if(!Number.isFinite(value)||value<0||value>1000000){status.textContent="Har duration ka valid price enter karein.";field.focus();return;}}
 button.disabled=true;status.textContent="Saving reseller prices for all products...";
 try{
  for(const field of fields){await api("/api/admin/reseller-prices",{method:"POST",body:JSON.stringify({product_id:field.dataset.productId,reseller_user_id:null,price:Number(field.value)})});}
  status.textContent="Sabhi products ke reseller prices Supabase mein save ho gaye.";
 }catch(e){status.textContent="Save error: "+e.message;}
 finally{button.disabled=false;}
};
const legacyResellerProductSelect=document.getElementById("resellerPriceProduct");if(legacyResellerProductSelect)legacyResellerProductSelect.addEventListener("change",e=>{const o=e.target.selectedOptions[0];if(o){const amount=document.getElementById("resellerPriceAmount");if(amount)amount.value=o.dataset.price||"";}});
document.getElementById("refreshCustomers").onclick=async()=>{await loadCustomers();await loadResellers();};
document.getElementById("refreshProducts").onclick=async()=>{await loadProducts();};
document.getElementById("refreshKeys").onclick=async()=>{await loadCustomers();await loadKeyGroups();};
document.getElementById("logout").onclick=async()=>{
 try{await api("/api/admin/logout",{method:"POST"});}catch(e){}
 document.getElementById("dashboard").hidden=true;
 document.getElementById("login").hidden=false;
 document.getElementById("adminMenuToggle").hidden=true;
 document.getElementById("adminMenu").classList.remove("open");
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
function dripClientApkmodDuration(productName) {
  const name = String(productName || "").trim().replace(/\s+/g, " ");
  if (!/dripclient.*apkmod/i.test(name)) return null;
  const match = name.match(/(?:^|\s-\s)(1|3|7|15|30)\s*days?(?:\s*\([^)]*\))?(?:\s+nonroot)?$/i);
  return match ? match[1] + " DaYS NONROOT" : null;
}
function aimHackDuration(productName) {
  const name = String(productName || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (name === "aim hack ff" || name === "aim hack ff - 1 hour" || name === "aim hack ff - 1 hours") return "1 Hours";
  if (name === "aim hack ff - 3 hours") return "3 Hours";
  if (name === "aim hack ff - 6 hours") return "6 Hours";
  if (name === "aim hack ff - 12 hours") return "12 Hours";
  if (name === "aim hack ff - 1 day") return "1 Day";
  if (name === "aim hack ff - 3 days") return "3 Days";
  if (name === "aim hack ff - 7 days") return "7 Days";
  if (name === "aim hack ff - 30 days") return "30 Days";
  return null;
}

function balaModsDuration(productName) {
  const name = String(productName || "").trim().replace(/\s+/g, " ");
  if (!/bala\s*mods/i.test(name)) return null;
  const hours = name.match(/(?:^|\s-\s)(1|3|6|12)\s*hours?/i);
  if (hours) return hours[1] + " Hours";
  const days = name.match(/(?:^|\s-\s)(1)\s*days?/i);
  if (days) return "1 DaYs";
  return null;
}

function silentCheatNonrootDuration(productName) {
  const name = String(productName || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (!/silent\s+cheat\s+ff\s+nonroot\s+proxy/i.test(name)) return null;
  const hours = name.match(/(1|3|6|12)\s*hours?/i);
  if (hours) return hours[1] + " Hours Apk Silent";
  const days = name.match(/(1|3|7)\s*days?/i);
  if (days) return (days[1] === "1" ? "1Days" : days[1] + " Days") + " Apk Silent";
  return null;
}

function silentXFFDuration(productName) {
  const name = String(productName || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (!/^silent\s*x\s*ff(?:\s+all)?(?:\s*-|$)/i.test(name)) return null;
  const hours = name.match(/(?:^|\s-\s)(1|3|6|12)\s*hours?/i);
  if (hours) return hours[1] + " Hours";
  const days = name.match(/(?:^|\s-\s)(1|3|7|30)\s*days?/i);
  if (days) return days[1] + " Days";
  return null;
}

function primeHookDuration(productName) {
  const name = String(productName || "").trim().replace(/\s+/g, " ");
  if (!/prime\s*hook/i.test(name)) return null;
  const match = name.match(/(1|3|7|10)\s*days?\s*nonroot/i);
  if (!match) return null;
  return ({ "1": "1 Days Nonroot", "3": "3 Days Nonroot", "7": "7 Days Nonroot", "10": "10 Days Nonroot" })[match[1]] || null;
}
function xragDuration(productName) {
  if (!/xrag\s*ff\s*all/i.test(String(productName || ""))) return null;
  const match = String(productName).match(/(1|3|6|12|24)\s*hours?|([37]|30)\s*days?/i);
  if (!match) return null;
  if (match[1]) {
    const n = match[1];
    // Bantibhaiya supplier catalog spells the hour duration as "1 Hours".
    return n + " Hours";
  }
  const n = match[2];
  return n + (n === "1" ? " Day" : " Days");
}
function phantomTrollDuration(productName) {
  const name = String(productName || "");
  if (!/phantom\s*x\s*troll\s*ff\s*all/i.test(name)) return null;
  const hours = name.match(/(1|3|6|12|24)\s*hours?/i);
  if (hours) return hours[1] + " Hours";
  const days = name.match(/(1|3|7|30)\s*days?/i);
  if (days) return days[1] + (days[1] === "1" ? " Day" : " Days");
  return null;
}

async function purchaseDripWireKey({ orderId, userId, productName, duration, supplierProductId = "150" }) {
  // Use the separate master key configured in Render; retain the legacy
  // BANTI_MASTER_KEY name for backwards compatibility.
  const apiKey = String(
    process.env.RESELLER_API_KEY || process.env.RESELLER_ACCESS_TOKEN || ""
  ).trim();
  const masterKey = String(
    process.env.X_MASTER_KEY || process.env.BANTI_MASTER_KEY || ""
  ).trim();
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
      "Accept": "application/json",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    redirect: "follow",
    body,
    signal: AbortSignal.timeout(25000)
  });
  const raw = await response.text();
  let result;
  try {
    result = raw ? JSON.parse(raw) : {};
  } catch {
    // Log safe diagnostics only: never log credentials or any key material.
    const preview = String(raw || "").replace(/(api_key|master[_ -]?key|token|authorization)\s*[:=]\s*[^\s&,<]+/ig, "$1=[redacted]").replace(/\s+/g, " ").slice(0, 180);
    console.error("Supplier invalid-response diagnostic:", JSON.stringify({
      productName: String(productName || "").slice(0, 100),
      supplierProductId: String(supplierProductId),
      duration: String(duration || "").slice(0, 40),
      httpStatus: response.status,
      contentType: String(response.headers.get("content-type") || "").slice(0, 100),
      bodyLength: raw.length,
      bodyPreview: preview
    }));
    throw new Error("Supplier returned an invalid response (HTTP " + response.status + ").");
  }

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
  const isDripClient = /dripclient.*apkmod/i.test(productName);
  const isAimHack = /^AIM HACK FF(?: - |$)/i.test(productName);
  const isBalaMods = /bala\s*mods/i.test(productName);
  const isPrimeHook = /prime\s*hook/i.test(productName);
  const isSilentXFF = /silent\s*x\s*ff/i.test(productName);
  const isSilentCheatNonroot = /silent\s+cheat\s+ff\s+nonroot\s+proxy/i.test(productName);
  const isXrag = /xrag\s*ff\s*all/i.test(productName);
  const isPhantomTroll = /phantom\s*x\s*troll\s*ff\s*all/i.test(productName);
  let duration = null;
  if (isSilentCheatNonroot) duration = silentCheatNonrootDuration(productName);
  else if (isSilentXFF) duration = silentXFFDuration(productName);
  else if (isPrimeHook) duration = primeHookDuration(productName);
  else if (isXrag) duration = xragDuration(productName);
  else if (isPhantomTroll) duration = phantomTrollDuration(productName);
  else if (isDripWire) duration = dripWireDuration(productName);
  else if (isDripClient) duration = dripClientApkmodDuration(productName);
  else if (isAimHack) duration = aimHackDuration(productName);
  else if (isBalaMods) duration = balaModsDuration(productName);
  const usesSupplier = isDripWire || isDripClient || isAimHack || isBalaMods || isPrimeHook || isSilentXFF || isSilentCheatNonroot || isXrag || isPhantomTroll;
  const supplierProductId = isSilentCheatNonroot ? "148" : (isSilentXFF ? "171" : (isPrimeHook ? "48" : (isXrag ? "149" : (isPhantomTroll ? "133" : (isAimHack ? "133" : (isBalaMods ? "136" : (isDripClient ? "62" : "150")))))));
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
    const [usersResult, depositsResult, keysResult, walletsResult, ordersResult] = await Promise.all([
      supabase.auth.admin.listUsers({ page: 1, perPage: 1000 }),
      supabase.from("deposit_requests")
        .select("id, user_id, customer_email, amount, transaction_id, status, created_at")
        .order("created_at", { ascending: false }).limit(1000),
      supabase.from("customer_keys")
        .select("id, user_id, product_name, key_value, status, created_at")
        .order("created_at", { ascending: false }).limit(1000),
      supabase.from("wallets").select("user_id, balance"),
      supabase.from("orders")
        .select('id, user_id, created_at, "Product_name", "Amount", "Payment_status", "Order status", supplier_status, supplier_duration')
        .order("created_at", { ascending: false }).limit(2000)
    ]);
    if (usersResult.error || depositsResult.error || keysResult.error || walletsResult.error || ordersResult.error) {
      console.error("Admin customer data failed:", usersResult.error?.message || depositsResult.error?.message || keysResult.error?.message || walletsResult.error?.message || ordersResult.error?.message);
      return res.status(500).json({ error: "Customer, wallet, order, deposit ya key data load nahi ho saka." });
    }
    const users = usersResult.data?.users || [];
    const deposits = depositsResult.data || [];
    const keys = keysResult.data || [];
    const walletMap = new Map((walletsResult.data || []).map(w => [w.user_id, Number(w.balance || 0)]));
    const ordersByUser = new Map();
    for (const order of (ordersResult.data || [])) {
      if (!order.user_id) continue;
      if (!ordersByUser.has(order.user_id)) ordersByUser.set(order.user_id, []);
      ordersByUser.get(order.user_id).push({
        id: order.id,
        product_name: order["Product_name"] || "Product",
        amount: Number(order["Amount"] || 0),
        payment_status: order["Payment_status"] || "—",
        order_status: order["Order status"] || "—",
        supplier_status: order.supplier_status || "",
        supplier_duration: order.supplier_duration || "",
        created_at: order.created_at
      });
    }
    const customers = users.map(user => {
      const userDeposits = deposits.filter(d => d.user_id === user.id);
      const userKeys = keys.filter(k => k.user_id === user.id);
      return {
        id: user.id,
        email: user.email || "",
        name: String(user.user_metadata?.full_name || user.user_metadata?.name || user.email?.split("@")[0] || "Customer").slice(0,100),
        created_at: user.created_at,
        confirmed: Boolean(user.email_confirmed_at),
        walletBalance: walletMap.get(user.id) || 0,
        totalDeposited: userDeposits.filter(d => d.status === "approved").reduce((sum,d) => sum + Number(d.amount || 0), 0),
        pendingDeposits: userDeposits.filter(d => d.status === "pending").reduce((sum,d) => sum + Number(d.amount || 0), 0),
        deposits: userDeposits,
        keys: userKeys,
        orders: ordersByUser.get(user.id) || []
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
  // Fail closed: a successful API/order response alone is NOT proof of payment.
  // Require an explicit final paid status from the transaction result, matching amount,
  // and a gateway transaction reference before enabling wallet credit/reseller activation.
  const statuses = [
    result?.status,
    result?.payment_status,
    result?.paymentStatus,
    result?.txnStatus,
    result?.transaction_status
  ].map(value => String(value ?? "").trim().toUpperCase());
  const paidStatuses = new Set(["COMPLETE", "COMPLETED", "SUCCESS", "PAID"]);
  const paid = statuses.some(value => paidStatuses.has(value));
  const gatewayAmount = Number(result.amount ?? result.txnAmount ?? result.transaction_amount);
  const utr = result.utr || result.txnId || result.paymentId || result.transaction_id || result.transactionId || null;
  if (!paid || !utr) return { paid: false, data };
  if (!Number.isFinite(gatewayAmount) || Math.round(gatewayAmount * 100) !== Math.round(Number(expectedAmount) * 100)) {
    return { paid: false, data };
  }
  return { paid: true, data, utr };
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

async function activateResellerFromVerifiedPayment(request, utr, payload) {
  const { data: settings, error: settingsError } = await supabase.from("reseller_settings").select("activation_price").eq("id",1).maybeSingle();
  if (settingsError) throw new Error("Reseller activation price load nahi hua.");
  const activationPrice = Number(settings?.activation_price ?? 99);
  if (Math.round(Number(request.amount)*100) !== Math.round(activationPrice*100)) throw new Error("Reseller activation amount mismatch.");
  const { error: paidError } = await supabase.from("payment_requests").update({
    status:"paid", updated_at:new Date().toISOString()
  }).eq("id",request.id).eq("status","pending");
  if (paidError) throw new Error("Verified reseller payment status save nahi hua.");
  const { error: activationError } = await supabase.from("reseller_accounts").upsert({
    user_id:request.user_id,is_active:true,activation_price:activationPrice
  },{onConflict:"user_id"});
  if (activationError) throw new Error("Payment verify ho gaya, lekin reseller activation finalize nahi hui. Admin se contact karein.");
  return {success:true,isReseller:true};
}

app.post("/api/payments/novapay/create-order", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const user = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: "Deposit ke liye pehle login karein." });

  const purpose = req.body?.purpose === "reseller" ? "reseller" : "wallet";
  let amount = Number(req.body?.amount);
  if (purpose === "reseller") {
    const { data: settings, error: settingsError } = await supabase.from("reseller_settings").select("activation_price").eq("id",1).maybeSingle();
    if (settingsError) return res.status(500).json({ error: "Reseller activation price load nahi hua." });
    amount = Number(settings?.activation_price ?? 99);
  }
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
    provider: purpose === "reseller" ? "novapay_reseller" : "novapay",
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
      remark1: purpose === "reseller" ? "JK PANEL SHOP reseller activation" : "JK PANEL SHOP wallet deposit",
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
    .in("provider", ["novapay","novapay_reseller"]).eq("provider_order_id", orderId).eq("user_id", user.id).maybeSingle();
  if (error) return res.status(500).json({ error: "Payment request load nahi hui." });
  if (!request) return res.status(404).json({ error: "Payment request nahi mili." });
  if (request.status === "paid") return res.json({ success: true, paid: true, isReseller: request.provider === "novapay_reseller", message: request.provider === "novapay_reseller" ? "Reseller Partner pehle hi activate ho chuka hai." : "Payment pehle hi verify ho chuka hai." });

  try {
    const verified = await verifyNovapayOrder(orderId, Number(request.amount));
    if (!verified.paid) return res.json({ success: true, paid: false, message: "Payment abhi confirm nahi hui. Payment ke baad dobara check karein." });
    if (request.provider === "novapay_reseller") {
      await activateResellerFromVerifiedPayment(request, verified.utr, {source:"status_check",gateway:verified.data});
      return res.json({success:true,paid:true,isReseller:true,message:"₹99 payment verify ho gaya. Reseller Partner activate ho gaya!"});
    }
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
    .in("provider", ["novapay","novapay_reseller"]).eq("provider_order_id", orderId).maybeSingle();
  if (error) return res.status(500).json({ error: "Payment request lookup failed" });
  if (!request) return res.status(404).json({ error: "Payment order not found" });
  if (Math.round(Number(request.amount) * 100) !== Math.round(amount * 100)) {
    return res.status(400).json({ error: "Payment amount mismatch" });
  }
  if (request.status === "paid") return res.json({ success: true, already_paid: true });

  try {
    const verified = await verifyNovapayOrder(orderId, Number(request.amount));
    if (!verified.paid) return res.status(409).json({ error: "Gateway status is not completed yet" });
    const payload = {
      source: "webhook",
      gateway: verified.data,
      callback: { event, status: callbackStatus, order_id: orderId, amount }
    };
    if (request.provider === "novapay_reseller") {
      await activateResellerFromVerifiedPayment(request, req.body?.utr || verified.utr, payload);
      return res.json({success:true,isReseller:true});
    }
    await creditVerifiedNovapayPayment(orderId, Number(request.amount), req.body?.utr || verified.utr, payload);
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


app.get("/api/check-update-links", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const { data, error } = await supabase.from("products")
    .select("name, download_url")
    .not("download_url", "is", null)
    .order("name", { ascending: true });
  if (error) {
    console.error("Check-update links load failed:", error.message);
    return res.status(500).json({ error: "Check Update File links load nahi ho sake." });
  }
  const links = (data || [])
    .map(p => ({ name: String(p.name || "Product"), download_url: String(p.download_url || "").trim() }))
    .filter(p => /^https:\/\//i.test(p.download_url));
  res.set("Cache-Control", "no-store, max-age=0");
  res.json({ links });
});

app.get("/api/products", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const { data, error } = await supabase.from("products")
    .select("id, name, price, image_url, video_url, download_url, description, created_at").eq("published", true).order("created_at", { ascending: false });
  if (error) { console.error("Public products load failed:", error.message); return res.status(500).json({ error: "Products load nahi ho sake." }); }
  const user = await getAuthenticatedUser(req);
  let products = data || [];
  let isReseller = false;
  if (user) {
    const { data: reseller } = await supabase.from("reseller_accounts").select("user_id").eq("user_id", user.id).eq("is_active", true).maybeSingle();
    isReseller = Boolean(reseller);
    if (reseller) {
      const { data: prices } = await supabase.from("reseller_prices").select("product_id, price, reseller_user_id").or("reseller_user_id.is.null,reseller_user_id.eq."+user.id);
      const defaults = new Map(), personal = new Map();
      (prices || []).forEach(p => { if (p.reseller_user_id === null) defaults.set(p.product_id, Number(p.price)); else if (p.reseller_user_id === user.id) personal.set(p.product_id, Number(p.price)); });
      products = products.map(p => personal.has(p.id) ? { ...p, price: personal.get(p.id) } : defaults.has(p.id) ? { ...p, price: defaults.get(p.id) } : p);
    }
  }
  res.json({ products, isReseller });
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

  let amount = Number(product.price);
  const { data: resellerAccount, error: resellerAccountError } = await supabase.from("reseller_accounts")
    .select("user_id").eq("user_id", user.id).eq("is_active", true).maybeSingle();
  if (resellerAccountError) console.error("Reseller account lookup failed:", resellerAccountError.message);
  if (resellerAccount) {
    const { data: personalPrice, error: personalPriceError } = await supabase.from("reseller_prices")
      .select("price").eq("product_id", product.id).eq("reseller_user_id", user.id).maybeSingle();
    const { data: defaultPrice, error: defaultPriceError } = await supabase.from("reseller_prices")
      .select("price").eq("product_id", product.id).is("reseller_user_id", null).maybeSingle();
    if (personalPriceError || defaultPriceError) console.error("Reseller price lookup failed:", personalPriceError?.message || defaultPriceError?.message);
    if (personalPrice) amount = Number(personalPrice.price);
    else if (defaultPrice) amount = Number(defaultPrice.price);
  }
  if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) {
    return res.status(400).json({ error: "Is product ki price admin panel mein sahi set karein." });
  }

  const isDripWire = /^DRIP Wire - /i.test(product.name || "");
  const isDripClient = /dripclient.*apkmod/i.test(product.name || "");
  const isAimHack = /^AIM HACK FF(?: - |$)/i.test(product.name || "");
   const isBalaMods = /bala\s*mods/i.test(product.name || "");
  const isPrimeHook = /prime\s*hook/i.test(product.name || "");
  const isSilentXFF = /silent\s*x\s*ff/i.test(product.name || "");
  const isSilentCheatNonroot = /silent\s+cheat\s+ff\s+nonroot\s+proxy/i.test(product.name || "");
  const isXrag = /xrag\s*ff\s*all/i.test(product.name || "");
  const isPhantomTroll = /phantom\s*x\s*troll\s*ff\s*all/i.test(product.name || "");
  if (isDripWire || isDripClient || isAimHack || isBalaMods || isPrimeHook || isSilentXFF || isSilentCheatNonroot || isXrag || isPhantomTroll) {
    const duration = isSilentCheatNonroot ? silentCheatNonrootDuration(product.name) : isSilentXFF ? silentXFFDuration(product.name) : isPrimeHook ? primeHookDuration(product.name) : isXrag ? xragDuration(product.name) : isPhantomTroll ? phantomTrollDuration(product.name) : isDripWire ? dripWireDuration(product.name) : isBalaMods ? balaModsDuration(product.name) : isDripClient ? dripClientApkmodDuration(product.name) : aimHackDuration(product.name);
    const supplierProductId = isSilentCheatNonroot ? "148" : (isSilentXFF ? "171" : (isPrimeHook ? "48" : (isXrag ? "149" : (isPhantomTroll ? "133" : (isAimHack ? "133" : (isBalaMods ? "136" : (isDripClient ? "62" : "150")))))));
    if (!duration) return res.status(400).json({ error: "Product duration configured nahi hai." });

    // Give customers a clear deposit redirect before attempting the atomic purchase.
    // The RPC below remains the final authority for charging the wallet.
    const { data: currentWallet, error: currentWalletError } = await supabase
      .from("wallets")
      .select("balance")
      .eq("user_id", user.id)
      .maybeSingle();
    if (currentWalletError) {
      console.error("Wallet precheck failed:", currentWalletError.message);
      return res.status(500).json({ error: "Wallet balance check nahi ho saka. Thodi der baad dobara try karein." });
    }
    if (!currentWallet) {
      return res.status(402).json({ error: "WALLET_NOT_FOUND: Wallet nahi mila. Pehle wallet mein deposit add karein." });
    }
    if (Number(currentWallet.balance || 0) < amount) {
      return res.status(402).json({ error: "INSUFFICIENT_WALLET_BALANCE: Wallet balance kam hai. Pehle wallet mein deposit karein." });
    }

    const { data: purchase, error: walletError } = await supabase.rpc("create_wallet_product_order", {
      p_user_id: user.id,
      p_product_id: product.id,
      p_price: amount
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
      const [{ data: finalOrder }, { data: deliveredKeys }] = await Promise.all([
        supabase.from("orders")
          .select('id, created_at, "Product_name", "Amount", "Payment_status", "Order status", supplier_status')
          .eq("id", orderId).maybeSingle(),
        supabase.from("customer_keys").select("key_value")
          .eq("order_id", orderId).eq("user_id", user.id).order("created_at", { ascending: true }).limit(10)
      ]);
      return res.status(201).json({
        success: true,
        order: {
          id: orderId,
          product_name: product.name,
          amount,
          payment_status: "paid",
          order_status: finalOrder?.["Order status"] || "completed",
          supplier_status: "completed",
          key_value: deliveredKeys?.[0]?.key_value || null,
          key_count: delivered.keyCount,
          wallet_balance: Number(purchase.wallet_balance),
          created_at: finalOrder?.created_at || new Date().toISOString()
        },
        message: "Wallet se payment ho gayi aur key My Account mein deliver kar di gayi."
      });
    } catch (supplierError) {
      const safeMessage = String(supplierError?.message || "Supplier delivery failed").slice(0, 250);
      console.error("Supplier wallet purchase delivery failed:", JSON.stringify({
        productName: String(product.name || "").slice(0, 100),
        productId: String(product.id || "").slice(0, 80),
        supplierProductId: String(supplierProductId || "").slice(0, 40),
        duration: String(duration || "").slice(0, 40),
        error: safeMessage
      }));
      const { data: refunded, error: refundError } = await supabase.rpc("refund_wallet_product_order", {
        p_order_id: orderId,
        p_user_id: user.id,
        p_reason: safeMessage
      });
      if (refundError) console.error("Wallet refund failed; admin must reconcile:", refundError.message);
      return res.status(502).json({
        success: false,
        refunded: refunded === true,
        product_unavailable: refunded === true,
        error: refunded === true
          ? "Product not available. Refund successful — ₹" + amount.toFixed(2) + " wallet mein wapas aa gaye."
          : "Product delivery fail hui. Refund confirm nahi hua; balance dobara spend na karein aur support se contact karein."
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
    .select("id, name, price, image_url, video_url, download_url, published, description, created_at, updated_at")
    .order("created_at", { ascending: false });
  if (error) {
    console.error("Admin products load failed:", error.message);
    return res.status(500).json({ error: "Products load nahi ho sake." });
  }
  res.json({ products: data || [] });
});

// Safe diagnostics only: this endpoint NEVER buys a key, charges a wallet, or
// calls the supplier's purchase action. It verifies local configuration/mappings.
app.get("/api/admin/product-health-check", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  try {
    const { data: products, error } = await supabase.from("products")
      .select("id, name, price, published").order("name", { ascending: true });
    if (error) throw error;
    const credentialsReady = Boolean(
      String(process.env.BANTI_MASTER_KEY || process.env.RESELLER_ACCESS_TOKEN || "").trim() &&
      String(process.env.RESELLER_API_KEY || process.env.RESELLER_ACCESS_TOKEN || "").trim()
    );
    const checks = (products || []).map(p => {
      const name = String(p.name || "");
      let supplierId = null, duration = null, automatic = false;
      if (/silent\s+cheat\s+ff\s+nonroot\s+proxy/i.test(name)) {
        supplierId = "148"; duration = silentCheatNonrootDuration(name); automatic = true;
      } else if (/silent\s*x\s*ff/i.test(name)) {
        supplierId = "171"; duration = silentXFFDuration(name); automatic = true;
      } else if (/prime\s*hook/i.test(name)) {
        supplierId = "48"; duration = primeHookDuration(name); automatic = true;
      } else if (/xrag\s*ff\s*all/i.test(name)) {
        supplierId = "149"; duration = xragDuration(name); automatic = true;
      } else if (/phantom\s*x\s*troll\s*ff\s*all/i.test(name)) {
        supplierId = "133"; duration = phantomTrollDuration(name); automatic = true;
      } else if (/^DRIP Wire - /i.test(name)) {
        supplierId = "150"; duration = dripWireDuration(name); automatic = true;
      } else if (/^AIM HACK FF(?: - |$)/i.test(name)) {
        supplierId = "133"; duration = aimHackDuration(name); automatic = true;
      } else if (/bala\s*mods/i.test(name)) {
        supplierId = "136"; duration = balaModsDuration(name); automatic = true;
      } else if (/dripclient.*apkmod/i.test(name)) {
        supplierId = "62"; duration = dripClientApkmodDuration(name); automatic = true;
      }
      let status, detail;
      if (!automatic) { status = "manual"; detail = "No automatic supplier mapping detected; manual/download-link product or mapping needed."; }
      else if (!credentialsReady) { status = "config_error"; detail = "Supplier credentials appear missing; no supplier call was made."; }
      else if (!duration) { status = "duration_error"; detail = "Product name duration does not match configured supplier duration."; }
      else { status = "mapping_ok"; detail = "Local mapping and credential presence look OK. Actual supplier stock/key delivery has NOT been tested."; }
      return { id: p.id, name, price: Number(p.price || 0), published: Boolean(p.published), supplier_id: supplierId, duration, status, detail };
    });
    res.json({ success: true, mode: "safe_no_purchase", checked_at: new Date().toISOString(), total: checks.length,
      summary: { mapping_ok: checks.filter(x=>x.status==="mapping_ok").length, config_error: checks.filter(x=>x.status==="config_error").length, duration_error: checks.filter(x=>x.status==="duration_error").length, manual: checks.filter(x=>x.status==="manual").length },
      note: "No keys were purchased and no wallet was charged. Mapping OK does not prove supplier stock or that a key activates.", products: checks });
  } catch (e) {
    console.error("Product health check failed:", e.message);
    res.status(500).json({ error: "Product diagnostic failed. Check server logs." });
  }
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
  if (Object.prototype.hasOwnProperty.call(req.body || {}, "download_url")) {
    const downloadUrl = typeof req.body.download_url === "string" ? req.body.download_url.trim() : "";
    if (downloadUrl && (downloadUrl.length > 2000 || !/^https:\/\//i.test(downloadUrl)))
      return res.status(400).json({ error: "Download link https:// se shuru hona chahiye." });
    updates.download_url = downloadUrl || null;
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


app.get("/api/setup-link", async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  const { data, error } = await supabase.from("reseller_settings").select("whatsapp_group_url").eq("id", 1).maybeSingle();
  if (error) return res.status(500).json({ error: "Setup link load nahi hua." });
  res.set("Cache-Control", "no-store");
  res.json({ whatsapp_group_url: data?.whatsapp_group_url || "" });
});

app.get("/api/admin/resellers", isAdmin, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: "Database is not configured" });
  try {
    const [usersResult, accountsResult, settingsResult, productsResult, resellerPricesResult] = await Promise.all([
      supabase.auth.admin.listUsers({ page: 1, perPage: 1000 }),
      supabase.from("reseller_accounts").select("user_id, is_active, activation_price, activated_at, created_at"),
      supabase.from("reseller_settings").select("activation_price, whatsapp_group_url").eq("id", 1).maybeSingle(),
      supabase.from("products").select("id, name, price, published").order("name"),
      supabase.from("reseller_prices").select("product_id, price").is("reseller_user_id", null)
    ]);
    if (usersResult.error) throw new Error("Customer list: " + usersResult.error.message);
    if (accountsResult.error) throw new Error("Reseller table: " + accountsResult.error.message);
    if (settingsResult.error) throw new Error("Reseller settings: " + settingsResult.error.message);
    if (productsResult.error) throw new Error("Products: " + productsResult.error.message);
    if (resellerPricesResult.error) throw new Error("Reseller prices: " + resellerPricesResult.error.message);
    const accountMap = new Map((accountsResult.data || []).map(a => [a.user_id, a]));
    const customers = (usersResult.data?.users || []).map(u => { const a=accountMap.get(u.id); return {id:u.id,email:u.email||"",name:String(u.user_metadata?.full_name||u.user_metadata?.name||u.email?.split("@")[0]||"Customer"),is_reseller:Boolean(a),reseller_active:Boolean(a?.is_active),activation_price:Number(a?.activation_price||0)}; });
    const resellerPriceMap = new Map((resellerPricesResult.data || []).map(p => [p.product_id, Number(p.price)]));
    const products = (productsResult.data || []).map(p => ({...p, reseller_price: resellerPriceMap.has(p.id) ? resellerPriceMap.get(p.id) : null}));
    res.json({settings:settingsResult.data||{activation_price:0},customers,products});
  } catch(e) { console.error("Reseller admin load failed:",e.message); res.status(500).json({error:"Reseller data load nahi hua: "+String(e.message||"Unknown error").slice(0,180)}); }
});
app.post("/api/admin/resellers/settings", isAdmin, async (req,res) => {
  if(!supabase)return res.status(503).json({error:"Database is not configured"});
  const activationPrice=Number(req.body?.activation_price);
  if(!Number.isFinite(activationPrice)||activationPrice<0||activationPrice>1000000)return res.status(400).json({error:"Valid activation price enter karein."});
  const whatsappGroupUrl=typeof req.body?.whatsapp_group_url==="string"?req.body.whatsapp_group_url.trim():"";
  if(whatsappGroupUrl && !/^https:\/\/[a-z0-9.-]+(?::\d+)?(?:\/[^\s]*)?$/i.test(whatsappGroupUrl)) return res.status(400).json({error:"Valid HTTPS download/profile link enter karein."});
   const {data,error}=await supabase.from("reseller_settings").upsert({id:1,activation_price:activationPrice,whatsapp_group_url:whatsappGroupUrl,updated_at:new Date().toISOString()},{onConflict:"id"}).select("activation_price,whatsapp_group_url").single();
  if(error){console.error("Reseller settings save failed:",error.message);return res.status(500).json({error:"Activation price save nahi hua."});}
  res.json({success:true,settings:data});
});
app.post("/api/admin/resellers/assign", isAdmin, async (req,res) => {
  if(!supabase)return res.status(503).json({error:"Database is not configured"});
  const userId=typeof req.body?.user_id==="string"?req.body.user_id.trim():"",active=req.body?.active!==false;
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId))return res.status(400).json({error:"Valid customer select karein."});
  const {data:settings}=await supabase.from("reseller_settings").select("activation_price").eq("id",1).maybeSingle();
  if(active){
    const {data,error}=await supabase.from("reseller_accounts").upsert({user_id:userId,is_active:true,activation_price:Number(settings?.activation_price||0),activated_at:new Date().toISOString(),updated_at:new Date().toISOString()},{onConflict:"user_id"}).select("user_id,is_active,activation_price").single();
    if(error){console.error("Reseller assignment failed:",error.message);return res.status(500).json({error:"Customer reseller nahi bana."});}
    return res.json({success:true,reseller:data});
  }
  const {data,error}=await supabase.from("reseller_accounts").update({is_active:false,updated_at:new Date().toISOString()}).eq("user_id",userId).select("user_id,is_active").maybeSingle();
  if(error){console.error("Reseller removal failed:",error.message);return res.status(500).json({error:"Reseller status update nahi hua."});}
  if(!data)return res.status(404).json({error:"Reseller record nahi mila."});
  res.json({success:true,reseller:data});
});
app.post("/api/admin/reseller-prices", isAdmin, async (req,res) => {
  if(!supabase)return res.status(503).json({error:"Database is not configured"});
  const productId=typeof req.body?.product_id==="string"?req.body.product_id.trim():"";
  const resellerUserId=typeof req.body?.reseller_user_id==="string"&&req.body.reseller_user_id.trim()?req.body.reseller_user_id.trim():null;
  const price=Number(req.body?.price);
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(productId)||!Number.isFinite(price)||price<0||price>1000000)return res.status(400).json({error:"Key aur valid reseller price select karein."});
  if(resellerUserId){const {data:account}=await supabase.from("reseller_accounts").select("user_id").eq("user_id",resellerUserId).eq("is_active",true).maybeSingle();if(!account)return res.status(400).json({error:"Is customer ka reseller access active nahi hai."});}
  let lookup=supabase.from("reseller_prices").select("id").eq("product_id",productId);
  lookup=resellerUserId?lookup.eq("reseller_user_id",resellerUserId):lookup.is("reseller_user_id",null);
  const {data:existing,error:lookupError}=await lookup.maybeSingle();
  if(lookupError){console.error("Reseller price lookup failed:",lookupError.message);return res.status(500).json({error:"Existing reseller price check nahi hua."});}
  const values={product_id:productId,reseller_user_id:resellerUserId,price,updated_at:new Date().toISOString()};
  let saved,error;
  if(existing){const r=await supabase.from("reseller_prices").update(values).eq("id",existing.id).select("id,product_id,reseller_user_id,price").single();saved=r.data;error=r.error;}
  else{const r=await supabase.from("reseller_prices").insert(values).select("id,product_id,reseller_user_id,price").single();saved=r.data;error=r.error;}
  if(error){console.error("Reseller price save failed:",error.message);return res.status(500).json({error:"Reseller key price save nahi hua."});}
  res.json({success:true,reseller_price:saved});
});

app.listen(PORT, () => {
  console.log("JKPanel server running on port " + PORT);
});
