
const express = require("express");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase =
  supabaseUrl && supabaseKey
    ? createClient(supabaseUrl, supabaseKey)
    : null;

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/status", (req, res) => {
  res.json({
    status: "ok",
    databaseConfigured: Boolean(supabase)
  });
});

app.post("/api/orders", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(503).json({
        error: "Database is not configured"
      });
    }

    const { customer_name, product_name, amount } = req.body;

    if (
      typeof customer_name !== "string" ||
      !customer_name.trim() ||
      typeof product_name !== "string" ||
      !product_name.trim() ||
      !Number.isFinite(Number(amount)) ||
      Number(amount) <= 0
    ) {
      return res.status(400).json({
        error: "Valid customer, product and amount are required"
      });
    }

    const { data, error } = await supabase
      .from("orders")
      .insert([{
        customer_name: customer_name.trim(),
        product_name: product_name.trim(),
        amount: Number(amount),
        payment_status: "pending",
        order_status: "pending"
      }])
      .select("id, customer_name, product_name, amount, payment_status, order_status, created_at")
      .single();

    if (error) {
      console.error("Order insert failed:", error.message);
      return res.status(500).json({
        error: "Could not create order"
      });
    }

    return res.status(201).json({ order: data });
  } catch (error) {
    console.error("Order request failed:", error.message);
    return res.status(500).json({
      error: "Server error"
    });
  }
});

app.listen(PORT, () => {
  console.log(`JKPanel server running on port ${PORT}`);
});
