const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));

app.get("/", (req, res) => {
res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/status", (req, res) => {
res.json({ status: "ok", message: "JKPanel server is running" });
});

app.listen(PORT, () => {
console.log("JKPanel server running on port ${PORT}");
});
