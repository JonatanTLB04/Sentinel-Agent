require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const webhookRoutes = require("./routes/webhook");
const { getStats, getAlerts } = require("./lib/store");

const app = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

app.use("/webhook", webhookRoutes);

app.get("/api/stats", (req, res) => res.json(getStats()));
app.get("/api/alerts", (req, res) => res.json(getAlerts()));

app.listen(PORT, () => {
  console.log(`SENTINEL running on http://localhost:${PORT}`);
});
