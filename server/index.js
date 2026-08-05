require("dotenv").config();
const express = require("express");
const cors = require("cors");
const webhookRoutes = require("./routes/webhook");

const app = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());
app.use("/webhook", webhookRoutes);

app.listen(PORT, () => {
  console.log(`SENTINEL running on http://localhost:${PORT}`);
});
