// backend/src/index.ts
import express from "express";
import cors from "cors";
import path from "path";

const app = express();
app.use(cors());
app.use(express.json());

// Serve frontend (index.html, events.html)
app.use(express.static(path.join(__dirname, "..", "public")));

// Routers
import checkoutRoute from "./api/checkoutRoute";
import dashboardRoute from "./api/dashboardRoute";
import sessionRoute from "./api/sessionRoute";

// IMPORTANT: mount /api/session FIRST, others under /api
app.use("/api/session", sessionRoute);  // GET /api/session
app.use("/api", checkoutRoute);         // POST /api/checkout
app.use("/api", dashboardRoute);        // GET /api/events (etc.)

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
