import { Router } from "express";
import crypto from "crypto";

const router = Router();

router.get("/", (_req, res) => {
  const sessionId = crypto.randomBytes(16).toString("hex");
  const challenge = crypto.randomBytes(16).toString("hex");

  res.json({ sessionId, challenge });
});

export default router;
