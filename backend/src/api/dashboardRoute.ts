import { Router } from "express";
import { getEvents } from "../storage/eventLog";

const router = Router();

router.get("/events", (_req, res) => {
  res.json(getEvents());
});

export default router;
