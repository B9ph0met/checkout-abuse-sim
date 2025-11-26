// backend/src/api/riskTestRoute.ts

import { Router } from "express";
import { computeRisk } from "../risk/riskEngine";
import { decideAction, DecisionOutcome } from "../decisions/decisionEngine";
import { ActionType } from "../risk/types";

const router = Router();
const events: any[] = [];

router.post("/checkout", async (req, res) => {
  const { ip, userAgent, action, deviceId, browser } = req.body;
  const safeAction = (action ?? "CHECKOUT") as ActionType;

  const risk = await computeRisk({ ip, userAgent, action: safeAction, deviceId, browser });
  const decision: DecisionOutcome = decideAction(risk);

  const event = {
    at: new Date().toISOString(),
    ip,
    userAgent,
    action: safeAction,
    deviceId,
    risk,
    decision,
  };

  events.push(event);
  res.json(event);
});

router.get("/events", (_req, res) => {
  res.json(events.slice(-100)); // last 100
});

export default router;
