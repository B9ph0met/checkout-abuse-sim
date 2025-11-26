// backend/src/api/checkoutRoute.ts

import { Router } from "express";
import crypto from "crypto";
import { computeRisk } from "../risk/riskEngine";
import { decideAction } from "../decisions/decisionEngine";
import { addEvent, EventLogEntry, SignatureStatus } from "../storage/eventLog";
import { ActionType, RiskResult } from "../risk/types";
import { isReplayAndRecord } from "../storage/replayCache";
import { getRuleConfig } from "../risk/config";

const router = Router();

router.post("/checkout", async (req, res) => {
  const { sessionId, challenge, signature, payload } = req.body || {};

  if (!payload) {
    return res.status(400).json({ error: "Missing payload" });
  }

  const { ip, userAgent, action, deviceId } = payload;
  const safeAction = (action ?? "CHECKOUT") as ActionType;

  // ---------------------------
  // 1) SignatureStatus + integrity check
  // ---------------------------
  const hasSignatureParts = Boolean(sessionId && challenge && signature);

  let integrityOk = false;
  let signatureStatus: SignatureStatus = "UNSIGNED";

  if (hasSignatureParts) {
    const expected = crypto
      .createHash("sha256")
      .update(challenge + JSON.stringify(payload))
      .digest("hex");

    if (expected === signature) {
      integrityOk = true;
      // we'll decide between SIGNED_OK / REPLAY after replay check
    } else {
      integrityOk = false;
      signatureStatus = "TAMPERED";
    }
  } else {
    integrityOk = false;
    signatureStatus = "UNSIGNED";
  }

  let risk: RiskResult;

  // ---------------------------
  // 2) Invalid / missing signature -> instant BLOCK (config-driven)
  // ---------------------------
  if (!integrityOk) {
    const rule = getRuleConfig("SIGNATURE_INVALID");
    risk = {
      total: rule.points,
      reasons: [
        {
          label: rule.label,
          points: rule.points,
        },
      ],
    };
  } else {
    // ---------------------------
    // 3) Replay protection
    // ---------------------------
    if (isReplayAndRecord(sessionId as string, signature as string)) {
      signatureStatus = "REPLAY";

      const rule = getRuleConfig("SIGNATURE_REPLAY");
      risk = {
        total: rule.points,
        reasons: [
          {
            label: rule.label,
            points: rule.points,
          },
        ],
      };
    } else {
      // ---------------------------
      // 4) Normal risk evaluation (valid fresh signature)
      // ---------------------------
      signatureStatus = "SIGNED_OK";

      risk = await computeRisk({
        ip,
        userAgent,
        action: safeAction,
        deviceId,
      });
    }
  }

  const decision = decideAction(risk);

  const event: EventLogEntry = {
    at: new Date().toISOString(),
    ip,
    userAgent,
    action: safeAction,
    deviceId,
    risk,
    decision,
    signatureStatus,
  };

  addEvent(event);
  res.json(event);
});

export default router;
