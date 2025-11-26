// backend/src/decisions/decisionEngine.ts

import type { RiskResult } from "../risk/types";
import { RISK_THRESHOLDS } from "../risk/config";

export type DecisionOutcome = "ALLOW" | "CAPTCHA" | "BLOCK" | "SHADOW_BAN";

export function decideAction(risk: RiskResult): DecisionOutcome {
  const score = risk.total;

  if (score <= RISK_THRESHOLDS.ALLOW_MAX) return "ALLOW";
  if (score <= RISK_THRESHOLDS.CAPTCHA_MAX) return "CAPTCHA";
  if (score <= RISK_THRESHOLDS.BLOCK_MAX) return "BLOCK";
  return "SHADOW_BAN";
}
