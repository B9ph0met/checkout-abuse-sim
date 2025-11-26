// backend/src/storage/eventLog.ts
import { RiskResult } from "../risk/types";
import { DecisionOutcome } from "../decisions/decisionEngine";

export type SignatureStatus = "SIGNED_OK" | "TAMPERED" | "REPLAY" | "UNSIGNED";

// You can delete RiskEvent if it's not used anywhere
// export interface RiskEvent { ... }

export type EventLogEntry = {
  at: string;
  ip: string;
  userAgent: string;
  action: string;
  deviceId?: string;
  risk: RiskResult;              // { total, reasons }
  decision: DecisionOutcome;
  signatureStatus?: SignatureStatus;  // 👈 add this (optional so old events still type-check)
};

const MAX_EVENTS = 100;
const events: EventLogEntry[] = [];

export function addEvent(entry: EventLogEntry): void {
  events.unshift(entry);
  if (events.length > MAX_EVENTS) {
    events.pop();
  }
}

export function getEvents(): EventLogEntry[] {
  return events;
}
