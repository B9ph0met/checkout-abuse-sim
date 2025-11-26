import { RiskContext, RiskReason } from "../types";

// Totally fake demo data – just for simulation.
const KNOWN_BAD_IPS = new Set<string>([
  "203.0.113.42",
  "198.51.100.99",
]);

const SUSPICIOUS_PREFIXES = [
  "198.51.100.",  // example doc range (pretend it's a datacenter)
  "203.0.113.",  // another example range
];

export async function ipReputationSignal(ctx: RiskContext): Promise<RiskReason> {
  const ip = (ctx.ip || "").trim();

  if (!ip) {
    return {
      label: "Missing IP address",
      points: 10,
    };
  }

  if (KNOWN_BAD_IPS.has(ip)) {
    return {
      label: "Known abusive IP",
      points: 60,
    };
  }

  if (SUSPICIOUS_PREFIXES.some((prefix) => ip.startsWith(prefix))) {
    return {
      label: "IP looks like datacenter / proxy range",
      points: 30,
    };
  }

  // Default: looks fine
  return {
    label: "Normal IP reputation",
    points: 0,
  };
}
