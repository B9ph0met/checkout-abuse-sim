// backend/src/risk/config.ts

// Simple numeric thresholds for mapping risk → decision.
export const RISK_THRESHOLDS = {
  ALLOW_MAX: 20,    // score 0–20 → ALLOW
  CAPTCHA_MAX: 50,  // 21–50    → CAPTCHA
  BLOCK_MAX: 80,    // 51–80    → BLOCK
  // anything > BLOCK_MAX → SHADOW_BAN
};

export type RuleCategory =
  | "VELOCITY"
  | "CORRELATION"
  | "BROWSER_INTEGRITY"
  | "FINGERPRINT"
  | "USER_AGENT"
  | "SIGNATURE"
  | "TESTING";

export type RuleId =
  | "IP_HIGH_VELOCITY"
  | "IP_EXTREME_VELOCITY"
  | "DEVICE_HIGH_VELOCITY"
  | "DEVICE_MANY_IPS"
  | "IP_MANY_DEVICES"
  | "HEADLESS_UA"
  | "NO_WEBGL"
  | "SOFTWARE_RENDERER"
  | "MOBILE_ZERO_TOUCH"
  | "MOBILE_DESKTOP_PLATFORM"
  | "MOBILE_DESKTOP_RESOLUTION"
  | "DESKTOP_SINGLE_CORE"
  | "DESKTOP_LOW_MEMORY"
  | "NO_LANGUAGES"
  | "NO_AUDIO_CONTEXT"
  | "MISSING_CANVAS_FP"
  | "UA_TOO_SHORT"
  | "UA_MISSING_MOZILLA"
  | "UA_MALFORMED_MOZILLA"
  | "UA_NON_BROWSER"
  | "UA_MISSING_ENGINE"
  | "UA_PYTHON_REQUESTS"
  | "TEST_IP"
  | "SIGNATURE_INVALID"
  | "SIGNATURE_REPLAY";

export interface RuleConfig {
  id: RuleId;
  label: string;       // base label (we can append dynamic bits in code)
  category: RuleCategory;
  points: number;
  enabled: boolean;
}

export const RULES: RuleConfig[] = [
  {
    id: "IP_HIGH_VELOCITY",
    label: "High request velocity from IP",
    category: "VELOCITY",
    points: 30,
    enabled: true,
  },
  {
    id: "IP_EXTREME_VELOCITY",
    label: "Extreme request velocity from IP",
    category: "VELOCITY",
    points: 60,
    enabled: true,
  },
  {
    id: "DEVICE_HIGH_VELOCITY",
    label: "High request velocity from device",
    category: "VELOCITY",
    points: 25,
    enabled: true,
  },
  {
    id: "DEVICE_MANY_IPS",
    label: "Device used across many IPs",
    category: "CORRELATION",
    points: 35,
    enabled: true,
  },
  {
    id: "IP_MANY_DEVICES",
    label: "IP has seen many devices",
    category: "CORRELATION",
    points: 35,
    enabled: true,
  },
  {
    id: "HEADLESS_UA",
    label: "Headless browser detected in user-agent",
    category: "BROWSER_INTEGRITY",
    points: 50,
    enabled: true,
  },
  {
    id: "NO_WEBGL",
    label: "No WebGL renderer information",
    category: "BROWSER_INTEGRITY",
    points: 15,
    enabled: true,
  },
  {
    id: "SOFTWARE_RENDERER",
    label: "Software WebGL renderer detected",
    category: "BROWSER_INTEGRITY",
    points: 25,
    enabled: true,
  },
  {
    id: "MOBILE_ZERO_TOUCH",
    label: "Mobile UA with zero touch support",
    category: "BROWSER_INTEGRITY",
    points: 20,
    enabled: true,
  },
  {
    id: "MOBILE_DESKTOP_PLATFORM",
    label: "Mobile UA but desktop platform",
    category: "BROWSER_INTEGRITY",
    points: 15,
    enabled: true,
  },
  {
    id: "MOBILE_DESKTOP_RESOLUTION",
    label: "Mobile UA with desktop-like resolution",
    category: "BROWSER_INTEGRITY",
    points: 10,
    enabled: true,
  },
  {
    id: "DESKTOP_SINGLE_CORE",
    label: "Desktop UA with single CPU core",
    category: "BROWSER_INTEGRITY",
    points: 10,
    enabled: true,
  },
  {
    id: "DESKTOP_LOW_MEMORY",
    label: "Very low reported device memory for desktop UA",
    category: "BROWSER_INTEGRITY",
    points: 10,
    enabled: true,
  },
  {
    id: "NO_LANGUAGES",
    label: "No browser languages reported",
    category: "FINGERPRINT",
    points: 10,
    enabled: true,
  },
  {
    id: "NO_AUDIO_CONTEXT",
    label: "No AudioContext support",
    category: "FINGERPRINT",
    points: 10,
    enabled: true,
  },
  {
    id: "MISSING_CANVAS_FP",
    label: "Missing or default canvas fingerprint",
    category: "FINGERPRINT",
    points: 10,
    enabled: true,
  },
  {
    id: "UA_TOO_SHORT",
    label: "Very short user-agent",
    category: "USER_AGENT",
    points: 15,
    enabled: true,
  },
  {
    id: "UA_MISSING_MOZILLA",
    label: 'User-agent missing standard "Mozilla/" prefix',
    category: "USER_AGENT",
    points: 20,
    enabled: true,
  },
  {
    id: "UA_MALFORMED_MOZILLA",
    label: "Malformed Mozilla user-agent",
    category: "USER_AGENT",
    points: 25,
    enabled: true,
  },
  {
    id: "UA_NON_BROWSER",
    label: "Known non-browser user-agent pattern",
    category: "USER_AGENT",
    points: 40,
    enabled: true,
  },
  {
    id: "UA_MISSING_ENGINE",
    label: "Missing known browser engine token (Gecko/WebKit/Blink)",
    category: "USER_AGENT",
    points: 20,
    enabled: true,
  },
  {
    id: "UA_PYTHON_REQUESTS",
    label: "Python / requests user-agent",
    category: "USER_AGENT",
    points: 40,
    enabled: true,
  },
  {
    id: "TEST_IP",
    label: "Known test IP 1.2.3.4.2",
    category: "TESTING",
    points: 40,
    enabled: true,
  },
  {
    id: "SIGNATURE_INVALID",
    label: "Invalid or missing telemetry signature",
    category: "SIGNATURE",
    points: 80,
    enabled: true,
  },
  {
    id: "SIGNATURE_REPLAY",
    label: "Replay of signed telemetry (same session/signature)",
    category: "SIGNATURE",
    points: 70,
    enabled: true,
  },
];

// quick lookup
const ruleMap: Record<RuleId, RuleConfig> = RULES.reduce(
  (acc, r) => {
    acc[r.id] = r;
    return acc;
  },
  {} as Record<RuleId, RuleConfig>
);

export function getRuleConfig(id: RuleId): RuleConfig {
  const cfg = ruleMap[id];
  if (!cfg) {
    throw new Error(`Unknown rule id: ${id}`);
  }
  return cfg;
}
