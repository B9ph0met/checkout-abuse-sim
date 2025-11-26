// backend/src/risk/riskEngine.ts

import { RiskContext, RiskResult, RiskReason } from "./types";
import { RuleId, getRuleConfig } from "./config";

/**
 * Config for velocity & correlation rules
 */
const IP_WINDOW_MS = 10_000;              // 10s window
const IP_HIGH_RATE_THRESHOLD = 5;         // >5 reqs in 10s = suspicious
const IP_EXTREME_RATE_THRESHOLD = 15;     // >15 = very bad

const DEVICE_WINDOW_MS = 10_000;          // 10s window for device
const DEVICE_HIGH_RATE_THRESHOLD = 8;     // >8 reqs in 10s from same device

// Correlation window: how long we look back for device<->IP relationships
const DEVICE_IP_WINDOW_MS = 60_000;       // 60s
const DEVICE_MAX_IPS_THRESHOLD = 3;       // device using >3 IPs in window
const IP_MAX_DEVICES_THRESHOLD = 5;       // IP seeing >5 devices in window

// In-memory history of recent request timestamps per IP
const ipRequestHistory = new Map<string, number[]>();

// In-memory history per deviceId
const deviceRequestHistory = new Map<string, number[]>();

// Device -> IPs mapping
const deviceToIps = new Map<string, Map<string, number[]>>();

// IP -> Devices mapping
const ipToDevices = new Map<string, Map<string, number[]>>();

function recordInWindow(
  map: Map<string, number[]>,
  key: string,
  now: number,
  windowMs: number
): number {
  const existing = map.get(key) ?? [];
  const cutoff = now - windowMs;
  const recent = existing.filter((t) => t >= cutoff);
  recent.push(now);
  map.set(key, recent);
  return recent.length;
}

// Keep nested maps pruned to time window and return unique counts
function recordDeviceIpCorrelation(
  deviceId: string,
  ip: string,
  now: number
): { uniqueIpsForDevice: number; uniqueDevicesForIp: number } {
  const cutoff = now - DEVICE_IP_WINDOW_MS;

  // ----- device -> IPs -----
  let ipMap = deviceToIps.get(deviceId);
  if (!ipMap) {
    ipMap = new Map();
    deviceToIps.set(deviceId, ipMap);
  }

  for (const [ipKey, tsList] of Array.from(ipMap.entries())) {
    const recent = tsList.filter((t) => t >= cutoff);
    if (recent.length === 0) ipMap.delete(ipKey);
    else ipMap.set(ipKey, recent);
  }

  const deviceIpTimestamps = ipMap.get(ip) ?? [];
  deviceIpTimestamps.push(now);
  ipMap.set(ip, deviceIpTimestamps);

  const uniqueIpsForDevice = ipMap.size;

  // ----- IP -> devices -----
  let devMap = ipToDevices.get(ip);
  if (!devMap) {
    devMap = new Map();
    ipToDevices.set(ip, devMap);
  }

  for (const [devKey, tsList] of Array.from(devMap.entries())) {
    const recent = tsList.filter((t) => t >= cutoff);
    if (recent.length === 0) devMap.delete(devKey);
    else devMap.set(devKey, recent);
  }

  const ipDevTimestamps = devMap.get(deviceId) ?? [];
  ipDevTimestamps.push(now);
  devMap.set(deviceId, ipDevTimestamps);

  const uniqueDevicesForIp = devMap.size;

  return { uniqueIpsForDevice, uniqueDevicesForIp };
}

// helper: push a reason using config (and optional dynamic suffix)
function addReason(
  reasons: RiskReason[],
  ruleId: RuleId,
  dynamicText?: string
) {
  const cfg = getRuleConfig(ruleId);
  if (!cfg.enabled) return;

  reasons.push({
    label: dynamicText ? `${cfg.label} ${dynamicText}` : cfg.label,
    points: cfg.points,
  });
}

/**
 * Core risk engine.
 * Returns:
 *  - total score
 *  - list of reasons (for "explain my score")
 */
export function evaluateRisk(ctx: RiskContext): RiskResult {
  const reasons: RiskReason[] = [];
  const now = Date.now();

  // 1) IP velocity rule
  const ipCount = recordInWindow(ipRequestHistory, ctx.ip, now, IP_WINDOW_MS);

  if (ipCount > IP_EXTREME_RATE_THRESHOLD) {
    addReason(
      reasons,
      "IP_EXTREME_VELOCITY",
      `(${ipCount} in last ${IP_WINDOW_MS / 1000}s)`
    );
  } else if (ipCount > IP_HIGH_RATE_THRESHOLD) {
    addReason(
      reasons,
      "IP_HIGH_VELOCITY",
      `(${ipCount} in last ${IP_WINDOW_MS / 1000}s)`
    );
  }

  // 2) Device velocity + device<->IP correlation (only if we have deviceId)
  if (ctx.deviceId) {
    const devCount = recordInWindow(
      deviceRequestHistory,
      ctx.deviceId,
      now,
      DEVICE_WINDOW_MS
    );

    if (devCount > DEVICE_HIGH_RATE_THRESHOLD) {
      addReason(
        reasons,
        "DEVICE_HIGH_VELOCITY",
        `(${devCount} in last ${DEVICE_WINDOW_MS / 1000}s)`
      );
    }

    const { uniqueIpsForDevice, uniqueDevicesForIp } = recordDeviceIpCorrelation(
      ctx.deviceId,
      ctx.ip,
      now
    );

    if (uniqueIpsForDevice > DEVICE_MAX_IPS_THRESHOLD) {
      addReason(
        reasons,
        "DEVICE_MANY_IPS",
        `(${uniqueIpsForDevice} IPs in last ${DEVICE_IP_WINDOW_MS / 1000}s)`
      );
    }

    if (uniqueDevicesForIp > IP_MAX_DEVICES_THRESHOLD) {
      addReason(
        reasons,
        "IP_MANY_DEVICES",
        `(${uniqueDevicesForIp} devices in last ${DEVICE_IP_WINDOW_MS / 1000}s)`
      );
    }
  }

  // 3) Browser integrity & fingerprint checks
  if (ctx.browser) {
    const b = ctx.browser;
    const ua = ctx.userAgent || "";

    const looksMobileUA = /Mobile|Android|iPhone|iPad/i.test(ua);
    const isHeadlessUA = /HeadlessChrome|PhantomJS|SlimerJS/i.test(ua);

    // 3a) Explicit headless indicator in UA
    if (isHeadlessUA) {
      addReason(reasons, "HEADLESS_UA");
    }

    // 3b) WebGL renderer integrity
    const renderer = (b.webglRenderer || "").toLowerCase();
    if (!b.webglVendor && !b.webglRenderer) {
      addReason(reasons, "NO_WEBGL");
    } else {
      if (
        renderer.includes("swiftshader") ||
        renderer.includes("llvmpipe") ||
        renderer.includes("software") ||
        renderer.includes("mesa")
      ) {
        addReason(
          reasons,
          "SOFTWARE_RENDERER",
          b.webglRenderer ? `(${b.webglRenderer})` : ""
        );
      }
    }

    // 3c) Mobile UA with desktop-ish platform or huge screen
    if (looksMobileUA) {
      if ((b.maxTouchPoints ?? 0) === 0) {
        addReason(reasons, "MOBILE_ZERO_TOUCH");
      }
      if (b.platform && /Win|Mac/i.test(b.platform)) {
        addReason(reasons, "MOBILE_DESKTOP_PLATFORM", `(${b.platform})`);
      }
      if (b.screenWidth >= 1400 && b.viewportWidth >= 1200) {
        addReason(
          reasons,
          "MOBILE_DESKTOP_RESOLUTION",
          `(${b.screenWidth}x${b.screenHeight})`
        );
      }
    } else {
      // Desktop UA sanity checks
      if (b.hardwareConcurrency && b.hardwareConcurrency <= 1) {
        addReason(reasons, "DESKTOP_SINGLE_CORE");
      }
      if (b.deviceMemory && b.deviceMemory <= 1) {
        addReason(reasons, "DESKTOP_LOW_MEMORY");
      }
    }

    // 3d) Language and timezone sanity
    if (!b.languages || b.languages.length === 0) {
      addReason(reasons, "NO_LANGUAGES");
    }

    // 3e) Audio / canvas fingerprinting presence
    if (!b.hasAudioContext) {
      addReason(reasons, "NO_AUDIO_CONTEXT");
    }

    if (!b.canvasHash || b.canvasHash === "0") {
      addReason(reasons, "MISSING_CANVAS_FP");
    }
  }

  // Suspicious or malformed user-agent string
  const ua = ctx.userAgent || "";

  // UA too short
  if (ua.length < 20) {
    addReason(reasons, "UA_TOO_SHORT", `(${ua.length} chars)`);
  }

  // Missing "Mozilla/" prefix (standard across all modern browsers)
  if (!ua.startsWith("Mozilla/")) {
    addReason(reasons, "UA_MISSING_MOZILLA");
  }

  // "Mozilla" but malformed version, e.g. "Mozilla1"
  if (/^Mozilla[^/]/.test(ua)) {
    addReason(reasons, "UA_MALFORMED_MOZILLA", `("${ua}")`);
  }

  // Known bot/automation identifiers
  if (/curl|wget|aiohttp|okhttp|java|node|go-http|httpclient/i.test(ua)) {
    addReason(reasons, "UA_NON_BROWSER", `("${ua}")`);
  }

  // Missing required parts like platform or engine
  if (!/Gecko|WebKit|Blink/i.test(ua)) {
    addReason(reasons, "UA_MISSING_ENGINE");
  }

  // 4) Example rule: suspicious Python user-agent
  if (/python|requests/i.test(ctx.userAgent)) {
    addReason(reasons, "UA_PYTHON_REQUESTS");
  }

  // 5) Example rule: test IP
  if (ctx.ip === "1.2.3.4.2") {
    addReason(reasons, "TEST_IP");
  }

  const total = reasons.reduce((sum, r) => sum + r.points, 0);

  return { total, reasons };
}

/**
 * Compatibility wrapper so existing code that calls `computeRisk`
 * still works. It's async only so the call sites don't need to change.
 */
export async function computeRisk(ctx: RiskContext): Promise<RiskResult> {
  return evaluateRisk(ctx);
}
