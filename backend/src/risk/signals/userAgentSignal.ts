import { RiskContext, RiskReason } from "../types";

export async function userAgentSignal(
  ctx: RiskContext
): Promise<RiskReason> {
  const ua = (ctx.userAgent || "").toLowerCase();

  if (!ua) {
    return { label: "Missing user-agent header", points: 20 };
  }

  if (
    ua.includes("curl") ||
    ua.includes("python") ||
    ua.includes("bot")
  ) {
    return { label: "User agent looks like a script / bot", points: 40 };
  }

  if (ua.includes("headless") || ua.includes("puppeteer")) {
    return { label: "Headless browser detected", points: 40 };
  }

  return { label: "Normal user agent", points: 0 };
}
