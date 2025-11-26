# 🚦 Checkout Abuse Simulator

**A compact, production-style anti-bot and abuse-detection engine.**

This project simulates the core pipeline used by large platforms (Google, Meta, Stripe) to detect automated abuse during checkout or login flows.
It includes **signed telemetry**, **risk scoring**, **velocity detection**, **device correlation**, and a **real-time analyst dashboard**.

---

## 🔍 What it does

* **Cryptographically signed telemetry**
  Prevents payload tampering & replay attacks (`SIGNED_OK`, `REPLAY`, `TAMPERED`, `UNSIGNED`).

* **Config-driven risk engine**
  Central rule weighting (UA anomalies, headless indicators, velocity, correlation, integrity failures).

* **Velocity & correlation detection**
  Detects:

  * High IP/device request rates
  * Same device across many IPs
  * Same IP serving many devices

* **Browser integrity signals**
  UA validation, missing engine tokens, suspicious renderers, touch mismatch, locale/timezone anomalies, headless hints.

* **Event Log Dashboard**
  Real-time review of decisions, risk breakdowns, signature statuses, latency, and device/IP context.

* **Polished UI**
  Simulator + dashboard styled like an internal abuse-analyst tool.

---

## 🧠 System Overview

```
public/index.html          →  Simulator (generates signed telemetry)
public/events.html         →  Dashboard (analyst UI)

backend/src/api/*          →  API routes
backend/src/risk/*         →  Risk engine + config
backend/src/storage/*      →  Event log + replay cache
backend/src/index.ts       →  Express server
```

Pipeline: **simulate ⇒ sign ⇒ verify ⇒ score ⇒ decide ⇒ log ⇒ review**

---

## 🚀 Run locally

```bash
npm install
npm run dev
```

Open:

* Simulator → [http://localhost:3001](http://localhost:3001)
* Dashboard → [http://localhost:3001/events.html](http://localhost:3001/events.html)

---

## 🧪 Quick test scenarios

**Clean browser:**
ALLOW
Normal UA, consistent device, low velocity.

**Basic bot:**
curl / python UA → BLOCK

**Proxy hopping:**
Same deviceId across many IPs → BLOCK/SHADOW_BAN

**Replay attack:**
Same `(sessionId, signature)` twice → signatureStatus=REPLAY

---

## 🎯 Why this project exists

To demonstrate **practical abuse-detection engineering**:
signal design, adversarial thinking, scoring pipelines, correlation logic, integrity verification, and analyst-facing tooling.

This mirrors the foundations of real work done on:

* Anti-Abuse / Integrity Engineering
* Bot detection
* Fraud & Risk
* Trust & Safety
* Platform security

---

## 📝 License

MIT — educational + portfolio use.
