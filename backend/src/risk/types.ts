// backend/src/risk/types.ts

// What kind of action the user is taking
export type ActionType = "CHECKOUT" | "LOGIN";

// Individual reason that contributed to the risk score
export type RiskReason = {
  label: string;
  points: number;
};

// Extra browser info sent from the frontend
export type BrowserInfo = {
  screenWidth: number;
  screenHeight: number;
  viewportWidth: number;
  viewportHeight: number;
  colorDepth: number;
  devicePixelRatio: number;

  timezoneOffset: number;
  platform: string;
  hardwareConcurrency?: number;
  deviceMemory?: number;
  maxTouchPoints?: number;
  languages?: string[];

  webglVendor?: string;
  webglRenderer?: string;
  hasAudioContext?: boolean;
  canvasHash?: string;
};

// Context we feed into the risk engine
export type RiskContext = {
  ip: string;
  userAgent: string;
  action: ActionType;
  deviceId?: string;      // fingerprinted device id
  browser?: BrowserInfo;  // browser integrity info
};

// Result of evaluating risk for a single request
export type RiskResult = {
  total: number;         // total risk score
  reasons: RiskReason[]; // list of reasons that added points
};
