// Static apiId registry, per requirement PDF p.7/p.9: "Each API will be
// assigned its unique api id. It can use to help to prevent request payload
// swapping that valid request payload was copy/clone to send to different
// API." Deploy-time config, not runtime data — a plain constant map.

export const API_IDS = {
  SESSION_ACQUIRING: 1,
  ACCOUNTS_LIST: 2,
  ACCOUNTS_TRANSFER: 3
} as const;

export type ApiId = (typeof API_IDS)[keyof typeof API_IDS];

/** Maps a Category 2/3 BFF request (method + path under /pds/bff) to its expected apiId. */
export function apiIdForBffRequest(method: string, upstreamPath: string): ApiId | undefined {
  if (method === "GET" && upstreamPath === "/accounts") return API_IDS.ACCOUNTS_LIST;
  if (method === "POST" && upstreamPath === "/accounts/transfer") return API_IDS.ACCOUNTS_TRANSFER;
  return undefined;
}
