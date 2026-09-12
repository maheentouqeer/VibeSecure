/**
 * Real backend client -- replaces the mock data page.tsx used to generate.
 *
 * Ownership model (matches backend/main.py exactly): the backend issues an
 * opaque X-Owner-Token on the first scan and expects it back on every later
 * request for that scan. We persist it in localStorage so a returning
 * visitor's later scans/rescans/badge checks are still recognized as theirs.
 */

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const TOKEN_KEY = "secure-vibecode-owner-token";

export function getOwnerToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

function persistOwnerToken(token: string) {
  if (typeof window !== "undefined") window.localStorage.setItem(TOKEN_KEY, token);
}

// ---------------------------------------------------------------------------
// Shapes returned by the backend (snake_case, matches backend/schemas.py)
// ---------------------------------------------------------------------------
export type ApiSeverity = "critical" | "high" | "medium" | "low";
export type ApiFindingStatus = "open" | "resolved";

export interface ApiFinding {
  id: string;
  category: string;
  label: string;
  file: string;
  severity: ApiSeverity;
  what_it_means: string;
  why_it_matters: string;
  fix_prompt: string;
  status: ApiFindingStatus;
}

export interface ApiScan {
  id: string;
  target: string;
  platform: string;
  status: string;
  created_at: string;
  findings: ApiFinding[];
}

export class ApiError extends Error {}

async function apiFetch(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<ApiScan> {
  const token = getOwnerToken();
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (token) headers.set("X-Owner-Token", token);

  const res = await fetch(`${API_URL}${path}`, { ...init, headers, signal });

  const returnedToken = res.headers.get("X-Owner-Token");
  if (returnedToken) persistOwnerToken(returnedToken);

  if (!res.ok) {
    const body = await res.json().catch(() => ({}) as { detail?: string });
    throw new ApiError(body.detail || `Request failed with status ${res.status}`);
  }
  return res.json();
}

export function createScan(target: string, signal?: AbortSignal): Promise<ApiScan> {
  return apiFetch("/scans", { method: "POST", body: JSON.stringify({ target }) }, signal);
}

export function rescanScan(scanId: string, signal?: AbortSignal): Promise<ApiScan> {
  return apiFetch(`/scans/${scanId}/rescan`, { method: "POST" }, signal);
}

export function getScan(scanId: string, signal?: AbortSignal): Promise<ApiScan> {
  return apiFetch(`/scans/${scanId}`, {}, signal);
}
