/**
 * Real backend client -- replaces the mock data page.tsx used to generate.
 *
 * Ownership model (matches backend/main.py exactly): the backend issues an
 * opaque X-Owner-Token on the first scan and expects it back on every later
 * request for that scan. We persist it in localStorage so a returning
 * visitor's later scans/rescans/badge checks are still recognized as theirs.
 */

import { supabase } from "./supabase";

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
  error: string | null;
  findings: ApiFinding[];
}

export class ApiError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

async function apiFetch<T = ApiScan>(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<T> {
  const token = getOwnerToken();
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (token) headers.set("X-Owner-Token", token);

  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (session?.access_token) {
    headers.set("Authorization", `Bearer ${session.access_token}`);
  }

  const res = await fetch(`${API_URL}${path}`, { ...init, headers, signal });

  const returnedToken = res.headers.get("X-Owner-Token");
  if (returnedToken) persistOwnerToken(returnedToken);

  if (!res.ok) {
    const body = await res.json().catch(() => ({}) as { detail?: string });
    throw new ApiError(body.detail || `Request failed with status ${res.status}`, res.status);
  }
  return res.json();
}

const POLL_INTERVAL_MS = 1500;
const MAX_WAIT_MS = 10 * 60 * 1000;

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException("Aborted", "AbortError"));
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(new DOMException("Aborted", "AbortError"));
      },
      { once: true }
    );
  });
}

export interface ApiScanStatus {
  id: string;
  status: string;
  error: string | null;
}

// POST /scans and /rescan only queue a background job; poll until it finishes
// so callers still get one finished scan back. Polling uses the light status
// endpoint (no findings); the full scan is fetched once, at the end.
async function waitForScan(scanId: string, signal?: AbortSignal): Promise<ApiScan> {
  const deadline = Date.now() + MAX_WAIT_MS;
  for (;;) {
    const state = await apiFetch<ApiScanStatus>(`/scans/${scanId}/status`, {}, signal);
    if (state.status !== "queued" && state.status !== "running") {
      if (state.error) throw new ApiError(state.error);
      return getScan(scanId, signal);
    }
    if (Date.now() > deadline) throw new ApiError("The scan is taking too long. Please try again.");
    await sleep(POLL_INTERVAL_MS, signal);
  }
}

export async function createScan(target: string, signal?: AbortSignal): Promise<ApiScan> {
  const queued = await apiFetch("/scans", { method: "POST", body: JSON.stringify({ target }) }, signal);
  return waitForScan(queued.id, signal);
}

export async function rescanScan(scanId: string, signal?: AbortSignal): Promise<ApiScan> {
  await apiFetch(`/scans/${scanId}/rescan`, { method: "POST" }, signal);
  return waitForScan(scanId, signal);
}

export function getScan(scanId: string, signal?: AbortSignal): Promise<ApiScan> {
  return apiFetch(`/scans/${scanId}`, {}, signal);
}

export async function listScans(signal?: AbortSignal): Promise<ApiScan[]> {
  const token = getOwnerToken();
  const headers: Record<string, string> = {};
  if (token) headers["X-Owner-Token"] = token;
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (session?.access_token) {
    headers["Authorization"] = `Bearer ${session.access_token}`;
  }
  const res = await fetch(`${API_URL}/scans`, { headers, signal });
  if (!res.ok) return [];
  return res.json();
}

export interface ApiMeResponse {
  user: { id: string; email: string } | null;
  plan: string;
  limits: { monthly_scans: number; auto_rescan: boolean };
  usage: { scans_this_month: number };
  enforced: boolean;
  orgs: { id: string; name: string; role: string }[];
}

export async function getMe(signal?: AbortSignal): Promise<ApiMeResponse> {
  return apiFetch<ApiMeResponse>("/me", {}, signal);
}

export async function claimScans(signal?: AbortSignal): Promise<{ claimed: number }> {
  return apiFetch<{ claimed: number }>("/me/claim", { method: "POST" }, signal);
}

export async function createCheckout(plan: "pro" = "pro", signal?: AbortSignal): Promise<{ url: string }> {
  return apiFetch<{ url: string }>("/billing/checkout", { method: "POST", body: JSON.stringify({ plan }) }, signal);
}


export interface ApiKeyMeta {
  id: string;
  label: string;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface ApiKeyCreated extends ApiKeyMeta {
  key: string;
  warning: string;
}

export async function listApiKeys(signal?: AbortSignal): Promise<ApiKeyMeta[]> {
  return apiFetch<ApiKeyMeta[]>("/me/api-keys", {}, signal);
}

export async function createApiKey(label: string, signal?: AbortSignal): Promise<ApiKeyCreated> {
  return apiFetch<ApiKeyCreated>("/me/api-keys", {
    method: "POST",
    body: JSON.stringify({ label }),
  }, signal);
}

export async function revokeApiKey(keyId: string, signal?: AbortSignal): Promise<void> {
  await apiFetch<void>("/me/api-keys/" + keyId, { method: "DELETE" }, signal);
}
