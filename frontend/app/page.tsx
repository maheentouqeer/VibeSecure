"use client";

import { useEffect, useRef, useState } from "react";
import {
  Shield,
  ShieldCheck,
  Sun,
  Moon,
  Loader2,
  CheckCircle2,
  XCircle,
  Circle,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  History,
  ArrowLeft,
  Sparkles,
  X,
  RotateCcw,
  Award,
  AlertTriangle,
} from "lucide-react";

import { API_URL, createScan, rescanScan, listScans, ApiError, type ApiScan, type ApiFinding } from "@/lib/api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Screen = "home" | "scanning" | "results" | "badge" | "history";
type Platform = "lovable/supabase" | "bolt" | "replit" | "generic";
type Severity = "critical" | "high" | "medium" | "low";
type ScanStatus = "scanning" | "pass" | "fail";

interface Finding {
  id: string;
  severity: Severity;
  title: string;
  whatItMeans: string;
  whyItMatters: string;
  fixPrompt: string;
  resolved: boolean;
}

interface ScanResult {
  id: string;
  repoUrl: string;
  platform: Platform;
  date: string; // ISO
  status: ScanStatus;
  findings: Finding[];
}

// ---------------------------------------------------------------------------
// Mapping: backend shape (snake_case, id-based status) -> frontend shape
// ---------------------------------------------------------------------------
function mapPlatform(apiPlatform: string): Platform {
  if (apiPlatform === "lovable_supabase") return "lovable/supabase";
  if (apiPlatform === "bolt_v0") return "bolt";
  if (apiPlatform === "replit") return "replit";
  return "generic";
}

function mapFinding(f: ApiFinding): Finding {
  return {
    id: f.id,
    severity: f.severity,
    title: f.label,
    whatItMeans: f.what_it_means,
    whyItMatters: f.why_it_matters,
    fixPrompt: f.fix_prompt,
    resolved: f.status === "resolved",
  };
}

function mapScan(s: ApiScan): ScanResult {
  const findings = s.findings.map(mapFinding);
  const openCriticalHigh = findings.filter(
    (f) => !f.resolved && (f.severity === "critical" || f.severity === "high")
  ).length;
  return {
    id: s.id,
    repoUrl: s.target,
    platform: mapPlatform(s.platform),
    date: s.created_at,
    status: openCriticalHigh === 0 ? "pass" : "fail",
    findings,
  };
}

// ---------------------------------------------------------------------------
// Constants / mock data helpers
// ---------------------------------------------------------------------------
const DEMO_REPO_URL = "https://github.com/vibecode-demo/leaky-todo-app";

const SCAN_STEPS = [
  { id: "clone", label: "Cloning repository..." },
  { id: "checks", label: "Running security checks..." },
  { id: "analyze", label: "Analyzing findings..." },
] as const;

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

let idCounter = 0;
function makeId(): string {
  idCounter += 1;
  return `id-${idCounter}-${Date.now().toString(36)}`;
}

function detectPlatform(url: string): Platform {
  const lower = url.toLowerCase();
  if (lower.includes("supabase") || lower.includes("lovable")) return "lovable/supabase";
  if (lower.includes("bolt.new") || lower.includes("bolt-")) return "bolt";
  if (lower.includes("replit")) return "replit";
  return "generic";
}



function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// Theming helper — explicit tokens instead of Tailwind's `dark:` variant.
// This guarantees the toggle works with zero tailwind.config changes.
// ---------------------------------------------------------------------------
function getTheme(isDark: boolean) {
  return {
    pageBg: isDark ? "bg-slate-950" : "bg-white",
    pageText: isDark ? "text-slate-50" : "text-slate-900",
    headerBorder: isDark ? "border-slate-800" : "border-slate-200",
    headerBg: isDark ? "bg-slate-950/80" : "bg-white/80",
    navLink: isDark ? "text-slate-400 hover:text-slate-100" : "text-slate-500 hover:text-slate-900",
    navLinkActive: isDark ? "text-slate-100" : "text-slate-900",
    ghostBtn: isDark
      ? "border-slate-700 text-slate-300 hover:border-emerald-500/50 hover:text-emerald-400"
      : "border-slate-300 text-slate-700 hover:border-emerald-500/50 hover:text-emerald-600",
    cardBg: isDark ? "border-slate-800 bg-slate-900/60" : "border-slate-200 bg-white",
    cardShadow: isDark ? "shadow-black/40" : "shadow-slate-200/50",
    subText: isDark ? "text-slate-400" : "text-slate-500",
    mutedText: isDark ? "text-slate-500" : "text-slate-400",
    label: isDark ? "text-slate-300" : "text-slate-700",
    inputBg: isDark
      ? "bg-slate-950/70 border-slate-700 text-slate-100 placeholder-slate-600"
      : "bg-white border-slate-300 text-slate-900 placeholder-slate-400",
    heading: isDark ? "text-slate-50" : "text-slate-900",
    codeBg: isDark ? "border-slate-800 bg-slate-950" : "border-slate-200 bg-slate-50",
    codeText: isDark ? "text-slate-300" : "text-slate-700",
    rowBorder: isDark ? "border-slate-800" : "border-slate-100",
    rowHover: isDark ? "hover:bg-slate-800/60" : "hover:bg-slate-50",
    tableBg: isDark ? "bg-slate-900/40" : "bg-white",
    tableHeadBg: isDark ? "bg-slate-900/60" : "bg-slate-50",
  };
}

function severityStyles(sev: Severity, isDark: boolean) {
  const map: Record<Severity, { light: string; dark: string }> = {
    critical: {
      light: "bg-red-100 text-red-700 border-red-300",
      dark: "bg-red-500/10 text-red-400 border-red-500/30",
    },
    high: {
      light: "bg-orange-100 text-orange-700 border-orange-300",
      dark: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    },
    medium: {
      light: "bg-amber-100 text-amber-700 border-amber-300",
      dark: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    },
    low: {
      light: "bg-blue-100 text-blue-700 border-blue-300",
      dark: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    },
  };
  return isDark ? map[sev].dark : map[sev].light;
}

function platformStyles(platform: Platform, isDark: boolean) {
  const map: Record<Platform, { light: string; dark: string }> = {
    "lovable/supabase": {
      light: "bg-emerald-100 text-emerald-700 border-emerald-300",
      dark: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    },
    bolt: {
      light: "bg-yellow-100 text-yellow-700 border-yellow-300",
      dark: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    },
    replit: {
      light: "bg-orange-100 text-orange-700 border-orange-300",
      dark: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    },
    generic: {
      light: "bg-slate-200 text-slate-700 border-slate-300",
      dark: "bg-slate-500/10 text-slate-300 border-slate-500/30",
    },
  };
  return isDark ? map[platform].dark : map[platform].light;
}

// ---------------------------------------------------------------------------
// Small shared UI pieces (top-level, stable identities)
// ---------------------------------------------------------------------------
function PlatformPill({ platform, isDark }: { platform: Platform; isDark: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${platformStyles(
        platform,
        isDark
      )}`}
    >
      {platform}
    </span>
  );
}

function SeverityBadge({ severity, isDark }: { severity: Severity; isDark: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${severityStyles(
        severity,
        isDark
      )}`}
    >
      {severity}
    </span>
  );
}

function StatusPill({ status, isDark }: { status: ScanStatus; isDark: boolean }) {
  if (status === "scanning") {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${
          isDark
            ? "border-slate-700 bg-slate-800 text-slate-300"
            : "border-slate-300 bg-slate-100 text-slate-600"
        }`}
      >
        <Loader2 className="h-3 w-3 animate-spin" /> Scanning
      </span>
    );
  }
  if (status === "pass") {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${
          isDark
            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
            : "border-emerald-300 bg-emerald-100 text-emerald-700"
        }`}
      >
        <CheckCircle2 className="h-3 w-3" /> Pass
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${
        isDark ? "border-red-500/30 bg-red-500/10 text-red-400" : "border-red-300 bg-red-100 text-red-700"
      }`}
    >
      <XCircle className="h-3 w-3" /> Fail
    </span>
  );
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------
function Header({
  isDark,
  toggleTheme,
  isSignedIn,
  toggleSignIn,
  screen,
  goHome,
  goHistory,
  showHistoryLink,
}: {
  isDark: boolean;
  toggleTheme: () => void;
  isSignedIn: boolean;
  toggleSignIn: () => void;
  screen: Screen;
  goHome: () => void;
  goHistory: () => void;
  showHistoryLink: boolean;
}) {
  const t = getTheme(isDark);
  return (
    <header className={`sticky top-0 z-20 border-b backdrop-blur-md ${t.headerBorder} ${t.headerBg}`}>
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <button onClick={goHome} className="flex items-center gap-2" aria-label="Go to home screen">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 ring-1 ring-emerald-400/40">
            <Shield className={`h-4 w-4 ${isDark ? "text-emerald-400" : "text-emerald-500"}`} />
          </div>
          <span className={`text-lg font-semibold tracking-tight ${t.heading}`}>
            Secure<span className={isDark ? "text-emerald-400" : "text-emerald-500"}>-VibeCode</span>
          </span>
        </button>

        <nav className="flex items-center gap-4 text-sm">
          <button
            onClick={goHome}
            className={`hidden sm:inline transition ${screen === "home" ? `font-semibold ${t.navLinkActive}` : t.navLink}`}
          >
            Home
          </button>

          {showHistoryLink && (
            <button
              onClick={goHistory}
              className={`hidden sm:inline transition ${
                screen === "history" ? `font-semibold ${t.navLinkActive}` : t.navLink
              }`}
            >
              Past scans
            </button>
          )}

          <button
            type="button"
            onClick={toggleTheme}
            aria-label="Toggle color theme"
            className={`flex h-9 w-9 items-center justify-center rounded-lg border transition ${t.ghostBtn}`}
          >
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>

          <button
            onClick={toggleSignIn}
            className={`rounded-md border px-3 py-1.5 transition ${t.ghostBtn}`}
          >
            {isSignedIn ? "Sign out" : "Sign in"}
          </button>
        </nav>
      </div>
    </header>
  );
}

// ---------------------------------------------------------------------------
// Screen 1: Home
// ---------------------------------------------------------------------------
function HomeScreen({
  isDark,
  urlInput,
  setUrlInput,
  onScan,
  onDemo,
  showHistoryLink,
  goHistory,
  error,
}: {
  isDark: boolean;
  urlInput: string;
  setUrlInput: (v: string) => void;
  onScan: () => void;
  onDemo: () => void;
  showHistoryLink: boolean;
  goHistory: () => void;
  error?: string | null;
}) {
  const t = getTheme(isDark);
  return (
    <main className="mx-auto max-w-2xl px-6 pb-24 pt-20 text-center">
      <span
        className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${
          isDark ? "border-slate-800 bg-slate-900/60 text-emerald-400" : "border-slate-200 bg-slate-50 text-emerald-600"
        }`}
      >
        <Sparkles className="h-3 w-3" />
        AI-powered vulnerability scanning for vibe-coded apps
      </span>

      <h1 className={`mt-6 text-4xl font-bold tracking-tight sm:text-5xl ${t.heading}`}>
        Ship fast. Stay{" "}
        <span
          className={`bg-clip-text text-transparent bg-gradient-to-r ${
            isDark ? "from-emerald-400 to-cyan-400" : "from-emerald-500 to-cyan-500"
          }`}
        >
          secure.
        </span>
      </h1>
      <p className={`mx-auto mt-4 max-w-lg text-base ${t.subText}`}>
        Paste a repository URL and Secure-VibeCode will scan it for exposed
        secrets, missing access controls, and common logic flaws.
      </p>

      {error && (
        <div
          className={`mx-auto mt-6 flex max-w-md items-start gap-2 rounded-lg border px-4 py-3 text-left text-sm ${
            isDark ? "border-red-500/30 bg-red-500/10 text-red-300" : "border-red-300 bg-red-50 text-red-700"
          }`}
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className={`mt-10 rounded-2xl border p-6 text-left shadow-xl sm:p-8 ${t.cardBg} ${t.cardShadow}`}>
        <label htmlFor="repo-url" className={`mb-2 block text-sm font-medium ${t.label}`}>
          Repository URL
        </label>
        <input
          id="repo-url"
          type="text"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          placeholder="https://github.com/owner/repo"
          className={`w-full rounded-lg border px-4 py-3 text-sm outline-none transition focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/20 ${t.inputBg}`}
        />
        <p className={`mt-2 text-xs ${t.mutedText}`}>
          Works with GitHub repos exported from Lovable, Bolt, Replit, or any
          generic codebase.
        </p>

        <div className="mt-6 flex flex-col gap-3 sm:flex-row">
          <button
            onClick={onScan}
            disabled={!urlInput.trim()}
            className={`flex-1 rounded-lg px-4 py-3 text-sm font-semibold shadow-lg shadow-emerald-500/20 transition disabled:cursor-not-allowed disabled:opacity-50 ${
              isDark ? "bg-emerald-500 text-slate-950 hover:bg-emerald-400" : "bg-emerald-500 text-white hover:bg-emerald-600"
            }`}
          >
            Scan now
          </button>
          <button
            onClick={onDemo}
            className={`flex-1 rounded-lg border px-4 py-3 text-sm font-semibold transition ${t.ghostBtn}`}
          >
            Try a demo repo
          </button>
        </div>

        {showHistoryLink && (
          <button
            onClick={goHistory}
            className={`mt-4 inline-flex items-center gap-1.5 text-sm transition ${
              isDark ? "text-slate-400 hover:text-emerald-400" : "text-slate-500 hover:text-emerald-600"
            }`}
          >
            <History className="h-3.5 w-3.5" />
            Past scans
          </button>
        )}
      </div>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Screen 2: Scanning
// ---------------------------------------------------------------------------
function ScanningScreen({
  isDark,
  activeScan,
  stepIndex,
  progress,
  onCancel,
}: {
  isDark: boolean;
  activeScan: ScanResult | null;
  stepIndex: number;
  progress: number;
  onCancel: () => void;
}) {
  const t = getTheme(isDark);
  return (
    <main className="mx-auto max-w-xl px-6 pb-24 pt-24 text-center">
      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-emerald-500/10 ring-1 ring-emerald-400/30">
        <Loader2 className={`h-7 w-7 animate-spin ${isDark ? "text-emerald-400" : "text-emerald-500"}`} />
      </div>

      <h2 className={`mt-6 text-2xl font-bold ${t.heading}`}>Scanning your repository</h2>
      <p className={`mt-2 truncate text-sm ${t.subText}`}>{activeScan?.repoUrl}</p>

      <div className={`mt-8 rounded-2xl border p-6 text-left shadow-lg ${t.cardBg}`}>
        <div className="space-y-4">
          {SCAN_STEPS.map((step, i) => {
            const state = i < stepIndex ? "done" : i === stepIndex ? "active" : "pending";
            return (
              <div key={step.id} className="flex items-center gap-3">
                {state === "done" && (
                  <CheckCircle2 className={`h-5 w-5 flex-shrink-0 ${isDark ? "text-emerald-400" : "text-emerald-500"}`} />
                )}
                {state === "active" && (
                  <Loader2 className={`h-5 w-5 flex-shrink-0 animate-spin ${isDark ? "text-cyan-400" : "text-cyan-500"}`} />
                )}
                {state === "pending" && (
                  <Circle className={`h-5 w-5 flex-shrink-0 ${isDark ? "text-slate-700" : "text-slate-300"}`} />
                )}
                <span
                  className={`text-sm ${
                    state === "pending" ? t.mutedText : `font-medium ${isDark ? "text-slate-200" : "text-slate-800"}`
                  }`}
                >
                  {step.label}
                </span>
              </div>
            );
          })}
        </div>

        <div className="mt-6">
          <div className={`mb-1.5 flex justify-between text-xs ${t.mutedText}`}>
            <span>Progress</span>
            <span>{progress}%</span>
          </div>
          <div className={`h-2 w-full overflow-hidden rounded-full ${isDark ? "bg-slate-800" : "bg-slate-200"}`}>
            <div
              className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-300 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>

      <button
        onClick={onCancel}
        className={`mt-6 text-sm underline-offset-4 transition hover:underline ${
          isDark ? "text-slate-500 hover:text-red-400" : "text-slate-400 hover:text-red-500"
        }`}
      >
        Cancel scan
      </button>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Finding card (used inside Results)
// ---------------------------------------------------------------------------
function FindingCard({
  isDark,
  finding,
  isExpanded,
  onToggleExpand,
  onCopy,
  copiedKey,
}: {
  isDark: boolean;
  finding: Finding;
  isExpanded: boolean;
  onToggleExpand: () => void;
  onCopy: (text: string, key: string) => void;
  copiedKey: string | null;
}) {
  const t = getTheme(isDark);
  return (
    <div
      className={`rounded-xl border p-4 transition ${
        finding.resolved
          ? isDark
            ? "border-emerald-500/20 bg-emerald-500/5"
            : "border-emerald-200 bg-emerald-50/50"
          : t.cardBg
      }`}
    >
      <button onClick={onToggleExpand} className="flex w-full items-start justify-between gap-3 text-left">
        <div className="flex items-start gap-3">
          <div className="mt-0.5">
            <SeverityBadge severity={finding.severity} isDark={isDark} />
          </div>
          <div>
            <p
              className={`text-sm font-semibold ${isDark ? "text-slate-100" : "text-slate-800"} ${
                finding.resolved ? "line-through decoration-2 opacity-60" : ""
              }`}
            >
              {finding.title}
            </p>
            {finding.resolved && (
              <span
                className={`mt-1 inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                  isDark
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-emerald-300 bg-emerald-100 text-emerald-700"
                }`}
              >
                <Check className="h-3 w-3" /> Resolved
              </span>
            )}
          </div>
        </div>
        {isExpanded ? (
          <ChevronUp className={`h-4 w-4 flex-shrink-0 ${t.mutedText}`} />
        ) : (
          <ChevronDown className={`h-4 w-4 flex-shrink-0 ${t.mutedText}`} />
        )}
      </button>

      {isExpanded && (
        <div className={`mt-4 space-y-4 border-t pt-4 ${t.rowBorder}`}>
          <div>
            <p className={`text-xs font-semibold uppercase tracking-wide ${t.mutedText}`}>What it means</p>
            <p className={`mt-1 text-sm ${isDark ? "text-slate-300" : "text-slate-600"}`}>{finding.whatItMeans}</p>
          </div>
          <div>
            <p className={`text-xs font-semibold uppercase tracking-wide ${t.mutedText}`}>Why it matters</p>
            <p className={`mt-1 text-sm ${isDark ? "text-slate-300" : "text-slate-600"}`}>{finding.whyItMatters}</p>
          </div>
          <div>
            <p className={`mb-1.5 text-xs font-semibold uppercase tracking-wide ${t.mutedText}`}>Fix prompt</p>
            <div className={`relative rounded-lg border p-3 pr-10 ${t.codeBg}`}>
              <code className={`block whitespace-pre-wrap font-mono text-xs ${t.codeText}`}>{finding.fixPrompt}</code>
              <button
                onClick={() => onCopy(finding.fixPrompt, finding.id)}
                aria-label="Copy fix prompt"
                className={`absolute right-2 top-2 rounded-md p-1.5 transition ${
                  isDark ? "text-slate-400 hover:bg-slate-800 hover:text-slate-200" : "text-slate-400 hover:bg-slate-200 hover:text-slate-700"
                }`}
              >
                {copiedKey === finding.id ? (
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Screen 3: Results
// ---------------------------------------------------------------------------
function ResultsScreen({
  isDark,
  activeScan,
  expandedIds,
  copiedKey,
  onToggleExpand,
  onCopy,
  onRescan,
  rescanningId,
  onGetBadge,
  onPastScans,
  goHome,
  error,
}: {
  isDark: boolean;
  activeScan: ScanResult | null;
  expandedIds: Set<string>;
  copiedKey: string | null;
  onToggleExpand: (id: string) => void;
  onCopy: (text: string, key: string) => void;
  onRescan: (scanId: string) => void;
  rescanningId?: string | null;
  onGetBadge: () => void;
  onPastScans: () => void;
  goHome: () => void;
  error?: string | null;
}) {
  const t = getTheme(isDark);

  if (!activeScan) {
    return (
      <main className={`mx-auto max-w-2xl px-6 pt-24 text-center ${t.subText}`}>
        No scan selected.{" "}
        <button onClick={goHome} className={isDark ? "text-emerald-400 underline" : "text-emerald-600 underline"}>
          Start a new scan
        </button>
      </main>
    );
  }

  const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let openCriticalHigh = 0;
  for (const f of activeScan.findings) {
    severityCounts[f.severity] += 1;
    if (!f.resolved && (f.severity === "critical" || f.severity === "high")) openCriticalHigh += 1;
  }
  const canGetBadge = activeScan.status !== "scanning" && openCriticalHigh === 0;

  return (
    <main className="mx-auto max-w-3xl px-6 pb-24 pt-10">
      {/* Target bar */}
      <div className={`flex flex-wrap items-center gap-3 rounded-xl border px-4 py-3 ${t.cardBg}`}>
        <span className={`truncate text-sm font-medium ${isDark ? "text-slate-200" : "text-slate-700"}`}>
          {activeScan.repoUrl}
        </span>
        <PlatformPill platform={activeScan.platform} isDark={isDark} />
        <span className={`text-xs ${t.mutedText}`}>{formatDate(activeScan.date)}</span>
      </div>

      {/* Summary card */}
      <div className={`mt-6 rounded-2xl border p-6 shadow-lg ${t.cardBg}`}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            {activeScan.status === "pass" ? (
              <CheckCircle2 className={`h-8 w-8 ${isDark ? "text-emerald-400" : "text-emerald-500"}`} />
            ) : (
              <XCircle className={`h-8 w-8 ${isDark ? "text-red-400" : "text-red-500"}`} />
            )}
            <div>
              <p className={`text-base font-semibold ${t.heading}`}>
                {activeScan.status === "pass"
                  ? "No blocking issues found"
                  : `${openCriticalHigh} unresolved critical/high issue${openCriticalHigh === 1 ? "" : "s"}`}
              </p>
              <p className={`text-xs ${t.mutedText}`}>
                {activeScan.findings.length} total finding{activeScan.findings.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>

          <button
            onClick={() => onRescan(activeScan.id)}
            disabled={rescanningId === activeScan.id}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60 ${t.ghostBtn}`}
          >
            <RotateCcw className={`h-3.5 w-3.5 ${rescanningId === activeScan.id ? "animate-spin" : ""}`} />
            {rescanningId === activeScan.id ? "Re-scanning..." : "Re-scan"}
          </button>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {SEVERITY_ORDER.map((sev) => (
            <div key={sev} className={`rounded-lg border px-3 py-2 text-center ${severityStyles(sev, isDark)}`}>
              <p className="text-lg font-bold">{severityCounts[sev]}</p>
              <p className="text-[11px] uppercase tracking-wide">{sev}</p>
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div
          className={`mt-6 flex items-start gap-2 rounded-lg border px-4 py-3 text-sm ${
            isDark ? "border-red-500/30 bg-red-500/10 text-red-300" : "border-red-300 bg-red-50 text-red-700"
          }`}
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Findings */}
      <div className="mt-6 space-y-3">
        {activeScan.findings.map((f) => (
          <FindingCard
            key={f.id}
            isDark={isDark}
            finding={f}
            isExpanded={expandedIds.has(f.id)}
            onToggleExpand={() => onToggleExpand(f.id)}
            onCopy={onCopy}
            copiedKey={copiedKey}
          />
        ))}
      </div>

      {activeScan.findings.some((f) => !f.resolved) && (
        <p className={`mt-3 text-center text-xs ${t.mutedText}`}>
          Apply the fix prompts above in your AI coding tool, then click Re-scan to verify.
        </p>
      )}

      {/* Badge gating banner — makes the disabled state obvious instead of "doing nothing" */}
      {!canGetBadge && (
        <div
          className={`mt-6 flex items-start gap-2 rounded-lg border px-4 py-3 text-sm ${
            isDark ? "border-amber-500/30 bg-amber-500/10 text-amber-300" : "border-amber-300 bg-amber-50 text-amber-700"
          }`}
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <span>
            Resolve all {openCriticalHigh} remaining Critical/High finding{openCriticalHigh === 1 ? "" : "s"} to
            unlock the badge.
          </span>
        </div>
      )}

      {/* Actions */}
      <div className="mt-6 flex flex-col gap-3 sm:flex-row">
        <button
          onClick={onGetBadge}
          disabled={!canGetBadge}
          className={`flex-1 inline-flex items-center justify-center gap-2 rounded-lg px-4 py-3 text-sm font-semibold shadow-lg shadow-emerald-500/20 transition disabled:cursor-not-allowed disabled:opacity-40 ${
            isDark ? "bg-emerald-500 text-slate-950 hover:bg-emerald-400" : "bg-emerald-500 text-white hover:bg-emerald-600"
          }`}
        >
          <Award className="h-4 w-4" />
          Get badge
        </button>
        <button
          onClick={onPastScans}
          className={`flex-1 rounded-lg border px-4 py-3 text-sm font-semibold transition ${t.ghostBtn}`}
        >
          Past scans
        </button>
      </div>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Screen 4: Badge & Share
// ---------------------------------------------------------------------------
function BadgeScreen({
  isDark,
  activeScan,
  copiedKey,
  onCopy,
  onDone,
}: {
  isDark: boolean;
  activeScan: ScanResult | null;
  copiedKey: string | null;
  onCopy: (text: string, key: string) => void;
  onDone: () => void;
}) {
  const t = getTheme(isDark);
  if (!activeScan) return null;

  const shareLink = `${API_URL}/badge/${activeScan.id}.svg`;
  const embedCode = `<img src="${shareLink}" alt="Secure-VibeCode Verified" />`;

  return (
    <main className="mx-auto max-w-lg px-6 pb-24 pt-16 text-center">
      <div
        className={`mx-auto flex flex-col items-center rounded-2xl border p-8 shadow-xl ${
          isDark
            ? "border-emerald-500/30 bg-gradient-to-b from-emerald-500/10 to-slate-900"
            : "border-emerald-300 bg-gradient-to-b from-emerald-50 to-white"
        }`}
      >
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500 shadow-lg shadow-emerald-500/30">
          <ShieldCheck className="h-8 w-8 text-white" />
        </div>
        <p className={`mt-4 text-lg font-bold ${t.heading}`}>Secure-VibeCode Verified</p>
        <p className={`mt-1 truncate text-xs ${t.subText}`}>{activeScan.repoUrl}</p>
        <p className={`mt-1 text-[11px] ${t.mutedText}`}>Verified {formatDate(activeScan.date)}</p>
      </div>

      <div className="mt-6 space-y-4 text-left">
        <div>
          <label className={`mb-1.5 block text-xs font-semibold uppercase tracking-wide ${t.mutedText}`}>
            Shareable link
          </label>
          <div className="flex items-center gap-2">
            <input
              readOnly
              value={shareLink}
              className={`flex-1 truncate rounded-lg border px-3 py-2 text-xs ${
                isDark ? "border-slate-700 bg-slate-950 text-slate-300" : "border-slate-300 bg-slate-50 text-slate-600"
              }`}
            />
            <button
              onClick={() => onCopy(shareLink, "link")}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition ${t.ghostBtn}`}
            >
              {copiedKey === "link" ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
              Copy link
            </button>
          </div>
        </div>

        <div>
          <label className={`mb-1.5 block text-xs font-semibold uppercase tracking-wide ${t.mutedText}`}>
            Embed code
          </label>
          <div className="flex items-center gap-2">
            <input
              readOnly
              value={embedCode}
              className={`flex-1 truncate rounded-lg border px-3 py-2 font-mono text-xs ${
                isDark ? "border-slate-700 bg-slate-950 text-slate-300" : "border-slate-300 bg-slate-50 text-slate-600"
              }`}
            />
            <button
              onClick={() => onCopy(embedCode, "embed")}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition ${t.ghostBtn}`}
            >
              {copiedKey === "embed" ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
              Copy embed code
            </button>
          </div>
        </div>
      </div>

      <button
        onClick={onDone}
        className={`mt-8 inline-flex items-center gap-1.5 rounded-lg px-5 py-2.5 text-sm font-semibold transition ${
          isDark ? "bg-emerald-500 text-slate-950 hover:bg-emerald-400" : "bg-slate-900 text-white hover:bg-slate-800"
        }`}
      >
        <X className="h-4 w-4" />
        Done
      </button>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Screen 5: History
// ---------------------------------------------------------------------------
function HistoryScreen({
  isDark,
  scans,
  onOpenScan,
  onNewScan,
  onBack,
}: {
  isDark: boolean;
  scans: ScanResult[];
  onOpenScan: (id: string) => void;
  onNewScan: () => void;
  onBack: () => void;
}) {
  const t = getTheme(isDark);
  return (
    <main className="relative mx-auto max-w-3xl px-6 pb-32 pt-10">
      <div className="mb-6 flex items-center gap-3">
        <button
          onClick={onBack}
          className={`rounded-lg border p-2 transition ${t.ghostBtn}`}
          aria-label="Back"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <h2 className={`text-xl font-bold ${t.heading}`}>Scan History</h2>
      </div>

      {scans.length === 0 ? (
        <div
          className={`rounded-xl border border-dashed p-10 text-center text-sm ${
            isDark ? "border-slate-700 text-slate-500" : "border-slate-300 text-slate-400"
          }`}
        >
          No scans yet. Run your first scan to see it here.
        </div>
      ) : (
        <div className={`overflow-hidden rounded-xl border ${isDark ? "border-slate-800" : "border-slate-200"}`}>
          <table className="w-full text-left text-sm">
            <thead className={`text-xs uppercase tracking-wide ${t.mutedText} ${t.tableHeadBg}`}>
              <tr>
                <th className="px-4 py-3 font-medium">Target repo</th>
                <th className="px-4 py-3 font-medium">Date</th>
                <th className="px-4 py-3 font-medium">Platform</th>
                <th className="px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr
                  key={s.id}
                  onClick={() => onOpenScan(s.id)}
                  className={`cursor-pointer border-t transition ${t.rowBorder} ${t.tableBg} ${t.rowHover}`}
                >
                  <td className={`max-w-[220px] truncate px-4 py-3 font-medium ${isDark ? "text-slate-200" : "text-slate-700"}`}>
                    {s.repoUrl}
                  </td>
                  <td className={`px-4 py-3 ${t.mutedText}`}>{formatDate(s.date)}</td>
                  <td className="px-4 py-3">
                    <PlatformPill platform={s.platform} isDark={isDark} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={s.status} isDark={isDark} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <button
        onClick={onNewScan}
        className={`fixed bottom-8 right-8 inline-flex items-center gap-2 rounded-full px-5 py-3 text-sm font-semibold shadow-xl shadow-emerald-500/30 transition ${
          isDark ? "bg-emerald-500 text-slate-950 hover:bg-emerald-400" : "bg-emerald-500 text-white hover:bg-emerald-600"
        }`}
      >
        <Sparkles className="h-4 w-4" />
        New scan
      </button>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Main app — owns all state, renders top-level screen components with props
// ---------------------------------------------------------------------------
export default function SecureVibeCodeApp() {
  const [isDark, setIsDark] = useState(true);
  const [isSignedIn, setIsSignedIn] = useState(false);
  const [screen, setScreen] = useState<Screen>("home");
  const [urlInput, setUrlInput] = useState("");
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [stepIndex, setStepIndex] = useState(0);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [rescanningId, setRescanningId] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const activeScan = scans.find((s) => s.id === activeScanId) || null;

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      abortRef.current?.abort();
    };
  }, []);

  // Restore past scans for a returning visitor (matched by their owner token).
  useEffect(() => {
    const controller = new AbortController();
    listScans(controller.signal)
      .then((apiScans) => {
        const past = apiScans.filter((s) => s.status === "completed").map(mapScan);
        setScans((prev) => {
          const known = new Set(prev.map((s) => s.id));
          return [...prev, ...past.filter((s) => !known.has(s.id))];
        });
      })
      .catch(() => {});
    return () => controller.abort();
  }, []);

  // Drives the decorative step/progress animation shown *while* the real
  // request is in flight. It never reaches 100% on its own -- only the
  // actual API response (success or failure) ends the scanning screen --
  // so it stays honest instead of promising a fake completion time.
  function startProgressAnimation() {
    if (intervalRef.current) clearInterval(intervalRef.current);
    let current = 0;
    setProgress(0);
    setStepIndex(0);
    intervalRef.current = setInterval(() => {
      current = Math.min(current + Math.floor(Math.random() * 8) + 4, 92);
      setProgress(current);
      setStepIndex(current < 34 ? 0 : current < 67 ? 1 : 2);
    }, 500);
  }

  function stopProgressAnimation() {
    if (intervalRef.current) clearInterval(intervalRef.current);
  }

  async function startScan(url: string) {
    const trimmed = url.trim();
    if (!trimmed) return;

    setScanError(null);
    const controller = new AbortController();
    abortRef.current = controller;

    const placeholderId = makeId();
    const placeholder: ScanResult = {
      id: placeholderId,
      repoUrl: trimmed,
      platform: detectPlatform(trimmed),
      date: new Date().toISOString(),
      status: "scanning",
      findings: [],
    };
    setScans((prev) => [placeholder, ...prev]);
    setActiveScanId(placeholderId);
    setExpandedIds(new Set());
    setScreen("scanning");
    startProgressAnimation();

    try {
      const apiScan = await createScan(trimmed, controller.signal);
      const mapped = mapScan(apiScan);
      // Swap the placeholder for the real scan (real id, real findings).
      setScans((prev) => prev.map((s) => (s.id === placeholderId ? mapped : s)));
      setActiveScanId(mapped.id);
      stopProgressAnimation();
      setProgress(100);
      setStepIndex(2);
      setScreen("results");
    } catch (err) {
      if (controller.signal.aborted) return; // user cancelled -- see cancelScan
      stopProgressAnimation();
      setScans((prev) => prev.filter((s) => s.id !== placeholderId));
      setActiveScanId(null);
      setScanError(err instanceof ApiError ? err.message : "Scan failed. Check the URL and try again.");
      setScreen("home");
    }
  }

  async function rescanCurrent(scanId: string) {
    if (rescanningId) return; // ignore repeat clicks while one is already in flight
    setScanError(null);
    setRescanningId(scanId);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const apiScan = await rescanScan(scanId, controller.signal);
      const mapped = mapScan(apiScan);
      setScans((prev) => prev.map((s) => (s.id === scanId ? mapped : s)));
    } catch (err) {
      if (controller.signal.aborted) return;
      setScanError(err instanceof ApiError ? err.message : "Re-scan failed. Please try again.");
    } finally {
      setRescanningId((prev) => (prev === scanId ? null : prev));
    }
  }

  function cancelScan() {
    abortRef.current?.abort();
    stopProgressAnimation();
    setScans((prev) => prev.filter((s) => s.id !== activeScanId));
    setActiveScanId(null);
    setScreen("home");
  }

  function toggleExpanded(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function copyToClipboard(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1500);
    } catch {
      // clipboard unavailable — fail silently
    }
  }

  function goHome() {
    setUrlInput("");
    setScreen("home");
  }

  const showHistoryLink = isSignedIn || scans.length > 0;

  return (
    <div className={isDark ? "bg-slate-950" : "bg-white"}>
      <div className={`min-h-screen transition-colors duration-300 ${isDark ? "bg-slate-950 text-slate-50" : "bg-white text-slate-900"}`}>
        <Header
          isDark={isDark}
          toggleTheme={() => setIsDark((d) => !d)}
          isSignedIn={isSignedIn}
          toggleSignIn={() => setIsSignedIn((v) => !v)}
          screen={screen}
          goHome={goHome}
          goHistory={() => setScreen("history")}
          showHistoryLink={showHistoryLink}
        />

        {screen === "home" && (
          <HomeScreen
            isDark={isDark}
            urlInput={urlInput}
            setUrlInput={setUrlInput}
            onScan={() => startScan(urlInput)}
            onDemo={() => setUrlInput(DEMO_REPO_URL)}
            showHistoryLink={showHistoryLink}
            goHistory={() => setScreen("history")}
            error={scanError}
          />
        )}

        {screen === "scanning" && (
          <ScanningScreen
            isDark={isDark}
            activeScan={activeScan}
            stepIndex={stepIndex}
            progress={progress}
            onCancel={cancelScan}
          />
        )}

        {screen === "results" && (
          <ResultsScreen
            isDark={isDark}
            activeScan={activeScan}
            expandedIds={expandedIds}
            copiedKey={copiedKey}
            onToggleExpand={toggleExpanded}
            onCopy={copyToClipboard}
            onRescan={rescanCurrent}
            rescanningId={rescanningId}
            onGetBadge={() => setScreen("badge")}
            onPastScans={() => setScreen("history")}
            goHome={goHome}
            error={scanError}
          />
        )}

        {screen === "badge" && (
          <BadgeScreen
            isDark={isDark}
            activeScan={activeScan}
            copiedKey={copiedKey}
            onCopy={copyToClipboard}
            onDone={() => setScreen("results")}
          />
        )}

        {screen === "history" && (
          <HistoryScreen
            isDark={isDark}
            scans={scans}
            onOpenScan={(id) => {
              setActiveScanId(id);
              setScreen("results");
            }}
            onNewScan={goHome}
            onBack={goHome}
          />
        )}
      </div>
    </div>
  );
}
