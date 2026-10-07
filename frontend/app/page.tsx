"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState, type ReactNode, type CSSProperties } from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Clipboard,
  Code2,
  History,
  Loader2,
  LockKeyhole,
  Network,
  RefreshCw,
  ScanSearch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  X,
  XCircle,
  Zap,
  type LucideIcon,
} from "lucide-react";

import {
  ApiError,
  createScan,
  getSecurityContext,
  listScans,
  rescanScan,
  type ApiScan,
  type AttackPath,
  type FraudRiskFinding,
  type HardeningItem,
  type SecurityContext,
} from "@/lib/api";

type Screen = "home" | "scanning" | "results" | "history";

const DEMO_REPO_URL = "https://github.com/maheentouqeer/test-vibesecure";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function bandClass(band: string) {
  if (band === "critical") return "risk-critical";
  if (band === "high") return "risk-high";
  if (band === "medium") return "risk-medium";
  return "risk-low";
}

function severityClass(severity: string) {
  if (severity === "critical") return "severity-critical";
  if (severity === "high") return "severity-high";
  if (severity === "medium") return "severity-medium";
  return "severity-low";
}

function scoreLabel(score: number) {
  return String(Math.max(0, Math.min(100, Math.round(score)))).padStart(2, "0");
}

function RiskBadge({ band }: { band: string }) {
  return (
    <span className={"inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.16em] " + bandClass(band)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {band} risk
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={"inline-flex items-center rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.15em] " + severityClass(severity)}>
      {severity}
    </span>
  );
}

function StatCard({
  eyebrow,
  value,
  label,
  icon,
}: {
  eyebrow: string;
  value: string;
  label: string;
  icon: ReactNode;
}) {
  return (
    <div className="glass-panel p-4">
      <div className="flex items-center justify-between">
        <span className="mono-label">{eyebrow}</span>
        <span className="icon-chip">{icon}</span>
      </div>
      <div className="mt-4 text-2xl font-semibold tracking-tight">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{label}</div>
    </div>
  );
}

function HomeScreen({
  value,
  onChange,
  onScan,
  onDemo,
  error,
}: {
  value: string;
  onChange: (value: string) => void;
  onScan: () => void;
  onDemo: () => void;
  error: string | null;
}) {
  return (
    <div className="mx-auto max-w-6xl px-5 pb-20 pt-8 md:px-8 md:pt-12">
      <section className="relative overflow-hidden rounded-[28px] border border-emerald-400/15 bg-slate-950/45 px-6 py-10 shadow-[0_30px_100px_rgba(0,0,0,0.26)] md:px-12 md:py-14">
        <div className="absolute inset-0 security-grid opacity-50" />
        <div className="absolute -right-28 -top-24 h-72 w-72 rounded-full bg-cyan-400/10 blur-3xl" />
        <div className="absolute -left-24 bottom-0 h-72 w-72 rounded-full bg-emerald-400/10 blur-3xl" />

        <div className="relative max-w-4xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/5 px-3 py-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-emerald-300">
            <ShieldCheck className="h-3.5 w-3.5" />
            VibeSecure 2.0 · ForgeHacks build
          </div>

          <h1 className="mt-6 max-w-4xl text-4xl font-semibold tracking-[-0.04em] text-white md:text-6xl">
            Security for the
            <span className="text-gradient"> AI-native software era.</span>
          </h1>

          <p className="mt-5 max-w-2xl text-sm leading-7 text-slate-400 md:text-base">
            VibeSecure does more than list vulnerabilities. It turns scanner evidence into an
            understandable attack path, explains the fraud or impersonation impact, generates a fix,
            and lets you re-scan to verify the path is closed.
          </p>

          <div className="mt-8 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
            {([
              { step: "01", label: "SCAN", Icon: ScanSearch },
              { step: "02", label: "ATTACK PATH", Icon: Network },
              { step: "03", label: "FRAUD IMPACT", Icon: ShieldAlert },
              { step: "04", label: "FIX", Icon: Zap },
              { step: "05", label: "VERIFY", Icon: ShieldCheck },
            ] as { step: string; label: string; Icon: LucideIcon }[]).map(({ step, label, Icon }) => (
              <div key={label} className="workflow-step">
                <span>{step}</span>
                <Icon className="h-3.5 w-3.5" />
                <strong>{label}</strong>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mt-6 grid gap-6 lg:grid-cols-[1.35fr_0.65fr]">
        <div className="glass-panel p-5 md:p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="mono-label">START A SECURITY REVIEW</div>
              <h2 className="mt-2 text-xl font-semibold tracking-tight text-white">Scan a repository</h2>
            </div>
            <div className="hidden rounded-full border border-white/10 px-3 py-1 text-[10px] font-semibold text-slate-500 md:block">
              GitHub · public repos
            </div>
          </div>

          <label htmlFor="repo-url" className="mt-5 block text-xs font-semibold uppercase tracking-[0.13em] text-slate-400">
            Repository URL
          </label>
          <div className="mt-2 flex flex-col gap-3 md:flex-row">
            <input
              id="repo-url"
              value={value}
              onChange={(event) => onChange(event.target.value)}
              placeholder="https://github.com/owner/repository"
              className="glass-input min-w-0 flex-1 rounded-xl px-4 py-3.5 text-sm text-white outline-none transition focus:border-emerald-400/50"
            />
            <button
              onClick={onScan}
              disabled={!value.trim()}
              className="primary-action"
            >
              <ScanSearch className="h-4 w-4" />
              Start scan
            </button>
          </div>

          {error && (
            <div className="mt-4 flex items-start gap-2 rounded-xl border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="mt-5 flex flex-wrap items-center gap-3 text-xs text-slate-500">
            <button onClick={onDemo} className="secondary-action">
              <Terminal className="h-3.5 w-3.5" />
              Try demo repository
            </button>
            <span>Source code is scanned by VibeSecure; only masked finding context is sent to Gemini when configured.</span>
          </div>
        </div>

        <div className="glass-panel p-5 md:p-6">
          <div className="mono-label">WHY THIS IS DIFFERENT</div>
          <div className="mt-4 space-y-3">
            {[
              ["Finding", "Missing authorization"],
              ["Attack path", "Attacker → victim data → account action"],
              ["Fraud impact", "Impersonation / transaction abuse"],
              ["Verification", "Re-scan → path closed"],
            ].map(([key, value]) => (
              <div key={key} className="rounded-xl border border-white/8 bg-white/[0.025] p-3.5">
                <div className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-500">{key}</div>
                <div className="mt-1.5 text-sm font-medium text-slate-200">{value}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard eyebrow="ENGINE" value="Scanner + reasoning" label="Deterministic evidence first" icon={<Code2 className="h-4 w-4" />} />
        <StatCard eyebrow="IMPACT" value="Attack paths" label="Fraud and impersonation context" icon={<Network className="h-4 w-4" />} />
        <StatCard eyebrow="HARDEN" value="15 controls" label="Automated + explicit not-checked states" icon={<LockKeyhole className="h-4 w-4" />} />
        <StatCard eyebrow="VERIFY" value="Re-scan loop" label="Fix → scan again → verify" icon={<RefreshCw className="h-4 w-4" />} />
      </section>
    </div>
  );
}

function ScanningScreen({ target, progress, onCancel }: { target: string; progress: number; onCancel: () => void }) {
  const stages = [
    ["SCANNING REPOSITORY", "Cloning target and identifying platform"],
    ["SECURITY SIGNALS", "Secrets, code rules, CORS and RLS checks"],
    ["IMPACT REASONING", "Turning findings into attack paths"],
    ["FRAUD RISK", "Estimating abuse and impersonation impact"],
    ["RESULTS READY", "Fix prompts and verification state"],
  ];

  const activeIndex = Math.min(4, Math.max(0, Math.floor(progress / 20)));

  return (
    <div className="mx-auto max-w-5xl px-5 pb-20 pt-10 md:px-8 md:pt-14">
      <section className="glass-panel overflow-hidden p-6 md:p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="mono-label">LIVE SECURITY PIPELINE</div>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white md:text-3xl">Building your security graph</h1>
            <p className="mt-2 max-w-2xl truncate text-sm text-slate-500">{target}</p>
          </div>
          <div className="scan-orb"><Loader2 className="h-6 w-6 animate-spin text-emerald-300" /></div>
        </div>

        <div className="mt-9 grid gap-3 md:grid-cols-5">
          {stages.map(([title, desc], index) => {
            const done = index < activeIndex;
            const active = index === activeIndex;
            return (
              <div key={title} className={"stage-card " + (done ? "stage-done" : "") + (active ? " stage-active" : "")}>
                <div className="flex items-center gap-2">
                  {done ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : active ? <Loader2 className="h-4 w-4 animate-spin text-cyan-300" /> : <span className="stage-index">{index + 1}</span>}
                  <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-300">{title}</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">{desc}</p>
              </div>
            );
          })}
        </div>

        <div className="mt-8">
          <div className="flex items-center justify-between text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">
            <span>Progress</span>
            <span>{Math.round(progress)}%</span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/5">
            <div className="scan-progress h-full rounded-full" style={{ width: progress + "%" }} />
          </div>
        </div>

        <button onClick={onCancel} className="mt-7 inline-flex items-center gap-2 text-xs font-semibold text-slate-500 transition hover:text-red-300">
          <X className="h-3.5 w-3.5" /> Cancel
        </button>
      </section>
    </div>
  );
}

function AttackPathVisual({ path }: { path: AttackPath | null }) {
  if (!path) {
    return (
      <div className="rounded-2xl border border-white/8 bg-white/[0.02] p-8 text-center">
        <ShieldCheck className="mx-auto h-8 w-8 text-emerald-300" />
        <p className="mt-3 text-sm font-semibold text-slate-200">No attack path generated</p>
        <p className="mt-1 text-xs text-slate-500">The scan found no evidence-backed path to visualize.</p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.02] p-4 md:p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="mono-label">ATTACK IMPACT GRAPH</div>
          <h3 className="mt-2 text-base font-semibold text-white">{path.title}</h3>
        </div>
        <div className="flex items-center gap-2">
          <RiskBadge band={path.risk_band} />
          <span className="rounded-full border border-white/10 px-2.5 py-1 text-[10px] font-bold text-slate-400">
            {Math.round(path.confidence * 100)}% confidence
          </span>
        </div>
      </div>

      <div className="mt-6 space-y-2">
        {path.steps.map((step, index) => (
          <div key={step + index}>
            <div className="graph-node">
              <div className="graph-dot">{index + 1}</div>
              <div className="min-w-0">
                <div className="text-sm font-medium text-slate-200">{step}</div>
                <div className="mt-0.5 text-[10px] uppercase tracking-[0.13em] text-slate-600">
                  {index === 0 ? "Evidence" : index === path.steps.length - 1 ? "Potential impact" : "Attack transition"}
                </div>
              </div>
            </div>
            {index < path.steps.length - 1 && (
              <div className="ml-5 flex h-6 items-center">
                <ArrowDown className="h-3.5 w-3.5 text-emerald-400/50" />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function RiskSummary({
  context,
}: {
  context: SecurityContext;
}) {
  const top = context.fraud_findings[0];
  return (
    <div className="glass-panel p-5 md:p-6">
      <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-4">
          <div className={"score-ring " + bandClass(context.overall_risk_band)} style={{ "--risk-progress": Math.max(0, Math.min(100, context.overall_risk_score)) + "%" } as CSSProperties}>
            <div className="score-ring-inner">
              <span className="text-2xl font-semibold text-white">{scoreLabel(context.overall_risk_score)}</span>
              <span className="text-[9px] uppercase tracking-[0.16em] text-slate-500">risk</span>
            </div>
          </div>
          <div>
            <div className="mono-label">FRAUD / SCAM RISK</div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <h2 className="text-xl font-semibold tracking-tight text-white">{context.overall_risk_band.toUpperCase()}</h2>
              <RiskBadge band={context.overall_risk_band} />
            </div>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
              {top ? top.fraud_category + ". " + top.business_impact : "No evidence-backed fraud impact is currently associated with this scan."}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 md:w-[270px]">
          <div className="mini-stat">
            <span>Findings</span>
            <strong>{context.finding_count}</strong>
          </div>
          <div className="mini-stat">
            <span>High / critical</span>
            <strong>{context.open_high_critical}</strong>
          </div>
          <div className="mini-stat">
            <span>Controls</span>
            <strong>{context.hardening.checked}/{context.hardening.total}</strong>
          </div>
          <div className="mini-stat">
            <span>Verify</span>
            <strong>{context.verification.passed ? "PASS" : "OPEN"}</strong>
          </div>
        </div>
      </div>
    </div>
  );
}

function FraudImpactCard({ item }: { item: FraudRiskFinding | null }) {
  if (!item) {
    return (
      <section className="glass-panel p-5 md:p-6">
        <div className="mono-label">FRAUD IMPACT ANALYZER</div>
        <p className="mt-4 text-sm text-slate-400">No finding requires fraud impact analysis.</p>
      </section>
    );
  }

  return (
    <section className="glass-panel p-5 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="mono-label">FRAUD IMPACT ANALYZER</div>
          <h2 className="mt-2 text-lg font-semibold text-white">{item.fraud_category}</h2>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={item.severity} />
          <span className="rounded-full border border-emerald-400/15 bg-emerald-400/5 px-2.5 py-1 text-[10px] font-semibold text-emerald-300">
            inferred · {Math.round(item.confidence * 100)}%
          </span>
        </div>
      </div>

      <div className="mt-5 grid gap-3 md:grid-cols-3">
        <div className="impact-box">
          <span>Attacker can try</span>
          <p>{item.attacker_action}</p>
        </div>
        <div className="impact-box">
          <span>Victim impact</span>
          <p>{item.victim_impact}</p>
        </div>
        <div className="impact-box">
          <span>Business / fraud impact</span>
          <p>{item.business_impact}</p>
        </div>
      </div>

      <div className="mt-4 flex items-start gap-2 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.03] px-3.5 py-3 text-xs leading-5 text-slate-400">
        <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-300" />
        Impact is a conservative scenario inferred from scanner evidence. VibeSecure does not claim exploitation unless a separate dynamic test proves it.
      </div>
    </section>
  );
}

function HardeningPanel({ items }: { items: HardeningItem[] }) {
  return (
    <section className="glass-panel p-5 md:p-6">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="mono-label">SECURITY HARDENING</div>
          <h2 className="mt-2 text-lg font-semibold text-white">Control coverage</h2>
        </div>
        <div className="text-xs text-slate-500">Automated: {items.filter((item) => item.automated).length} · Not checked: {items.filter((item) => item.status === "not_checked").length}</div>
      </div>

      <div className="mt-5 grid gap-2 sm:grid-cols-2">
        {items.map((item) => {
          const state = item.status === "attention" ? "attention" : item.status === "no_finding" ? "clear" : "unchecked";
          return (
            <div key={item.id} className="hardening-row">
              <div className={"hardening-icon hardening-" + state}>
                {state === "attention" ? <TriangleAlert className="h-3.5 w-3.5" /> : state === "clear" ? <Check className="h-3.5 w-3.5" /> : <span>—</span>}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-slate-200">{item.title}</span>
                  {item.automated && <span className="text-[9px] font-bold uppercase tracking-[0.14em] text-slate-600">auto</span>}
                </div>
                <p className="mt-0.5 text-[11px] leading-5 text-slate-500">{item.description}</p>
              </div>
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-600">
                {state === "attention" ? "attention" : state === "clear" ? "no finding" : "not checked"}
              </span>
            </div>
          );
        })}
      </div>

      <p className="mt-4 text-[11px] leading-5 text-slate-600">{'No finding is not proof of security. ' + items.length + ' controls are shown so gaps stay visible instead of being hidden behind a single score.'}</p>
    </section>
  );
}

function FindingList({
  scan,
  context,
  expanded,
  onToggle,
  onCopy,
  copied,
}: {
  scan: ApiScan;
  context: SecurityContext;
  expanded: string | null;
  onToggle: (id: string) => void;
  onCopy: (text: string) => void;
  copied: boolean;
}) {
  const riskById = useMemo(
    () => new Map(context.fraud_findings.map((item) => [item.finding_id, item])),
    [context.fraud_findings]
  );

  return (
    <section className="glass-panel overflow-hidden">
      <div className="border-b border-white/8 px-5 py-4 md:px-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="mono-label">SECURITY FINDINGS</div>
            <h2 className="mt-2 text-lg font-semibold text-white">{scan.findings.length} findings, ranked by evidence</h2>
          </div>
          <span className="hidden text-xs text-slate-500 md:block">Tap a finding to inspect impact + fix</span>
        </div>
      </div>

      {scan.findings.length === 0 ? (
        <div className="px-5 py-12 text-center">
          <ShieldCheck className="mx-auto h-10 w-10 text-emerald-300" />
          <h3 className="mt-3 text-base font-semibold text-white">No findings detected</h3>
          <p className="mt-1 text-sm text-slate-500">The current scanner suite did not produce an evidence-backed finding.</p>
        </div>
      ) : (
        <div className="divide-y divide-white/6">
          {scan.findings.map((finding) => {
            const open = expanded === finding.id;
            const risk = riskById.get(finding.id);
            return (
              <div key={finding.id} className={finding.status === "resolved" ? "finding-row finding-resolved" : "finding-row"}>
                <button onClick={() => onToggle(finding.id)} className="w-full px-5 py-4 text-left md:px-6">
                  <div className="flex items-start gap-3">
                    <div className="pt-0.5"><SeverityBadge severity={finding.severity} /></div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-slate-200">{finding.label}</span>
                        {finding.status === "resolved" && (
                          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-400/20 bg-emerald-400/5 px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.14em] text-emerald-300">
                            <Check className="h-3 w-3" /> resolved
                          </span>
                        )}
                        {risk && <span className="text-[10px] font-semibold text-slate-600">fraud {scoreLabel(risk.risk_score)}</span>}
                      </div>
                      <p className="mt-1 text-xs text-slate-500">{finding.file || "runtime / repository"}</p>
                    </div>
                    {open ? <ArrowDown className="h-4 w-4 rotate-180 text-slate-600" /> : <ArrowRight className="h-4 w-4 text-slate-600" />}
                  </div>
                </button>

                {open && risk && (
                  <div className="border-t border-white/6 bg-white/[0.015] px-5 pb-5 pt-4 md:px-6">
                    <div className="grid gap-3 md:grid-cols-2">
                      <div className="detail-box">
                        <span>What it means</span>
                        <p>{finding.what_it_means}</p>
                      </div>
                      <div className="detail-box">
                        <span>Why it matters</span>
                        <p>{finding.why_it_matters}</p>
                      </div>
                    </div>

                    <div className="mt-3">
                      <div className="mono-label">ATTACK PATH</div>
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        {risk.attack_path.map((step, index) => (
                          <div key={step + index} className="flex items-center gap-1.5">
                            <span className="rounded-lg border border-white/8 bg-white/[0.025] px-2.5 py-2 text-[11px] text-slate-300">{step}</span>
                            {index < risk.attack_path.length - 1 && <ArrowRight className="h-3 w-3 text-emerald-400/50" />}
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="mt-4 rounded-xl border border-emerald-400/10 bg-emerald-400/[0.025] p-3.5">
                      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                        <div className="min-w-0 flex-1">
                          <div className="mono-label">RECOMMENDED FIX</div>
                          <code className="mt-2 block whitespace-pre-wrap text-xs leading-6 text-slate-300">{risk.recommended_fix}</code>
                        </div>
                        <button onClick={() => onCopy(risk.recommended_fix)} className="secondary-action shrink-0">
                          {copied ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Clipboard className="h-3.5 w-3.5" />}
                          {copied ? "Copied" : "Copy fix"}
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {open && !risk && (
                  <div className="border-t border-white/6 px-5 pb-5 pt-4 text-sm text-slate-500 md:px-6">
                    Impact analysis is not available for this finding.
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function ResultsScreen({
  scan,
  context,
  onRescan,
  onCopy,
  copied,
  onBack,
  rescanBusy,
  onHistory,
}: {
  scan: ApiScan;
  context: SecurityContext;
  onRescan: () => void;
  onCopy: (text: string) => void;
  copied: boolean;
  onBack: () => void;
  rescanBusy: boolean;
  onHistory: () => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const topFinding = context.fraud_findings[0] || null;
  const topPath = context.attack_paths[0] || null;

  return (
    <div className="mx-auto max-w-6xl px-5 pb-20 pt-8 md:px-8 md:pt-10">
      <div className="flex flex-col gap-4 border-b border-white/7 pb-6 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <button onClick={onBack} className="mb-4 inline-flex items-center gap-2 text-xs font-semibold text-slate-500 hover:text-emerald-300">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to scan
          </button>
          <div className="mono-label">SECURITY REVIEW</div>
          <h1 className="mt-2 truncate text-2xl font-semibold tracking-tight text-white md:text-3xl">{scan.target}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="rounded-full border border-white/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.13em] text-slate-500">{scan.platform || "generic"}</span>
            <span className="text-[11px] text-slate-600">{formatDate(scan.created_at)}</span>
            <span className="text-[11px] text-slate-600">{scan.status}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={onHistory} className="secondary-action"><History className="h-3.5 w-3.5" /> Past scans</button>
          <Link href="/mcp" className="secondary-action"><Terminal className="h-3.5 w-3.5" /> MCP</Link>
          <button onClick={onRescan} disabled={rescanBusy} className="primary-action">
            {rescanBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            {rescanBusy ? "Verifying..." : "Re-scan & verify"}
          </button>
        </div>
      </div>

      <div className="mt-6 space-y-5">
        <RiskSummary context={context} />

        <div className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
          <AttackPathVisual path={topPath} />
          <FraudImpactCard item={topFinding} />
        </div>

        <div className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
          <HardeningPanel items={context.hardening.items} />
          <section className="glass-panel p-5 md:p-6">
            <div className="mono-label">FIX → VERIFY</div>
            <h2 className="mt-2 text-lg font-semibold text-white">
              {context.verification.passed ? "Security path is clear" : "High-impact paths remain open"}
            </h2>
            <div className={"mt-4 rounded-2xl border p-4 " + (context.verification.passed ? "border-emerald-400/15 bg-emerald-400/[0.04]" : "border-red-400/15 bg-red-400/[0.04]")}>
              <div className="flex items-center gap-3">
                {context.verification.passed ? <CheckCircle2 className="h-7 w-7 text-emerald-300" /> : <XCircle className="h-7 w-7 text-red-300" />}
                <div>
                  <div className="text-sm font-semibold text-slate-200">{context.verification.passed ? "VERIFIED" : "ACTION REQUIRED"}</div>
                  <div className="mt-1 text-xs leading-5 text-slate-500">{context.verification.label}</div>
                </div>
              </div>
            </div>
            <div className="mt-4 space-y-2">
              <div className="timeline-item"><span>1</span><p>Review the evidence and attack path.</p></div>
              <div className="timeline-item"><span>2</span><p>Copy the generated remediation prompt into your AI editor.</p></div>
              <div className="timeline-item"><span>3</span><p>Run VibeSecure again. Resolved finding signatures are marked closed.</p></div>
            </div>
          </section>
        </div>

        <FindingList
          scan={scan}
          context={context}
          expanded={expanded}
          onToggle={(id) => setExpanded(expanded === id ? null : id)}
          onCopy={onCopy}
          copied={copied}
        />

        <section className="glass-panel p-4">
          <div className="flex items-start gap-3">
            <Shield className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
            <p className="text-[11px] leading-5 text-slate-600">
              Method: {context.methodology} VibeSecure keeps deterministic scanner evidence as the source of truth and uses AI only for grounded explanations/fix wording when configured.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}

function HistoryScreen({
  scans,
  loading,
  onSelect,
  onHome,
}: {
  scans: ApiScan[];
  loading: boolean;
  onSelect: (scan: ApiScan) => void;
  onHome: () => void;
}) {
  return (
    <div className="mx-auto max-w-5xl px-5 pb-20 pt-8 md:px-8 md:pt-12">
      <div className="flex items-end justify-between gap-4 border-b border-white/7 pb-5">
        <div>
          <div className="mono-label">SCAN HISTORY</div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white">Past security reviews</h1>
        </div>
        <button onClick={onHome} className="secondary-action"><ScanSearch className="h-3.5 w-3.5" /> New scan</button>
      </div>

      {loading ? (
        <div className="glass-panel mt-6 p-10 text-center text-sm text-slate-500"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
      ) : scans.length === 0 ? (
        <div className="glass-panel mt-6 p-10 text-center">
          <History className="mx-auto h-8 w-8 text-slate-600" />
          <p className="mt-3 text-sm font-semibold text-slate-300">No scans yet</p>
          <p className="mt-1 text-xs text-slate-500">Your first security review will appear here.</p>
        </div>
      ) : (
        <div className="mt-6 space-y-2">
          {scans.map((scan) => {
            const openHigh = scan.findings.filter((item) => item.status === "open" && (item.severity === "critical" || item.severity === "high")).length;
            const passed = scan.status === "completed" && openHigh === 0;
            return (
              <button key={scan.id} onClick={() => onSelect(scan)} className="history-row">
                <div className="flex min-w-0 items-center gap-3">
                  <div className={"h-2 w-2 rounded-full " + (passed ? "bg-emerald-300" : "bg-red-300")} />
                  <div className="min-w-0 text-left">
                    <div className="truncate text-sm font-medium text-slate-200">{scan.target}</div>
                    <div className="mt-1 text-[11px] text-slate-600">{scan.platform || "generic"} · {formatDate(scan.created_at)}</div>
                  </div>
                </div>
                <div className="hidden items-center gap-3 sm:flex">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.13em] text-slate-600">{scan.findings.length} findings</span>
                  <span className={"text-[10px] font-semibold uppercase tracking-[0.13em] " + (passed ? "text-emerald-300" : "text-red-300")}>{passed ? "verified" : openHigh + " high+"}</span>
                  <ArrowRight className="h-4 w-4 text-slate-700" />
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function Home() {
  const [screen, setScreen] = useState<Screen>("home");
  const [urlInput, setUrlInput] = useState("");
  const [activeScan, setActiveScan] = useState<ApiScan | null>(null);
  const [securityContext, setSecurityContext] = useState<SecurityContext | null>(null);
  const [history, setHistory] = useState<ApiScan[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [progress, setProgress] = useState(6);
  const [error, setError] = useState<string | null>(null);
  const [rescanBusy, setRescanBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (screen !== "scanning") return;
    const timer = window.setInterval(() => {
      setProgress((current) => (current >= 92 ? current : current + 7));
    }, 1100);
    return () => window.clearInterval(timer);
  }, [screen]);

  async function loadContext(scan: ApiScan, signal?: AbortSignal) {
    const context = await getSecurityContext(scan.id, signal);
    setSecurityContext(context);
  }

  async function startScan(target = urlInput) {
    const normalized = target.trim();
    if (!normalized) return;

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setError(null);
    setActiveScan(null);
    setSecurityContext(null);
    setProgress(8);
    setScreen("scanning");

    try {
      const scan = await createScan(normalized, controller.signal);
      if (controller.signal.aborted) return;
      setProgress(100);
      setActiveScan(scan);
      await loadContext(scan, controller.signal);
      setScreen("results");
    } catch (err) {
      if (controller.signal.aborted) return;
      setScreen("home");
      setError(err instanceof ApiError ? err.message : "The scan could not be completed.");
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
    }
  }

  function cancelScan() {
    abortRef.current?.abort();
    abortRef.current = null;
    setScreen("home");
    setProgress(0);
  }

  async function openHistory() {
    setError(null);
    setHistoryLoading(true);
    try {
      setHistory(await listScans());
      setScreen("history");
    } catch {
      setHistory([]);
      setError("Could not load scan history.");
    } finally {
      setHistoryLoading(false);
    }
  }

  async function selectHistoryScan(scan: ApiScan) {
    setError(null);
    try {
      setActiveScan(scan);
      await loadContext(scan);
      setScreen("results");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load this scan.");
    }
  }

  async function verifyAgain() {
    if (!activeScan || rescanBusy) return;
    setRescanBusy(true);
    setError(null);
    try {
      const scan = await rescanScan(activeScan.id);
      setActiveScan(scan);
      await loadContext(scan);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "The re-scan could not be completed.");
    } finally {
      setRescanBusy(false);
    }
  }

  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      setError("Clipboard access was blocked. Copy the fix manually.");
    }
  }

  return (
    <div className="app-shell min-h-screen">
      {screen === "home" && (
        <HomeScreen
          value={urlInput}
          onChange={setUrlInput}
          onScan={() => void startScan()}
          onDemo={() => {
            setUrlInput(DEMO_REPO_URL);
            void startScan(DEMO_REPO_URL);
          }}
          error={error}
        />
      )}

      {screen === "scanning" && activeScan === null && (
        <ScanningScreen
          target={urlInput}
          progress={progress}
          onCancel={cancelScan}
        />
      )}

      {screen === "results" && activeScan && securityContext && (
        <ResultsScreen
          scan={activeScan}
          context={securityContext}
          onRescan={() => void verifyAgain()}
          onCopy={(text) => void copyText(text)}
          copied={copied}
          onBack={() => setScreen("home")}
          rescanBusy={rescanBusy}
          onHistory={() => void openHistory()}
        />
      )}

      {screen === "history" && (
        <HistoryScreen
          scans={history}
          loading={historyLoading}
          onSelect={(scan) => void selectHistoryScan(scan)}
          onHome={() => setScreen("home")}
        />
      )}

      {screen === "home" && error && (
        <div className="pointer-events-none fixed bottom-5 right-5 z-50 max-w-sm">
          <div className="pointer-events-auto flex items-start gap-2 rounded-xl border border-red-400/15 bg-slate-950/90 px-4 py-3 text-xs text-red-200 shadow-2xl backdrop-blur-xl">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>{error}</span>
          </div>
        </div>
      )}
    </div>
  );
}
