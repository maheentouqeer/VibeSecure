// app/forgot-password/page.tsx
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useTheme } from "next-themes";
import {
  Shield,
  Sun,
  Moon,
  Mail,
  AlertCircle,
  Loader2,
  CheckCircle2,
  Circle,
  MailCheck,
  ArrowLeft,
} from "lucide-react";
import { supabase } from "@/lib/supabase";

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMounted(true);
  }, []);
  const isDark = mounted && resolvedTheme === "dark";

  return (
    <button
      type="button"
      onClick={() => setTheme(isDark ? "light" : "dark")}
      aria-label="Toggle color theme"
      className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-300 text-slate-700 transition hover:border-emerald-500/50 hover:text-emerald-600 dark:border-slate-700 dark:text-slate-300 dark:hover:border-emerald-500/50 dark:hover:text-emerald-400"
    >
      {mounted && isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

const PREVIEW_CHECKS = [
  { label: "Scanning for exposed secrets", delay: 0 },
  { label: "Checking row-level security policies", delay: 1400 },
  { label: "Auditing auth redirect rules", delay: 2800 },
] as const;

function LiveCheckPreview() {
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const timers: ReturnType<typeof setTimeout>[] = [];

    function runCycle() {
      setActiveIndex(0);
      PREVIEW_CHECKS.forEach((check, i) => {
        timers.push(
          setTimeout(() => {
            if (!cancelled) setActiveIndex(i + 1);
          }, check.delay + 1200)
        );
      });
      timers.push(setTimeout(() => !cancelled && runCycle(), 5600));
    }

    runCycle();
    return () => {
      cancelled = true;
      timers.forEach(clearTimeout);
    };
  }, []);

  return (
    <div className="space-y-3 rounded-xl border border-white/10 bg-black/20 p-5 backdrop-blur-sm">
      {PREVIEW_CHECKS.map((check, i) => {
        const state = i < activeIndex ? "done" : i === activeIndex ? "active" : "pending";
        return (
          <div key={check.label} className="flex items-center gap-3">
            {state === "done" && <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />}
            {state === "active" && <Loader2 className="h-4 w-4 shrink-0 animate-spin text-cyan-400" />}
            {state === "pending" && <Circle className="h-4 w-4 shrink-0 text-white/20" />}
            <span className={cx("text-sm", state === "pending" ? "text-white/40" : "text-white/90")}>
              {check.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function isValidEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [emailError, setEmailError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [submittedEmail, setSubmittedEmail] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);

    if (!email.trim()) {
      setEmailError("Enter your email address.");
      return;
    }
    if (!isValidEmail(email)) {
      setEmailError("Enter a valid email address.");
      return;
    }
    setEmailError(null);
    setIsLoading(true);

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/login`,
    });

    setIsLoading(false);

    if (error) {
      setFormError(error.message);
    } else {
      setSubmittedEmail(email);
    }
  }

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950">
      <div className="grid min-h-screen lg:grid-cols-2">
        <div className="relative flex flex-col px-6 py-8 sm:px-12 sm:py-10">
          <div className="flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 ring-1 ring-emerald-400/40">
                <Shield className="h-4 w-4 text-emerald-500 dark:text-emerald-400" />
              </div>
              <span className="text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-50">
                Vibe<span className="text-emerald-500 dark:text-emerald-400">Secure</span>
              </span>
            </Link>
            <ThemeToggle />
          </div>

          <div className="flex flex-1 items-center justify-center py-10">
            <div className="w-full max-w-sm">
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-50">
                Reset your password
              </h1>
              <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">
                Enter the email tied to your account and we&apos;ll send you a link.
              </p>

              <div className="mt-8">
                {submittedEmail ? (
                  <div className="rounded-xl border border-emerald-300 bg-emerald-50 p-5 text-center dark:border-emerald-500/30 dark:bg-emerald-500/10">
                    <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full bg-emerald-500/15">
                      <MailCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    </div>
                    <p className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-50">Check your inbox</p>
                    <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                      We sent a password reset link to <span className="font-medium">{submittedEmail}</span>. It
                      expires in 15 minutes.
                    </p>
                    <button
                      type="button"
                      onClick={() => setSubmittedEmail(null)}
                      className="mt-4 text-sm font-medium text-emerald-600 hover:underline dark:text-emerald-400"
                    >
                      Use a different email
                    </button>
                  </div>
                ) : (
                  <div className="space-y-5">
                    {formError && (
                      <div
                        role="alert"
                        className="flex items-start gap-2 rounded-lg border border-red-300 bg-red-50 px-3.5 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
                      >
                        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                        <span>{formError}</span>
                      </div>
                    )}

                    <form onSubmit={handleSubmit} noValidate className="space-y-4">
                      <div>
                        <label htmlFor="reset-email" className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
                          Email
                        </label>
                        <div className="relative">
                          <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-600" />
                          <input
                            id="reset-email"
                            type="email"
                            autoComplete="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            aria-invalid={!!emailError}
                            aria-describedby={emailError ? "reset-email-error" : undefined}
                            placeholder="you@company.com"
                            className={cx(
                              "w-full rounded-lg border bg-white py-3 pl-10 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400",
                              "focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/20",
                              "dark:bg-slate-950/70 dark:text-slate-100 dark:placeholder:text-slate-600",
                              emailError
                                ? "border-red-400 focus:border-red-500 focus:ring-red-500/20 dark:border-red-500/60"
                                : "border-slate-300 dark:border-slate-700"
                            )}
                          />
                        </div>
                        {emailError && (
                          <p id="reset-email-error" className="mt-1.5 text-xs text-red-500 dark:text-red-400">
                            {emailError}
                          </p>
                        )}
                      </div>

                      <button
                        type="submit"
                        disabled={isLoading}
                        className={cx(
                          "flex w-full items-center justify-center gap-2 rounded-lg px-4 py-3 text-sm font-semibold shadow-lg shadow-emerald-500/20 transition",
                          "bg-emerald-500 text-white hover:bg-emerald-600 dark:text-slate-950 dark:hover:bg-emerald-400",
                          isLoading && "cursor-not-allowed opacity-70"
                        )}
                      >
                        {isLoading && <Loader2 className="h-4 w-4 animate-spin" />}
                        {isLoading ? "Sending link..." : "Send reset link"}
                      </button>
                    </form>
                  </div>
                )}
              </div>

              <p className="mt-6 text-center text-sm text-slate-500 dark:text-slate-400">
                <Link
                  href="/login"
                  className="inline-flex items-center gap-1.5 font-medium text-emerald-600 hover:underline dark:text-emerald-400"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  Back to sign in
                </Link>
              </p>
            </div>
          </div>
        </div>

        <div className="relative hidden overflow-hidden bg-slate-950 lg:flex lg:flex-col lg:justify-between lg:p-12">
          <div
            className="absolute inset-0 opacity-40"
            style={{
              backgroundImage:
                "linear-gradient(rgba(255,255,255,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.06) 1px, transparent 1px)",
              backgroundSize: "40px 40px",
            }}
          />
          <div className="absolute -right-32 -top-32 h-96 w-96 rounded-full bg-emerald-500/20 blur-[120px]" />
          <div className="absolute -bottom-32 -left-16 h-96 w-96 rounded-full bg-cyan-500/10 blur-[120px]" />

          <div className="relative">
            <p className="max-w-md text-3xl font-semibold leading-tight tracking-tight text-white">
              Ship fast. Know exactly what&apos;s exposed before anyone else finds it.
            </p>
          </div>

          <div className="relative mt-10 max-w-md">
            <LiveCheckPreview />
            <p className="mt-4 text-xs text-white/40">Live preview — findings vary by repository.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
