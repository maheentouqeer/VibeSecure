// app/login/page.tsx
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import {
  Shield,
  Sun,
  Moon,
  Mail,
  Lock,
  Eye,
  EyeOff,
  AlertCircle,
  Loader2,
  CheckCircle2,
  Circle,
} from "lucide-react";
import { supabase } from "@/lib/supabase";
import { claimScans } from "@/lib/api";

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function GitHubIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M12 .5C5.73.5.75 5.48.75 11.75c0 5.02 3.26 9.28 7.78 10.78.57.1.78-.25.78-.55 0-.27-.01-1.17-.02-2.12-3.17.69-3.84-1.34-3.84-1.34-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.25 3.33.95.1-.74.4-1.25.73-1.54-2.53-.29-5.19-1.27-5.19-5.63 0-1.24.44-2.26 1.17-3.05-.12-.29-.51-1.45.11-3.02 0 0 .96-.31 3.15 1.16a10.9 10.9 0 0 1 5.73 0c2.18-1.47 3.14-1.16 3.14-1.16.63 1.57.23 2.73.12 3.02.73.79 1.17 1.81 1.17 3.05 0 4.37-2.67 5.33-5.21 5.62.41.36.77 1.06.77 2.14 0 1.55-.01 2.79-.01 3.17 0 .3.21.66.79.55A11.26 11.26 0 0 0 23.25 11.75C23.25 5.48 18.27.5 12 .5Z" />
    </svg>
  );
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

function PasswordInput({
  id,
  value,
  onChange,
  error,
  autoComplete,
}: {
  id: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error?: string;
  autoComplete?: string;
}) {
  const [visible, setVisible] = useState(false);

  return (
    <div>
      <div className="relative">
        <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-600" />
        <input
          id={id}
          type={visible ? "text" : "password"}
          value={value}
          onChange={onChange}
          autoComplete={autoComplete}
          aria-invalid={!!error}
          aria-describedby={error ? `${id}-error` : undefined}
          className={cx(
            "w-full rounded-lg border bg-white py-3 pl-10 pr-11 text-sm text-slate-900 outline-none transition placeholder:text-slate-400",
            "focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/20",
            "dark:bg-slate-950/70 dark:text-slate-100 dark:placeholder:text-slate-600",
            error
              ? "border-red-400 focus:border-red-500 focus:ring-red-500/20 dark:border-red-500/60"
              : "border-slate-300 dark:border-slate-700"
          )}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? "Hide password" : "Show password"}
          aria-pressed={visible}
          className="absolute right-2 top-1/2 flex h-7 w-7 -translate-y-1/2 items-center justify-center rounded-md text-slate-400 transition hover:bg-slate-100 hover:text-slate-600 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-300"
        >
          {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
      {error && (
        <p id={`${id}-error`} className="mt-1.5 text-xs text-red-500 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}

function GitHubButton({ isLoading, onClick }: { isLoading: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={isLoading}
      className={cx(
        "flex w-full items-center justify-center gap-2.5 rounded-lg border px-4 py-3 text-sm font-semibold transition",
        "border-slate-300 bg-white text-slate-800 hover:bg-slate-50",
        "dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800",
        isLoading && "cursor-not-allowed opacity-60"
      )}
    >
      {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitHubIcon className="h-4 w-4" />}
      Continue with GitHub
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

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isGitHubLoading, setIsGitHubLoading] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  function validate() {
    const errors: { email?: string; password?: string } = {};
    if (!email.trim()) errors.email = "Enter your email address.";
    else if (!isValidEmail(email)) errors.email = "Enter a valid email address.";
    if (!password) errors.password = "Enter your password.";
    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    if (!validate()) return;

    setIsLoading(true);

    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      setFormError(error.message);
      setIsLoading(false);
      return;
    }

    try {
      await claimScans();
    } catch {
      // Ignore claim errors if backend is in anonymous-only mode
    }

    setIsLoading(false);
    router.push("/");
  }

  async function handleGitHubLogin() {
    setIsGitHubLoading(true);
    setFormError(null);
    const { error } = await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo: `${window.location.origin}/`,
      },
    });
    if (error) {
      setFormError(error.message);
      setIsGitHubLoading(false);
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
                Welcome back
              </h1>
              <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">
                Sign in to see your latest scan results.
              </p>

              <div className="mt-8 space-y-5">
                {formError && (
                  <div
                    role="alert"
                    className="flex items-start gap-2 rounded-lg border border-red-300 bg-red-50 px-3.5 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
                  >
                    <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{formError}</span>
                  </div>
                )}

                <GitHubButton isLoading={isGitHubLoading} onClick={handleGitHubLogin} />

                <div className="flex items-center gap-3">
                  <div className="h-px flex-1 bg-slate-200 dark:bg-slate-800" />
                  <span className="text-xs text-slate-400 dark:text-slate-600">or</span>
                  <div className="h-px flex-1 bg-slate-200 dark:bg-slate-800" />
                </div>

                <form onSubmit={handleSubmit} noValidate className="space-y-4">
                  <div>
                    <label htmlFor="login-email" className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
                      Email
                    </label>
                    <div className="relative">
                      <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-600" />
                      <input
                        id="login-email"
                        type="email"
                        autoComplete="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        aria-invalid={!!fieldErrors.email}
                        aria-describedby={fieldErrors.email ? "login-email-error" : undefined}
                        placeholder="you@company.com"
                        className={cx(
                          "w-full rounded-lg border bg-white py-3 pl-10 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400",
                          "focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/20",
                          "dark:bg-slate-950/70 dark:text-slate-100 dark:placeholder:text-slate-600",
                          fieldErrors.email
                            ? "border-red-400 focus:border-red-500 focus:ring-red-500/20 dark:border-red-500/60"
                            : "border-slate-300 dark:border-slate-700"
                        )}
                      />
                    </div>
                    {fieldErrors.email && (
                      <p id="login-email-error" className="mt-1.5 text-xs text-red-500 dark:text-red-400">
                        {fieldErrors.email}
                      </p>
                    )}
                  </div>

                  <div>
                    <div className="mb-1.5 flex items-center justify-between">
                      <label htmlFor="login-password" className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                        Password
                      </label>
                      <Link
                        href="/forgot-password"
                        className="text-xs font-medium text-emerald-600 hover:underline dark:text-emerald-400"
                      >
                        Forgot password?
                      </Link>
                    </div>
                    <PasswordInput
                      id="login-password"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      error={fieldErrors.password}
                    />
                  </div>

                  <div className="flex items-center gap-2.5">
                    <input
                      id="remember-me"
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="h-4 w-4 rounded border-slate-300 text-emerald-600 focus:ring-emerald-500/40 dark:border-slate-700 dark:bg-slate-900"
                    />
                    <label htmlFor="remember-me" className="text-sm text-slate-600 dark:text-slate-400">
                      Remember me
                    </label>
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
                    {isLoading ? "Signing in..." : "Sign in"}
                  </button>
                </form>
              </div>

              <p className="mt-6 text-center text-sm text-slate-500 dark:text-slate-400">
                Don&apos;t have an account?{" "}
                <Link href="/signup" className="font-medium text-emerald-600 hover:underline dark:text-emerald-400">
                  Sign up
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
