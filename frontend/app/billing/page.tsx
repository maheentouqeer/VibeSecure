'use client';

import React, { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import {
  Check,
  ShieldCheck,
  ArrowUpRight,
  BarChart3,
  Loader2,
  AlertCircle,
  Sparkles,
  X
} from 'lucide-react';
import { ApiError, ApiMeResponse, createCheckout, getMe } from '@/lib/api';

export default function BillingPage() {
  const [isCheckoutOpen, setIsCheckoutOpen] = useState(false);
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [checkoutError, setCheckoutError] = useState<string | null>(null);

  const [meData, setMeData] = useState<ApiMeResponse | null>(null);
  const [meLoading, setMeLoading] = useState(true);
  const [meError, setMeError] = useState<string | null>(null);

  const loadMe = useCallback(async () => {
    setMeLoading(true);
    setMeError(null);
    try {
      const data = await getMe();
      setMeData(data);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setMeError('You must be signed in to view billing information.');
        } else {
          setMeError(err.message);
        }
      } else {
        setMeError('Failed to load account information.');
      }
    } finally {
      setMeLoading(false);
    }
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadMe();
  }, [loadMe]);

  const planName = meData?.plan ?? 'free';
  const isPro = planName === 'pro';
  const monthlyScanLimit = meData?.limits.monthly_scans ?? 50;
  const scansUsed = meData?.usage.scans_this_month ?? 0;
  const scanPercent = monthlyScanLimit > 0 ? Math.min(100, Math.round((scansUsed / monthlyScanLimit) * 100)) : 0;

  const handleOpenCheckout = () => {
    setCheckoutError(null);
    setIsCheckoutOpen(true);
  };

  const handleStartCheckout = async () => {
    setCheckoutLoading(true);
    setCheckoutError(null);
    try {
      const { url } = await createCheckout('pro');
      window.location.href = url;
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setCheckoutError('Please sign in before upgrading.');
        } else if (err.status === 409) {
          setCheckoutError('You already have an active Pro subscription.');
        } else if (err.status === 503) {
          setCheckoutError('Billing is not configured on this server yet.');
        } else {
          setCheckoutError(err.message);
        }
      } else {
        setCheckoutError('Something went wrong. Please try again.');
      }
      setCheckoutLoading(false);
    }
  };

  if (meLoading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-500" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 p-6 md:p-10 transition-colors">
      <div className="max-w-6xl mx-auto space-y-8">

        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900/10 dark:border-white/10 pb-6">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Billing &amp; Subscriptions</h1>
            <p className="text-slate-600 dark:text-slate-400 mt-1">
              Manage your plan tier and usage allocations.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <Link
              href="/settings"
              className="px-4 py-2 glass-button rounded-lg text-sm font-medium hover:bg-white/10 transition-colors shadow-none"
            >
              Account Settings
            </Link>
          </div>
        </div>

        {meError && (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-lg border border-red-300 bg-red-50 px-3.5 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{meError}</span>
          </div>
        )}

        {/* Current Active Status & Usage Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

          {/* Active Plan Card */}
          <div className="md:col-span-1 glass-panel p-6 flex flex-col justify-between shadow-none">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-slate-500 font-semibold">Current Plan</span>
                <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  Active
                </span>
              </div>
              <h2 className="text-2xl font-bold mt-3">{isPro ? 'Pro' : 'Free'} Tier</h2>
              <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                {isPro
                  ? 'Unlimited scans, AI fixes, and priority support.'
                  : 'For individual developers building personal projects and prototypes.'}
              </p>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-3xl font-extrabold">{isPro ? '$29' : '$0'}</span>
                <span className="text-xs text-slate-500 dark:text-slate-400"> / month</span>
              </div>
              {!isPro && (
                <button
                  onClick={handleOpenCheckout}
                  className="px-4 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg transition-colors flex items-center gap-1.5 shadow-none"
                >
                  Upgrade <ArrowUpRight className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Usage Stats Meter */}
          <div className="md:col-span-2 glass-panel p-6 space-y-6 shadow-none">
            <h3 className="text-lg font-semibold border-b border-slate-900/10 dark:border-white/10 pb-3">
              Monthly Resource Usage
            </h3>

            <div className="space-y-4">
              {/* Code Scans Progress */}
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="font-medium flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-emerald-500" /> Code Scans
                  </span>
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                    {scansUsed} / {isPro ? '∞' : monthlyScanLimit} Scans
                  </span>
                </div>
                <div className="w-full h-2.5 bg-white/5 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 rounded-full transition-all duration-300"
                    style={{ width: isPro ? '5%' : `${scanPercent}%` }}
                  />
                </div>
              </div>

              {/* Auto-Rescan */}
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium">Auto-rescan</span>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${meData?.limits.auto_rescan ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-white/5 text-slate-500 dark:text-slate-400'}`}>
                  {meData?.limits.auto_rescan ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* 2-Tier Subscription Cards (Free vs Pro) */}
        <div className="space-y-6 pt-4">
          <div>
            <h2 className="text-2xl font-bold">Subscription Plans</h2>
            <p className="text-sm text-slate-600 dark:text-slate-400">
              Select a tier to scale your repository security and compliance automation.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-2">

            {/* Free Tier Card */}
            <div className="glass-panel p-8 flex flex-col justify-between shadow-none relative hover:border-slate-300 dark:hover:border-slate-700 transition-all">
              <div>
                <div className="flex justify-between items-center">
                  <h3 className="text-xl font-bold">Free Tier</h3>
                  <span className="text-xs bg-white/5 text-slate-600 dark:text-slate-400 px-2.5 py-1 rounded-full font-medium">
                    Hobby
                  </span>
                </div>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-2">
                  For individuals building personal projects and testing security features.
                </p>

                <div className="my-6">
                  <span className="text-4xl font-extrabold">$0</span>
                  <span className="text-sm text-slate-500 dark:text-slate-400"> / month</span>
                </div>

                <div className="space-y-3 pt-2">
                  <p className="text-xs uppercase tracking-wider font-semibold text-slate-400">Included Features:</p>
                  <ul className="space-y-2.5 text-sm text-slate-700 dark:text-slate-300">
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Up to 50 security scans per month
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Standard vulnerability assessment
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Community support access
                    </li>
                  </ul>
                </div>
              </div>

              <button
                disabled={!isPro}
                className={`mt-8 w-full py-2.5 font-medium text-sm rounded-xl border ${
                  !isPro
                    ? 'bg-white/5 text-slate-400 dark:text-slate-500 cursor-not-allowed border-slate-200 dark:border-slate-700/50'
                    : 'bg-white/5 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors'
                }`}
              >
                {!isPro ? 'Current Plan' : 'Downgrade'}
              </button>
            </div>

            {/* Pro Tier Card (Highlighted) */}
            <div className="p-8 rounded-2xl border-2 border-emerald-500 bg-white/5 flex flex-col justify-between shadow-md relative hover:shadow-xl transition-all">
              <span className="absolute -top-3.5 right-6 bg-gradient-to-r from-emerald-600 to-teal-600 text-white text-[11px] uppercase tracking-wider font-bold px-3 py-0.5 rounded-full shadow-none flex items-center gap-1">
                <Sparkles className="h-3 w-3" /> Recommended
              </span>

              <div>
                <div className="flex justify-between items-center">
                  <h3 className="text-xl font-bold">Pro Tier</h3>
                  <span className="text-xs bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 px-2.5 py-1 rounded-full font-semibold border border-emerald-500/20">
                    Pro
                  </span>
                </div>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-2">
                  For engineering teams requiring real-time scanning, compliance models, and AI fixes.
                </p>

                <div className="my-6">
                  <span className="text-4xl font-extrabold">$29</span>
                  <span className="text-sm text-slate-500 dark:text-slate-400"> / month</span>
                </div>

                <div className="space-y-3 pt-2">
                  <p className="text-xs uppercase tracking-wider font-semibold text-emerald-600 dark:text-emerald-400">Everything in Free, plus:</p>
                  <ul className="space-y-2.5 text-sm text-slate-700 dark:text-slate-300">
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Unlimited code and container scans
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Automated AI Data Masking &amp; Fix generation
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Custom Webhook &amp; CI/CD Pipeline integration
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Priority 24/7 technical support
                    </li>
                  </ul>
                </div>
              </div>

              {isPro ? (
                <button
                  disabled
                  className="mt-8 w-full py-2.5 bg-white/5 text-slate-400 dark:text-slate-500 font-medium text-sm rounded-xl cursor-not-allowed border border-slate-200 dark:border-slate-700/50"
                >
                  Current Plan
                </button>
              ) : (
                <button
                  onClick={handleOpenCheckout}
                  className="mt-8 w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 text-white font-semibold text-sm rounded-xl transition-all shadow-md shadow-emerald-500/10 flex items-center justify-center gap-2"
                >
                  Get Pro Access <ArrowUpRight className="h-4 w-4" />
                </button>
              )}
            </div>

          </div>
        </div>

      </div>

      {/* Whop Checkout Modal */}
      {isCheckoutOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
          <div className="glass-panel rounded-2xl w-full max-w-lg p-6 shadow-2xl relative">
            <button
              onClick={() => { setIsCheckoutOpen(false); setCheckoutError(null); }}
              className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-white/10 rounded-lg transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-6 w-6 text-emerald-500" />
                <h3 className="text-xl font-bold">Upgrade to Pro</h3>
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                You are subscribing to the <strong className="text-slate-900 dark:text-white">Pro Plan</strong> ($29/month).
                You will be redirected to our payment provider to complete the purchase.
              </p>

              {checkoutError && (
                <div
                  role="alert"
                  className="flex items-start gap-2 rounded-lg border border-red-300 bg-red-50 px-3.5 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
                >
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{checkoutError}</span>
                </div>
              )}

              <button
                onClick={handleStartCheckout}
                disabled={checkoutLoading}
                className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-sm rounded-xl transition-all shadow-md shadow-emerald-500/10 flex items-center justify-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {checkoutLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Redirecting to checkout…
                  </>
                ) : (
                  <>
                    Continue to Payment <ArrowUpRight className="h-4 w-4" />
                  </>
                )}
              </button>

              <button
                onClick={() => { setIsCheckoutOpen(false); setCheckoutError(null); }}
                className="w-full py-2.5 bg-white/5 text-slate-600 dark:text-slate-300 font-medium text-sm rounded-xl hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}