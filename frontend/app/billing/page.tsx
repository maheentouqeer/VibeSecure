'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  Check, 
  Download, 
  ShieldCheck, 
  ArrowUpRight, 
  BarChart3, 
  Users, 
  Key, 
  ExternalLink,
  Sparkles,
  X
} from 'lucide-react';

export default function BillingPage() {
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'yearly'>('monthly');
  const [isCheckoutOpen, setIsCheckoutOpen] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState<string>('Pro');

  const handleOpenCheckout = (planName: string) => {
    setSelectedPlan(planName);
    setIsCheckoutOpen(true);
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 p-6 md:p-10 transition-colors">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-6">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Billing & Subscriptions</h1>
            <p className="text-slate-600 dark:text-slate-400 mt-1">
              Manage your plan tier, usage allocations, and invoices.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <Link
              href="/settings"
              className="px-4 py-2 border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 rounded-lg text-sm font-medium hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shadow-sm"
            >
              Account Settings
            </Link>
          </div>
        </div>

        {/* Current Active Status & Usage Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          {/* Active Plan Card */}
          <div className="md:col-span-1 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col justify-between shadow-sm">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-slate-500 font-semibold">Current Plan</span>
                <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  Active
                </span>
              </div>
              <h2 className="text-2xl font-bold mt-3">Free Tier</h2>
              <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                For individual developers building personal projects and prototypes.
              </p>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-3xl font-extrabold">$0</span>
                <span className="text-xs text-slate-500 dark:text-slate-400"> / month</span>
              </div>
              <button 
                onClick={() => handleOpenCheckout('Pro')}
                className="px-4 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg transition-colors flex items-center gap-1.5 shadow-sm"
              >
                Upgrade <ArrowUpRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Usage Stats Meter */}
          <div className="md:col-span-2 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-6 shadow-sm">
            <h3 className="text-lg font-semibold border-b border-slate-200 dark:border-slate-800 pb-3">
              Monthly Resource Usage
            </h3>

            <div className="space-y-4">
              {/* Code Scans Progress */}
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="font-medium flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-emerald-500" /> Code Scans
                  </span>
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">42 / 50 Scans</span>
                </div>
                <div className="w-full h-2.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-emerald-500 rounded-full transition-all duration-300" style={{ width: '84%' }}></div>
                </div>
              </div>

              {/* Team Seats */}
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="font-medium flex items-center gap-2">
                    <Users className="h-4 w-4 text-cyan-500" /> Team Seats
                  </span>
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">1 / 1 Seat</span>
                </div>
                <div className="w-full h-2.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-cyan-500 rounded-full transition-all duration-300" style={{ width: '100%' }}></div>
                </div>
              </div>

              {/* API Keys */}
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="font-medium flex items-center gap-2">
                    <Key className="h-4 w-4 text-purple-500" /> API Keys Created
                  </span>
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">2 / 3 Keys</span>
                </div>
                <div className="w-full h-2.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-purple-500 rounded-full transition-all duration-300" style={{ width: '66%' }}></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* 2-Tier Subscription Cards (Free vs Pro) */}
        <div className="space-y-6 pt-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h2 className="text-2xl font-bold">Subscription Plans</h2>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                Select a tier to scale your repository security and compliance automation.
              </p>
            </div>

            {/* Monthly / Yearly Toggle */}
            <div className="flex items-center bg-slate-200/60 dark:bg-slate-800/80 p-1 rounded-xl w-fit self-start md:self-auto border border-slate-300/40 dark:border-slate-700/50">
              <button
                onClick={() => setBillingCycle('monthly')}
                className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                  billingCycle === 'monthly'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Monthly
              </button>
              <button
                onClick={() => setBillingCycle('yearly')}
                className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all flex items-center gap-1.5 ${
                  billingCycle === 'yearly'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Yearly <span className="text-[10px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 px-1.5 py-0.5 rounded font-bold border border-emerald-500/20">20% OFF</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-2">
            
            {/* Free Tier Card */}
            <div className="p-8 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col justify-between shadow-sm relative hover:border-slate-300 dark:hover:border-slate-700 transition-all">
              <div>
                <div className="flex justify-between items-center">
                  <h3 className="text-xl font-bold">Free Tier</h3>
                  <span className="text-xs bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-2.5 py-1 rounded-full font-medium">
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
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> 1 Active team seat
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
                disabled
                className="mt-8 w-full py-2.5 bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-500 font-medium text-sm rounded-xl cursor-not-allowed border border-slate-200 dark:border-slate-700/50"
              >
                Current Plan
              </button>
            </div>

            {/* Pro Tier Card (Highlighted) */}
            <div className="p-8 rounded-2xl border-2 border-emerald-500 bg-white dark:bg-slate-900 flex flex-col justify-between shadow-md relative hover:shadow-xl transition-all">
              <span className="absolute -top-3.5 right-6 bg-gradient-to-r from-emerald-600 to-teal-600 text-white text-[11px] uppercase tracking-wider font-bold px-3 py-0.5 rounded-full shadow-sm flex items-center gap-1">
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
                  <span className="text-4xl font-extrabold">
                    {billingCycle === 'monthly' ? '$29' : '$23'}
                  </span>
                  <span className="text-sm text-slate-500 dark:text-slate-400"> / month</span>
                </div>

                <div className="space-y-3 pt-2">
                  <p className="text-xs uppercase tracking-wider font-semibold text-emerald-600 dark:text-emerald-400">Everything in Free, plus:</p>
                  <ul className="space-y-2.5 text-sm text-slate-700 dark:text-slate-300">
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Unlimited code and container scans
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Up to 10 Team seats included
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Automated AI Data Masking & Fix generation
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Custom Webhook & CI/CD Pipeline integration
                    </li>
                    <li className="flex items-center gap-2.5">
                      <Check className="h-4 w-4 text-emerald-500 shrink-0" /> Priority 24/7 technical support
                    </li>
                  </ul>
                </div>
              </div>

              <button
                onClick={() => handleOpenCheckout('Pro')}
                className="mt-8 w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 text-white font-semibold text-sm rounded-xl transition-all shadow-md shadow-emerald-500/10 flex items-center justify-center gap-2"
              >
                Get Pro Access <ArrowUpRight className="h-4 w-4" />
              </button>
            </div>

          </div>
        </div>

        {/* Invoice History */}
        <div className="pt-6 border-t border-slate-200 dark:border-slate-800 space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold">Invoice History</h2>
            <button 
              onClick={() => alert('Opening Whop portal...')}
              className="text-xs text-emerald-600 dark:text-emerald-400 hover:underline flex items-center gap-1 font-medium"
            >
              Manage on Whop Portal <ExternalLink className="h-3 w-3" />
            </button>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden bg-white dark:bg-slate-900 shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 border-b border-slate-200 dark:border-slate-800 text-xs uppercase tracking-wider">
                  <tr>
                    <th className="p-4 font-semibold">Invoice ID</th>
                    <th className="p-4 font-semibold">Date</th>
                    <th className="p-4 font-semibold">Amount</th>
                    <th className="p-4 font-semibold">Status</th>
                    <th className="p-4 font-semibold text-right">Receipt</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  <tr className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 font-mono text-xs font-medium">INV-2026-001</td>
                    <td className="p-4 text-slate-600 dark:text-slate-400">Sep 15, 2026</td>
                    <td className="p-4 font-medium">$0.00</td>
                    <td className="p-4">
                      <span className="px-2.5 py-0.5 text-xs rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 font-medium">
                        Paid
                      </span>
                    </td>
                    <td className="p-4 text-right">
                      <button 
                        onClick={() => alert('Downloading invoice PDF...')}
                        className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors text-slate-500 hover:text-slate-900 dark:hover:text-white"
                        title="Download Invoice PDF"
                      >
                        <Download className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

      </div>

      {/* Whop Checkout Modal Container */}
      {isCheckoutOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg p-6 shadow-2xl relative">
            <button
              onClick={() => setIsCheckoutOpen(false)}
              className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-6 w-6 text-emerald-500" />
                <h3 className="text-xl font-bold">Whop Checkout Integration</h3>
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                You are subscribing to the <strong className="text-slate-900 dark:text-white">{selectedPlan} Plan</strong> ({billingCycle}).
              </p>
              
              {/* Whop Embed Container Placeholder */}
              <div className="min-h-[220px] rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 flex flex-col items-center justify-center p-6 text-center">
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  [ Embed Whop Checkout iframe or widget component here ]
                </p>
              </div>

              <button
                onClick={() => setIsCheckoutOpen(false)}
                className="w-full py-2.5 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 font-semibold text-sm rounded-xl hover:opacity-90 transition-opacity"
              >
                Close Window
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}