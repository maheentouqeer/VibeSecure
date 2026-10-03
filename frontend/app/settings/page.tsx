'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  User,
  Key,
  Bell,
  Check,
  Sun,
  Moon,
  Monitor,
  Save,
  Construction,
} from 'lucide-react';
import { useTheme } from 'next-themes';

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'profile' | 'apikeys' | 'preferences'>('profile');
  const { theme, setTheme } = useTheme();

  // Profile Form State
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [isSaved, setIsSaved] = useState(false);

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2000);
  };

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 p-6 md:p-10">
      <div className="max-w-5xl mx-auto space-y-8">

        {/* Top Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-6">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Account Settings</h1>
            <p className="text-slate-600 dark:text-slate-400 mt-1">
              Manage your personal credentials and preferences.
            </p>
          </div>
          <Link
            href="/billing"
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-sm font-medium transition-colors w-fit"
          >
            Manage Billing
          </Link>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-2 border-b border-slate-200 dark:border-slate-800 overflow-x-auto pb-1">
          {[
            { id: 'profile', label: 'Profile', icon: User },
            { id: 'apikeys', label: 'API Keys & Access', icon: Key },
            { id: 'preferences', label: 'Preferences', icon: Bell },
          ].map((tabItem) => {
            const TabIcon = tabItem.icon;
            return (
              <button
                key={tabItem.id}
                onClick={() => setActiveTab(tabItem.id as 'profile' | 'apikeys' | 'preferences')}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors border-b-2 whitespace-nowrap ${activeTab === tabItem.id
                    ? 'border-emerald-500 text-emerald-600 dark:text-emerald-400 bg-slate-50 dark:bg-slate-900/50'
                    : 'border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-slate-200'
                  }`}
              >
                <TabIcon className="h-4 w-4" />
                {tabItem.label}
              </button>
            );
          })}
        </div>

        {/* TAB 1: PROFILE */}
        {activeTab === 'profile' && (
          <form onSubmit={handleSaveProfile} className="space-y-6 max-w-2xl">
            <div className="p-6 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 space-y-4">
              <h2 className="text-lg font-semibold">Personal Information</h2>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setName(e.target.value)}
                  placeholder="Your name"
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-emerald-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-emerald-500"
                />
              </div>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 space-y-4">
              <h2 className="text-lg font-semibold">Security</h2>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  New Password
                </label>
                <input
                  type="password"
                  placeholder="••••••••••••"
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-emerald-500"
                />
              </div>
            </div>

            <button
              type="submit"
              className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white font-medium rounded-lg transition-colors flex items-center gap-2"
            >
              {isSaved ? <Check className="h-4 w-4" /> : <Save className="h-4 w-4" />}
              {isSaved ? 'Changes Saved!' : 'Save Changes'}
            </button>
          </form>
        )}

        {/* TAB 2: API KEYS — Coming Soon */}
        {activeTab === 'apikeys' && (
          <div className="space-y-6">
            <div className="p-8 rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 flex flex-col items-center justify-center text-center">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-500/10 mb-4">
                <Construction className="h-6 w-6 text-amber-500" />
              </div>
              <h2 className="text-xl font-bold">API Keys &mdash; Coming Soon</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-2 max-w-md">
                API key management is not available yet. This feature is under active development and
                will allow you to generate tokens for CLI and CI/CD pipeline integrations.
              </p>
            </div>
          </div>
        )}

        {/* TAB 3: PREFERENCES */}
        {activeTab === 'preferences' && (
          <div className="space-y-6 max-w-2xl">
            <div className="p-6 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 space-y-4">
              <h2 className="text-lg font-semibold">Theme Selection</h2>
              <div className="grid grid-cols-3 gap-3">
                <button
                  onClick={() => setTheme('light')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${theme === 'light'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                >
                  <Sun className="h-5 w-5" /> Light
                </button>
                <button
                  onClick={() => setTheme('dark')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${theme === 'dark'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-400'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                >
                  <Moon className="h-5 w-5" /> Dark
                </button>
                <button
                  onClick={() => setTheme('system')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${theme === 'system'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-500'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                >
                  <Monitor className="h-5 w-5" /> System
                </button>
              </div>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 space-y-4">
              <h2 className="text-lg font-semibold">Notifications</h2>
              <div className="space-y-3">
                <label className="flex items-center justify-between">
                  <span className="text-sm font-medium">Critical Security Alerts</span>
                  <input type="checkbox" defaultChecked className="h-4 w-4 accent-emerald-500 rounded" />
                </label>
                <label className="flex items-center justify-between">
                  <span className="text-sm font-medium">Weekly Scan Summaries</span>
                  <input type="checkbox" defaultChecked className="h-4 w-4 accent-emerald-500 rounded" />
                </label>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}