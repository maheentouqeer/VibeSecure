'use client';

import React, { useEffect, useState } from 'react';
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
  Copy,
  Plus,
  ShieldCheck,
  Trash2,
  Terminal,
} from 'lucide-react';
import { useTheme } from 'next-themes';
import { ApiError, createApiKey, listApiKeys, revokeApiKey, type ApiKeyCreated, type ApiKeyMeta } from '@/lib/api';

function ApiKeysPanel() {
  const [keys, setKeys] = useState<ApiKeyMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [label, setLabel] = useState('VS Code / MCP');
  const [createdKey, setCreatedKey] = useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadKeys() {
    setLoading(true);
    setError(null);
    try {
      setKeys(await listApiKeys());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load API keys.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadKeys();
  }, []);

  async function handleCreate() {
    setBusy(true);
    setError(null);
    setCreatedKey(null);
    try {
      const created = await createApiKey(label);
      setCreatedKey(created);
      await loadKeys();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not create API key.');
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke(id: string) {
    setBusy(true);
    setError(null);
    try {
      await revokeApiKey(id);
      await loadKeys();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not revoke API key.');
    } finally {
      setBusy(false);
    }
  }

  async function copyKey() {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey.key);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      setError('Clipboard access was blocked. Copy the key manually.');
    }
  }

  return (
    <div className="space-y-6">
      <div className="glass-panel p-6">
        <div className="flex flex-col gap-5 md:flex-row md:items-start md:justify-between">
          <div className="flex items-start gap-3">
            <div className="glass-badge mt-0.5 flex h-11 w-11 items-center justify-center rounded-2xl">
              <Key className="h-5 w-5 text-emerald-500" />
            </div>
            <div>
              <h2 className="text-xl font-bold">API Keys & Access</h2>
              <p className="mt-1 max-w-2xl text-sm text-slate-500 dark:text-slate-400">
                Create revocable credentials for the hosted MCP endpoint and future CLI/CI integrations.
                The full key is shown only once.
              </p>
            </div>
          </div>
          <Link href="/mcp" className="glass-button inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold">
            <Terminal className="h-4 w-4" /> MCP setup
          </Link>
        </div>

        {error && (
          <div className="mt-5 rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-600 dark:text-red-300">
            {error}
          </div>
        )}

        {createdKey && (
          <div className="mt-5 rounded-2xl border border-emerald-500/25 bg-emerald-500/10 p-4">
            <div className="flex items-start gap-3">
              <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-500" />
              <div className="min-w-0 flex-1">
                <p className="font-semibold text-emerald-700 dark:text-emerald-300">API key created</p>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Copy it now. The full credential will not be displayed again.
                </p>
                <div className="mt-3 flex gap-2">
                  <code className="min-w-0 flex-1 overflow-x-auto rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-200">
                    {createdKey.key}
                  </code>
                  <button onClick={copyKey} className="glass-button inline-flex shrink-0 items-center gap-1.5 rounded-xl px-3 py-2 text-xs font-semibold">
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="mt-6 grid gap-3 md:grid-cols-[1fr_auto]">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            maxLength={80}
            placeholder="Key label, e.g. VS Code / MCP"
            className="glass-input w-full rounded-xl border px-4 py-3 text-sm outline-none"
          />
          <button
            onClick={handleCreate}
            disabled={busy || !label.trim()}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-500 px-5 py-3 text-sm font-bold text-slate-950 shadow-lg shadow-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Plus className="h-4 w-4" /> {busy ? 'Creating…' : 'Create API key'}
          </button>
        </div>
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="border-b border-white/10 px-5 py-4">
          <h3 className="font-semibold">Your keys</h3>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Only metadata is displayed after creation.</p>
        </div>

        {loading ? (
          <div className="px-5 py-8 text-sm text-slate-500">Loading keys…</div>
        ) : keys.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-slate-500 dark:text-slate-400">
            No API keys yet. Create one for the hosted MCP connection.
          </div>
        ) : (
          <div className="divide-y divide-white/10">
            {keys.map((item) => {
              const revoked = Boolean(item.revoked_at);
              return (
                <div key={item.id} className="flex flex-col gap-3 px-5 py-4 md:flex-row md:items-center md:justify-between">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-medium">{item.label}</p>
                      <span className={revoked
                        ? 'rounded-full border border-slate-500/20 bg-white/5 px-2 py-0.5 text-[10px] font-semibold text-slate-500'
                        : 'rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-500'}>
                        {revoked ? 'Revoked' : 'Active'}
                      </span>
                    </div>
                    <p className="mt-1 font-mono text-xs text-slate-500">{item.key_prefix}…••••</p>
                    <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                      Created {new Date(item.created_at).toLocaleString()}
                      {item.last_used_at ? ' · Last used ' + new Date(item.last_used_at).toLocaleString() : ''}
                    </p>
                  </div>
                  {!revoked && (
                    <button
                      onClick={() => handleRevoke(item.id)}
                      disabled={busy}
                      className="glass-button inline-flex items-center justify-center gap-1.5 self-start rounded-xl px-3 py-2 text-xs font-semibold text-red-500 md:self-auto"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Revoke
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

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
    <div className="min-h-screen app-shell text-slate-900 dark:text-slate-100 p-6 md:p-10">
      <div className="max-w-5xl mx-auto space-y-8">

        {/* Top Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-900/10 dark:border-white/10 pb-6">
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
        <div className="flex space-x-2 border-b border-slate-900/10 dark:border-white/10 overflow-x-auto pb-1">
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
            <div className="glass-panel p-6 space-y-4">
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

            <div className="glass-panel p-6 space-y-4">
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

        {/* TAB 2: API KEYS */}
        {activeTab === 'apikeys' && <ApiKeysPanel />}

        {/* TAB 3: PREFERENCES */}
        {activeTab === 'preferences' && (
          <div className="space-y-6 max-w-2xl">
            <div className="glass-panel p-6 space-y-4">
              <h2 className="text-lg font-semibold">Theme Selection</h2>
              <div className="grid grid-cols-3 gap-3">
                <button
                  onClick={() => setTheme('light')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${theme === 'light'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-white/10'
                    }`}
                >
                  <Sun className="h-5 w-5" /> Light
                </button>
                <button
                  onClick={() => setTheme('dark')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${theme === 'dark'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-400'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-white/10'
                    }`}
                >
                  <Moon className="h-5 w-5" /> Dark
                </button>
                <button
                  onClick={() => setTheme('system')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${theme === 'system'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-500'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-white/10'
                    }`}
                >
                  <Monitor className="h-5 w-5" /> System
                </button>
              </div>
            </div>

            <div className="glass-panel p-6 space-y-4">
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