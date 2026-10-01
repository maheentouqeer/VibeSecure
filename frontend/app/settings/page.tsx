'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  User, 
  Key, 
  Bell, 
  Users, 
  Copy, 
  Check, 
  Trash2, 
  Plus, 
  Sun, 
  Moon, 
  Monitor, 
  Save 
} from 'lucide-react';
import { useTheme } from 'next-themes';

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'profile' | 'apikeys' | 'preferences' | 'team'>('profile');
  const { theme, setTheme } = useTheme();

  // Profile Form State
  const [name, setName] = useState('Zahra Jafri');
  const [email, setEmail] = useState('zahra@vibesecure.io');
  const [isSaved, setIsSaved] = useState(false);

  // API Key State
  const [apiKeys, setApiKeys] = useState([
    { id: '1', name: 'CLI Key Local', key: 'vsk_live_9a8b...7c6d', created: '2026-08-12' },
    { id: '2', name: 'GitHub Actions CI', key: 'vsk_live_1f2e...3d4c', created: '2026-09-01' },
  ]);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Team State
  const [teamMembers, setTeamMembers] = useState([
    { id: '1', name: 'Zahra Jafri', email: 'zahra@vibesecure.io', role: 'Owner' },
    { id: '2', name: 'Aneel', email: 'aneel@vibesecure.io', role: 'Admin' },
  ]);
  const [newMemberEmail, setNewMemberEmail] = useState('');

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2000);
  };

  const copyToClipboard = (id: string, keyText: string) => {
    navigator.clipboard.writeText(keyText);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const createApiKey = () => {
    const keyName = prompt('Enter a name for your new API key:');
    if (keyName) {
      const newKey = {
        id: Date.now().toString(),
        name: keyName,
        key: `vsk_live_${Math.random().toString(36).substring(2, 10)}...${Math.random().toString(36).substring(2, 6)}`,
        created: new Date().toISOString().split('T')[0],
      };
      setApiKeys([...apiKeys, newKey]);
    }
  };

  const revokeApiKey = (id: string) => {
    if (confirm('Are you sure you want to revoke this API Key?')) {
      setApiKeys(apiKeys.filter((k) => k.id !== id));
    }
  };

  const inviteMember = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMemberEmail) return;
    setTeamMembers([
      ...teamMembers,
      { id: Date.now().toString(), name: 'Pending User', email: newMemberEmail, role: 'Developer' },
    ]);
    setNewMemberEmail('');
  };

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 p-6 md:p-10">
      <div className="max-w-5xl mx-auto space-y-8">
        
        {/* Top Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-6">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Account Settings</h1>
            <p className="text-slate-600 dark:text-slate-400 mt-1">
              Manage your personal credentials, API security tokens, and organization team roles.
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
            { id: 'team', label: 'Team Members', icon: Users },
          ].map((tabItem) => {
            const TabIcon = tabItem.icon;
            return (
              <button
                key={tabItem.id}
                onClick={() => setActiveTab(tabItem.id as 'profile' | 'apikeys' | 'preferences' | 'team')}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors border-b-2 whitespace-nowrap ${
                  activeTab === tabItem.id
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

        {/* TAB 2: API KEYS */}
        {activeTab === 'apikeys' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="text-xl font-bold">API Tokens</h2>
                <p className="text-sm text-slate-500">
                  Use these secrets to authenticate CLI runs and custom webhook workflows.
                </p>
              </div>
              <button
                onClick={createApiKey}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
              >
                <Plus className="h-4 w-4" /> Generate New Key
              </button>
            </div>

            <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden bg-slate-50 dark:bg-slate-900">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-100 dark:bg-slate-800 text-slate-500 border-b border-slate-200 dark:border-slate-800">
                  <tr>
                    <th className="p-3.5 font-medium">Name</th>
                    <th className="p-3.5 font-medium">Key Secret</th>
                    <th className="p-3.5 font-medium">Created</th>
                    <th className="p-3.5 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {apiKeys.map((k) => (
                    <tr key={k.id}>
                      <td className="p-3.5 font-medium">{k.name}</td>
                      <td className="p-3.5 font-mono text-xs text-slate-500">{k.key}</td>
                      <td className="p-3.5 text-slate-500 text-xs">{k.created}</td>
                      <td className="p-3.5 text-right space-x-2">
                        <button
                          onClick={() => copyToClipboard(k.id, k.key)}
                          className="p-1.5 hover:bg-slate-200 dark:hover:bg-slate-800 rounded transition-colors text-slate-500 hover:text-slate-900 dark:hover:text-white"
                          title="Copy Key"
                        >
                          {copiedId === k.id ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
                        </button>
                        <button
                          onClick={() => revokeApiKey(k.id)}
                          className="p-1.5 hover:bg-rose-500/10 rounded transition-colors text-slate-500 hover:text-rose-500"
                          title="Revoke Key"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${
                    theme === 'light'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <Sun className="h-5 w-5" /> Light
                </button>
                <button
                  onClick={() => setTheme('dark')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${
                    theme === 'dark'
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-400'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <Moon className="h-5 w-5" /> Dark
                </button>
                <button
                  onClick={() => setTheme('system')}
                  className={`p-3 rounded-lg border flex flex-col items-center gap-2 text-sm font-medium transition-all ${
                    theme === 'system'
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

        {/* TAB 4: TEAM */}
        {activeTab === 'team' && (
          <div className="space-y-6">
            <form onSubmit={inviteMember} className="flex gap-3 max-w-xl">
              <input
                type="email"
                required
                placeholder="colleague@company.com"
                value={newMemberEmail}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setNewMemberEmail(e.target.value)}
                className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-emerald-500 text-sm"
              />
              <button
                type="submit"
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-sm font-medium transition-colors whitespace-nowrap"
              >
                Invite Member
              </button>
            </form>

            <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden bg-slate-50 dark:bg-slate-900">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-100 dark:bg-slate-800 text-slate-500 border-b border-slate-200 dark:border-slate-800">
                  <tr>
                    <th className="p-3.5 font-medium">Member</th>
                    <th className="p-3.5 font-medium">Role</th>
                    <th className="p-3.5 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {teamMembers.map((m) => (
                    <tr key={m.id}>
                      <td className="p-3.5">
                        <div className="font-medium">{m.name}</div>
                        <div className="text-xs text-slate-500">{m.email}</div>
                      </td>
                      <td className="p-3.5">
                        <span className="px-2 py-0.5 text-xs rounded-md bg-slate-200 dark:bg-slate-800 font-medium">
                          {m.role}
                        </span>
                      </td>
                      <td className="p-3.5 text-right">
                        {m.role !== 'Owner' && (
                          <button
                            onClick={() => setTeamMembers(teamMembers.filter((item) => item.id !== m.id))}
                            className="p-1.5 hover:bg-rose-500/10 rounded transition-colors text-slate-500 hover:text-rose-500"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}