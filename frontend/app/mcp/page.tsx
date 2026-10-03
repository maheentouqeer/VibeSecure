'use client';

import Link from 'next/link';
import { ArrowLeft, CheckCircle2, Copy, KeyRound, Terminal, ShieldCheck, ExternalLink } from 'lucide-react';
import { useState } from 'react';

const REMOTE_MCP_URL =
  (process.env.NEXT_PUBLIC_API_URL || 'https://backend-production-cc2b.up.railway.app') + '/mcp';

export default function McpPage() {
  const [copied, setCopied] = useState<string | null>(null);

  async function copy(text: string, id: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(null), 1500);
    } catch {}
  }

  const localConfig = [
    '{',
    '  "mcpServers": {',
    '    "vibesecure": {',
    '      "command": "python",',
    '      "args": ["/absolute/path/to/VibeSecure/mcp_server.py"]',
    '    }',
    '  }',
    '}',
  ].join('\n');

  const remoteConfig = [
    '{',
    '  "mcpServers": {',
    '    "vibesecure": {',
    '      "type": "http",',
    '      "url": "' + REMOTE_MCP_URL + '",',
    '      "headers": {',
    '        "X-API-Key": "vsk_your_key_here"',
    '      }',
    '    }',
    '  }',
    '}',
  ].join('\n');

  return (
    <main className="app-shell min-h-screen px-5 py-8 md:px-10">
      <div className="mx-auto max-w-5xl space-y-7">
        <Link href="/" className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-emerald-500">
          <ArrowLeft className="h-4 w-4" /> Back to dashboard
        </Link>

        <section className="glass-panel overflow-hidden p-6 md:p-8">
          <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="glass-badge inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-semibold text-emerald-500">
                <Terminal className="h-3.5 w-3.5" /> MCP enabled
              </div>
              <h1 className="mt-4 text-3xl font-bold tracking-tight md:text-4xl">VibeSecure MCP</h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500 dark:text-slate-400">
                Bring VibeSecure into your AI coding workflow. Use Local MCP for files on your machine,
                or Hosted MCP for authenticated repository and live-URL scans.
              </p>
            </div>
            <Link href="/settings" className="glass-button inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold">
              <KeyRound className="h-4 w-4" /> Manage API keys
            </Link>
          </div>
        </section>

        <div className="grid gap-5 lg:grid-cols-2">
          <section className="glass-panel p-6">
            <div className="flex items-center gap-3">
              <div className="glass-badge flex h-10 w-10 items-center justify-center rounded-xl"><Terminal className="h-5 w-5 text-emerald-500" /></div>
              <div><h2 className="font-bold">Local MCP</h2><p className="text-xs text-slate-500">No API key required</p></div>
            </div>
            <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
              Runs from your machine over stdio and scans the current project directly. Nothing is cloned from GitHub for local workspace scans.
            </p>
            <div className="relative mt-4">
              <pre className="glass-code overflow-x-auto rounded-2xl p-4 text-xs leading-6 text-slate-300">{localConfig}</pre>
              <button onClick={() => copy(localConfig, 'local')} className="glass-button absolute right-3 top-3 inline-flex items-center gap-1.5 rounded-lg px-2.5 py-2 text-xs font-semibold" aria-label="Copy local MCP config">
                <Copy className="h-4 w-4" />
                {copied === 'local' ? 'Copied' : 'Copy'}
              </button>
            </div>
          </section>

          <section className="glass-panel p-6">
            <div className="flex items-center gap-3">
              <div className="glass-badge flex h-10 w-10 items-center justify-center rounded-xl"><ShieldCheck className="h-5 w-5 text-emerald-500" /></div>
              <div><h2 className="font-bold">Hosted MCP</h2><p className="text-xs text-slate-500">API-key authenticated</p></div>
            </div>
            <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
              The hosted endpoint uses a VibeSecure API key. Create a key in Settings, then add it as the
              X-API-Key header in your MCP client.
            </p>
            <div className="mt-4 rounded-2xl border border-emerald-500/15 bg-emerald-500/5 p-4">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Endpoint</p>
              <p className="mt-2 break-all font-mono text-xs text-emerald-500">{REMOTE_MCP_URL}</p>
            </div>
            <div className="relative mt-4">
              <pre className="glass-code overflow-x-auto rounded-2xl p-4 text-xs leading-6 text-slate-300">{remoteConfig}</pre>
              <button onClick={() => copy(remoteConfig, 'remote')} className="glass-button absolute right-3 top-3 inline-flex items-center gap-1.5 rounded-lg px-2.5 py-2 text-xs font-semibold" aria-label="Copy hosted MCP config">
                <Copy className="h-4 w-4" />
                {copied === 'remote' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <Link href="/settings" className="mt-4 inline-flex items-center gap-1.5 text-sm font-semibold text-emerald-500 hover:text-emerald-400">
              Create / revoke API keys <ExternalLink className="h-3.5 w-3.5" />
            </Link>
          </section>
        </div>

        <section className="glass-panel p-6">
          <h2 className="font-bold">What the AI agent can do</h2>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {[
              ['scan_repository', 'Scan a public Git repository'],
              ['scan_live_url', 'Run passive live checks'],
              ['get_scan_status', 'Check progress'],
              ['get_findings', 'Read structured findings and fixes'],
              ['rescan', 'Verify fixes after code changes'],
            ].map(([name, description]) => (
              <div key={name} className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <p className="font-mono text-xs font-semibold text-emerald-500">{name}</p>
                <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{description}</p>
              </div>
            ))}
          </div>
          <div className="mt-5 flex items-center gap-2 text-xs text-emerald-500">
            <CheckCircle2 className="h-4 w-4" /> Your API key is never shown again after creation.
          </div>
        </section>
      </div>
    </main>
  );
}
