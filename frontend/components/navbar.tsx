'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Settings, CreditCard, LogIn, UserPlus, Terminal } from 'lucide-react';

export default function Navbar() {
  const pathname = usePathname();

  return (
    <aside className="glass-sidebar w-16 lg:w-64 h-screen sticky top-0 flex flex-col justify-between p-2.5 lg:p-4 transition-all shrink-0">
      <div className="space-y-6">
        {/* Brand / Logo */}
        <Link href="/" className="flex items-center justify-center lg:justify-start gap-2 font-bold text-xl text-slate-900 dark:text-white px-2 pt-2">
          <Shield className="h-7 w-7 text-emerald-500" />
          <span className="hidden lg:inline">VibeSecure</span>
        </Link>

        {/* Primary App Navigation */}
        <div className="space-y-4"><div className="px-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 dark:text-slate-500 hidden lg:block">Workspace</div><nav className="space-y-1">
          <Link
            href="/settings"
            className={`w-full px-3.5 py-2.5 rounded-xl text-sm font-medium transition-colors flex items-center gap-3 ${
              pathname === '/settings'
                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-semibold'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Settings className="h-5 w-5" />
            <span>Settings</span>
          </Link>

          <Link
            href="/billing"
            className={`w-full px-3.5 py-2.5 rounded-xl text-sm font-medium transition-colors flex items-center gap-3 ${
              pathname === '/billing'
                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-semibold'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <CreditCard className="h-5 w-5" />
            <span>Billing</span>
          </Link>
        </nav><Link href="/mcp" className="glass-badge hidden lg:flex items-center gap-2 rounded-2xl px-3 py-2.5 text-xs text-emerald-700 transition hover:border-emerald-400/40 dark:text-emerald-300" title="Open VibeSecure MCP setup"><Terminal className="h-4 w-4 shrink-0" /><span><strong className="block font-semibold">MCP available</strong><span className="text-[11px] text-slate-500 dark:text-slate-400">Open setup & connect</span></span></Link></div>
      </div>

      {/* Auth Actions (Bottom Panel) */}
      <div className="space-y-2 pt-4 border-t border-slate-200 dark:border-slate-800">
        <Link
          href="/login"
          className="w-full px-2.5 lg:px-3.5 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-white/10 rounded-xl transition-colors flex items-center justify-center lg:justify-start gap-2.5"
        >
          <LogIn className="h-4 w-4" />
          <span className="hidden lg:inline">Sign In</span>
        </Link>

        <Link
          href="/signup"
          className="w-full px-2.5 lg:px-3.5 py-2.5 text-sm font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-xl transition-colors flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20"
        >
          <UserPlus className="h-4 w-4" />
          <span className="hidden lg:inline">Sign Up</span>
        </Link>
      </div>
    </aside>
  );
}