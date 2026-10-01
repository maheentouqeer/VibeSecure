'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Settings, CreditCard, LogIn, UserPlus } from 'lucide-react';

export default function Navbar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 h-screen sticky top-0 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col justify-between p-4 transition-colors shrink-0">
      <div className="space-y-6">
        {/* Brand / Logo */}
        <Link href="/" className="flex items-center gap-2 font-bold text-xl text-slate-900 dark:text-white px-2 pt-2">
          <Shield className="h-7 w-7 text-emerald-500" />
          <span>VibeSecure</span>
        </Link>

        {/* Primary App Navigation */}
        <nav className="space-y-1">
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
        </nav>
      </div>

      {/* Auth Actions (Bottom Panel) */}
      <div className="space-y-2 pt-4 border-t border-slate-200 dark:border-slate-800">
        <Link
          href="/login"
          className="w-full px-3.5 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-colors flex items-center gap-2.5"
        >
          <LogIn className="h-4 w-4" />
          <span>Sign In</span>
        </Link>

        <Link
          href="/signup"
          className="w-full px-3.5 py-2.5 text-sm font-semibold bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl transition-colors flex items-center justify-center gap-2 shadow-sm"
        >
          <UserPlus className="h-4 w-4" />
          <span>Sign Up</span>
        </Link>
      </div>
    </aside>
  );
}