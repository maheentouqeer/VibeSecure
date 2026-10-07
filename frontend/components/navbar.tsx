'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  BadgeCheck,
  CreditCard,
  LayoutDashboard,
  LogIn,
  Settings,
  Shield,
  Terminal,
  UserPlus,
} from 'lucide-react';

export default function Navbar() {
  const pathname = usePathname();

  const primary = [
    { href: '/', label: 'Security dashboard', icon: LayoutDashboard },
    { href: '/mcp', label: 'AI editors / MCP', icon: Terminal },
    { href: '/settings', label: 'Settings', icon: Settings },
    { href: '/billing', label: 'Billing', icon: CreditCard },
  ];

  return (
    <aside className="glass-sidebar sticky top-0 flex h-screen w-16 shrink-0 flex-col justify-between p-2.5 transition-all lg:w-64 lg:p-4">
      <div className="space-y-5">
        <Link
          href="/"
          className="flex items-center justify-center gap-2 px-2 pt-2 lg:justify-start"
          aria-label="VibeSecure dashboard"
        >
          <div className="icon-chip h-9 w-9 rounded-xl">
            <Shield className="h-4 w-4 text-emerald-300" />
          </div>
          <div className="hidden min-w-0 lg:block">
            <div className="text-base font-semibold tracking-tight text-white">VibeSecure</div>
            <div className="mt-0.5 text-[9px] font-bold uppercase tracking-[0.14em] text-slate-600">
              AI software security
            </div>
          </div>
        </Link>

        <div className="px-2 pt-2">
          <div className="mono-label hidden lg:block">WORKSPACE</div>
          <nav className="mt-2 space-y-1">
            {primary.map((item) => {
              const Icon = item.icon;
              const active =
                item.href === '/'
                  ? pathname === '/'
                  : pathname === item.href || pathname.startsWith(item.href + '/');

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  title={item.label}
                  className={
                    'flex items-center justify-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition lg:justify-start ' +
                    (active
                      ? 'border border-emerald-400/10 bg-emerald-400/[0.06] text-emerald-300'
                      : 'text-slate-500 hover:bg-white/[0.03] hover:text-slate-200')
                  }
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span className="hidden lg:inline">{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>


        <div className="mx-1 hidden rounded-2xl border border-white/[0.06] bg-white/[0.018] p-3 lg:block">
          <div className="flex items-center gap-2">
            <BadgeCheck className="h-4 w-4 text-emerald-300" />
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">
              ForgeHacks V1
            </span>
          </div>
          <p className="mt-1 text-[10px] leading-4 text-slate-600">
            Fraud impact + attack-path verification.
          </p>
        </div>
      </div>

      <div className="space-y-1 border-t border-white/[0.06] pt-3">
        <Link
          href="/login"
          title="Sign in"
          className="flex items-center justify-center gap-2 rounded-xl px-2.5 py-2.5 text-sm font-medium text-slate-500 transition hover:bg-white/[0.03] hover:text-slate-200 lg:justify-start lg:px-3.5"
        >
          <LogIn className="h-4 w-4" />
          <span className="hidden lg:inline">Sign in</span>
        </Link>
        <Link
          href="/signup"
          title="Sign up"
          className="flex items-center justify-center gap-2 rounded-xl border border-emerald-400/20 bg-emerald-400/90 px-2.5 py-2.5 text-sm font-bold text-slate-950 shadow-lg shadow-emerald-500/10 transition hover:bg-emerald-300 lg:justify-start lg:px-3.5"
        >
          <UserPlus className="h-4 w-4" />
          <span className="hidden lg:inline">Sign up</span>
        </Link>
      </div>
    </aside>
  );
}
