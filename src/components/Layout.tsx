import { NavLink, Outlet } from 'react-router-dom';
import { Shield, LayoutDashboard, Inbox, AlertTriangle, FolderLock, Settings, ScrollText, ScanLine } from 'lucide-react';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/scan', label: 'Scan Email', icon: ScanLine },
  { to: '/emails', label: 'Emails', icon: Inbox },
  { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { to: '/quarantine', label: 'Quarantine', icon: FolderLock },
  { to: '/audit', label: 'Audit Logs', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export default function Layout() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      <aside className="w-64 shrink-0 border-r border-slate-800 bg-slate-900/60 backdrop-blur flex flex-col">
        <div className="px-6 py-5 flex items-center gap-2 border-b border-slate-800">
          <Shield className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-sm font-semibold tracking-tight">PhishGuard AI</h1>
            <p className="text-[11px] text-slate-500">Phishing Detection System</p>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                  }`
                }
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
        <div className="px-6 py-4 border-t border-slate-800 text-[11px] text-slate-600">
          Dry-run mode by default. No Gmail emails are modified unless auto-quarantine is enabled.
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
