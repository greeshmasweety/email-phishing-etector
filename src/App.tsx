import { Routes, Route, NavLink, Link } from 'react-router-dom';
import { AlertProvider } from './context/AlertContext';
import ToastContainer from './components/ToastContainer';
import AlertBell from './components/AlertBell';
import Dashboard from './pages/Dashboard';
import ScanEmail from './pages/ScanEmail';
import Emails from './pages/Emails';
import EmailDetail from './pages/EmailDetail';
import UrlScanner from './pages/UrlScanner';
import Alerts from './pages/Alerts';
import Quarantine from './pages/Quarantine';
import ThreatDetection from './pages/ThreatDetection';
import Reports from './pages/Reports';
import AIAnalyst from './pages/AIAnalyst';
import Settings from './pages/Settings';

const navItems = [
  { to: '/', label: 'Dashboard', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { to: '/scan', label: 'Scan Email', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  { to: '/url-scan', label: 'URL Scanner', icon: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1' },
  { to: '/threats', label: 'Threat Detection', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
  { to: '/quarantine', label: 'Quarantine', icon: 'M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636' },
  { to: '/ai-analyst', label: 'AI Analyst', icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' },
  { to: '/emails', label: 'Emails', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  { to: '/alerts', label: 'Alerts', icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9' },
  { to: '/reports', label: 'Reports', icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
  { to: '/settings', label: 'Settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.86-.987 3.79.942 2.803 2.803a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.987 1.86-.942 3.79-2.803 2.803a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.86.987-3.79-.942-2.803-2.803a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.987-1.86.942-3.79 2.803-2.803a1.724 1.724 0 002.573-1.066z' },
];

export default function App() {
  return (
    <AlertProvider>
      <div className="min-h-screen bg-gray-50 flex">
        <aside className="w-64 bg-slate-900 text-white flex flex-col fixed h-full overflow-y-auto">
          <div className="px-6 py-5 border-b border-slate-700">
            <Link to="/" className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-lg">P</div>
              <div>
                <div className="font-bold text-lg leading-tight">PhishGuard</div>
                <div className="text-xs text-slate-400">Email Threat Scanner</div>
              </div>
            </Link>
          </div>
          <nav className="flex-1 px-3 py-4 space-y-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                  }`
                }
              >
                <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={item.icon} />
                </svg>
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="px-6 py-4 border-t border-slate-700 flex items-center justify-between">
            <span className="text-xs text-slate-400">VirusTotal + AI detection</span>
            <AlertBell />
          </div>
        </aside>

        <main className="flex-1 ml-64 p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<ScanEmail />} />
            <Route path="/url-scan" element={<UrlScanner />} />
            <Route path="/threats" element={<ThreatDetection />} />
            <Route path="/quarantine" element={<Quarantine />} />
            <Route path="/ai-analyst" element={<AIAnalyst />} />
            <Route path="/emails" element={<Emails />} />
            <Route path="/emails/:id" element={<EmailDetail />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>

        <ToastContainer />
      </div>
    </AlertProvider>
  );
}
