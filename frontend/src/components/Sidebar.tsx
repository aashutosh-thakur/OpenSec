import {
  Shield, BarChart2,
  FileText, Settings, Scan,
  Globe, ChevronRight, AlertTriangle
} from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

const navItems = [
  { label: 'Dashboard',       icon: BarChart2,    href: '/dashboard',       phase: 1 },
  { label: 'Attack Surface',  icon: Globe,        href: '/attack-surface',  phase: 1 },
  { label: 'Scans',           icon: Scan,         href: '/scans',           phase: 1 },
  { label: 'Vulnerabilities', icon: AlertTriangle, href: '/vulnerabilities', phase: 1 },
  { label: 'Reports',         icon: FileText,     href: '/reports',         phase: 1 },
];

const phaseColors: Record<number, string> = {
  1: 'rgba(168,199,250,0.7)',
  2: 'rgba(129,201,149,0.6)',
  3: 'rgba(253,214,99,0.6)',
  4: 'var(--text-tertiary)',
};

export default function Sidebar() {
  const location = useLocation();

  return (
    <aside
      className="w-56 shrink-0 flex flex-col h-screen sticky top-0"
      style={{
        background: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border-light)',
      }}
    >
      {/* Logo */}
      <div
        className="h-14 flex items-center px-5 gap-3 shrink-0"
        style={{ borderBottom: '1px solid var(--border-light)' }}
      >
        <div
          className="w-7 h-7 rounded-lg flex items-center justify-center"
          style={{
            background: 'var(--border-light)',
            border: '1px solid var(--border-medium)',
          }}
        >
          <Shield className="w-3.5 h-3.5" style={{ color: 'var(--text-primary)' }} />
        </div>
        <span className="font-semibold tracking-tight text-sm" style={{ color: 'var(--text-primary)' }}>
          Open<span style={{ color: '#A8C7FA' }}>SecX</span>
        </span>

        {/* Phase badge */}
        <span
          className="ml-auto text-[9px] font-mono px-1.5 py-0.5 rounded"
          style={{
            background: 'rgba(168,199,250,0.08)',
            color: 'rgba(168,199,250,0.55)',
            border: '1px solid rgba(168,199,250,0.12)',
          }}
        >
          P1
        </span>
      </div>

      {/* Project context */}
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border-light)' }}>
        <p className="text-[10px] mb-1.5 font-medium tracking-wider uppercase" style={{ color: 'var(--text-muted)' }}>
          Active Project
        </p>
        <button
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-all"
          style={{
            background: 'var(--border-light)',
            color: 'var(--text-secondary)',
            border: '1px solid var(--border-light)',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'var(--border-light)';
            e.currentTarget.style.borderColor = 'var(--border-medium)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'var(--border-light)';
            e.currentTarget.style.borderColor = 'var(--border-light)';
          }}
        >
          <span className="font-medium truncate">Default Project</span>
          <ChevronRight className="w-3 h-3 shrink-0 ml-1" style={{ color: 'var(--text-tertiary)' }} />
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-3 space-y-0.5 overflow-y-auto">
        <p
          className="px-3 pt-1 pb-2 text-[10px] font-semibold tracking-widest uppercase"
          style={{ color: 'var(--text-muted)' }}
        >
          Platform
        </p>

        {navItems.map(({ label, icon: Icon, href, phase }) => {
          const active = location.pathname === href;
          const isComingSoon = phase > 1 && !active;

          return (
            <Link
              key={label}
              to={href}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all relative group"
              style={{
                background: active ? 'rgba(168,199,250,0.08)' : 'transparent',
                color: active ? 'var(--text-primary)' : isComingSoon ? 'var(--text-tertiary)' : 'var(--text-secondary)',
                fontWeight: active ? 500 : 400,
              }}
              onMouseEnter={(e) => {
                if (!active) {
                  e.currentTarget.style.background = 'var(--border-light)';
                  e.currentTarget.style.color = isComingSoon ? 'var(--text-tertiary)' : 'var(--text-primary)';
                }
              }}
              onMouseLeave={(e) => {
                if (!active) {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = isComingSoon ? 'var(--text-tertiary)' : 'var(--text-secondary)';
                }
              }}
            >
              {/* Active indicator */}
              {active && (
                <span
                  className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 rounded-r"
                  style={{ background: '#A8C7FA' }}
                />
              )}

              <Icon className="w-4 h-4 shrink-0" />
              <span className="flex-1">{label}</span>

              {/* Phase indicator for non-Phase-1 items */}
              {phase > 1 && (
                <span
                  className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                  style={{
                    background: 'var(--border-light)',
                    color: phaseColors[phase],
                    border: '1px solid var(--border-light)',
                  }}
                >
                  P{phase}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Phase status */}
      <div
        className="mx-3 mb-3 p-3 rounded-lg"
        style={{
          background: 'var(--border-light)',
          border: '1px solid var(--border-light)',
        }}
      >
        <p className="text-[10px] font-semibold mb-2 tracking-wider uppercase" style={{ color: 'var(--text-muted)' }}>
          Build Progress
        </p>
        {[
          { num: 1, label: 'Asset Discovery',     done: true },
          { num: 2, label: 'VAPT & Findings',     done: true },
          { num: 3, label: 'Attack Paths & Reports', done: true },
          { num: 4, label: 'Risk & Compliance',   done: false },
        ].map((p) => (
          <div key={p.num} className="flex items-center gap-2 mb-1">
            <div
              className="w-4 h-4 rounded-sm flex items-center justify-center shrink-0"
              style={{
                background: p.done ? 'rgba(129,201,149,0.15)' : 'var(--border-light)',
                border: `1px solid ${p.done ? 'rgba(129,201,149,0.3)' : 'var(--border-light)'}`,
              }}
            >
              <span
                className="text-[8px] font-mono font-bold"
                style={{ color: p.done ? '#81C995' : 'var(--text-muted)' }}
              >
                {p.num}
              </span>
            </div>
            <span
              className="text-[11px] truncate"
              style={{ color: p.done ? 'var(--text-secondary)' : 'var(--text-muted)' }}
            >
              {p.label}
            </span>
            {p.done && (
              <span className="ml-auto text-[9px] shrink-0" style={{ color: '#81C995' }}>✓</span>
            )}
          </div>
        ))}
      </div>

      {/* Bottom */}
      <div
        className="px-3 py-3"
        style={{ borderTop: '1px solid var(--border-light)' }}
      >
        <Link
          to="/settings"
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all"
          style={{ color: 'var(--text-tertiary)' }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = 'var(--text-secondary)';
            e.currentTarget.style.background = 'var(--border-light)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = 'var(--text-tertiary)';
            e.currentTarget.style.background = 'transparent';
          }}
        >
          <Settings className="w-4 h-4" />
          Settings
        </Link>
      </div>
    </aside>
  );
}
