import { Shield, ExternalLink, ArrowLeft, BookOpen } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import ThemeToggle from './ThemeToggle';

const landingNavItems = [
  { label: 'Platform', href: '#platform' },
  { label: 'Features', href: '#features' },
  { label: 'Architecture', href: '#architecture' },
];

export default function Navbar() {
  const location = useLocation();
  const isLanding = location.pathname === '/';

  const handleAnchorClick = (
    e: React.MouseEvent<HTMLAnchorElement>,
    href: string,
  ) => {
    if (href.startsWith('#')) {
      e.preventDefault();
      const id = href.slice(1);

      if (!isLanding) {
        // Navigate to landing then scroll
        window.location.href = `/${href}`;
        return;
      }

      const el = document.getElementById(id);
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header
      className="fixed top-0 left-0 right-0 z-50"
      style={{
        background: 'var(--bg-navbar)',
        backdropFilter: 'blur(18px)',
        borderBottom: '1px solid var(--border-light)',
      }}
    >
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center gap-6">

        {/* Logo — always links back to landing */}
        <Link to="/" className="flex items-center gap-2.5 shrink-0">
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
        </Link>

        {/* On inner pages — show a back crumb */}
        {!isLanding && (
          <Link
            to="/"
            className="hidden md:flex items-center gap-1.5 text-xs transition-colors"
            style={{ color: 'var(--text-tertiary)' }}
            onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-secondary)')}
            onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-tertiary)')}
          >
            <ArrowLeft className="w-3 h-3" />
            Back to Home
          </Link>
        )}

        {/* Separator */}
        {!isLanding && (
          <div
            className="hidden md:block w-px h-4 shrink-0"
            style={{ background: 'var(--border-medium)' }}
          />
        )}

        {/* Nav links */}
        <nav className="hidden md:flex items-center gap-0.5 flex-1">
          {isLanding ? (
            // Landing page: scroll anchors
            landingNavItems.map((item) => (
              <a
                key={item.label}
                href={item.href}
                onClick={(e) => handleAnchorClick(e, item.href)}
                className="px-3 py-1.5 text-sm rounded-md transition-colors cursor-pointer"
                style={{ color: 'var(--text-secondary)' }}
                onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
                onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-secondary)')}
              >
                {item.label}
              </a>
            ))
          ) : (
            // Inner pages: show links to main app sections
            <>
              <Link
                to="/dashboard"
                className="px-3 py-1.5 text-sm rounded-md transition-colors"
                style={{
                  color: location.pathname === '/dashboard'
                    ? 'var(--text-primary)'
                    : 'var(--text-secondary)',
                  background: location.pathname === '/dashboard'
                    ? 'var(--border-light)'
                    : 'transparent',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
                onMouseLeave={(e) => {
                  if (location.pathname !== '/dashboard')
                    e.currentTarget.style.color = 'var(--text-secondary)';
                }}
              >
                Dashboard
              </Link>
              <Link
                to="/attack-surface"
                className="px-3 py-1.5 text-sm rounded-md transition-colors"
                style={{
                  color: location.pathname === '/attack-surface'
                    ? 'var(--text-primary)'
                    : 'var(--text-secondary)',
                  background: location.pathname === '/attack-surface'
                    ? 'var(--border-light)'
                    : 'transparent',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
                onMouseLeave={(e) => {
                  if (location.pathname !== '/attack-surface')
                    e.currentTarget.style.color = 'var(--text-secondary)';
                }}
              >
                Attack Surface
              </Link>
              <Link
                to="/scans"
                className="px-3 py-1.5 text-sm rounded-md transition-colors"
                style={{
                  color: location.pathname === '/scans'
                    ? 'var(--text-primary)'
                    : 'var(--text-secondary)',
                  background: location.pathname === '/scans'
                    ? 'var(--border-light)'
                    : 'transparent',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
                onMouseLeave={(e) => {
                  if (location.pathname !== '/scans')
                    e.currentTarget.style.color = 'var(--text-secondary)';
                }}
              >
                Scans
              </Link>
            </>
          )}
        </nav>

        {/* Right side actions */}
        <div className="flex items-center gap-2 ml-auto shrink-0">
          <ThemeToggle />

          {/* Documentation — links to GitHub wiki / readme */}
          <a
            href="https://github.com/OpenSecX/OpenSecX/wiki"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden md:flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-md transition-all"
            style={{
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-light)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = 'var(--text-primary)';
              e.currentTarget.style.borderColor = 'var(--border-medium)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = 'var(--text-secondary)';
              e.currentTarget.style.borderColor = 'var(--border-light)';
            }}
          >
            <BookOpen className="w-3.5 h-3.5" />
            Docs
            <ExternalLink className="w-2.5 h-2.5 opacity-50" />
          </a>

          {/* Primary CTA */}
          {isLanding ? (
            <Link
              to="/attack-surface"
              className="flex items-center gap-1.5 px-4 py-1.5 text-sm font-medium rounded-md transition-opacity"
              style={{ background: 'var(--text-primary)', color: 'var(--bg-main)' }}
              onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.88')}
              onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
            >
              Open Platform
            </Link>
          ) : (
            <div
              className="flex items-center gap-1.5 text-xs font-mono"
              style={{ color: 'var(--text-tertiary)' }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: '#81C995', boxShadow: '0 0 5px rgba(129,201,149,0.7)' }}
              />
              API online
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
