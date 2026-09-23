/**
 * AppLayout — wraps all inner platform pages (Dashboard, Attack Surface, Scans etc.)
 *
 * Renders:
 *   - Top Navbar (with Back to Home, nav links, Docs button)
 *   - Sidebar
 *   - Page content
 *
 * The Navbar sits above everything. The sidebar + content fill the remaining height.
 */
import Navbar from './Navbar';
import Sidebar from './Sidebar';

interface AppLayoutProps {
  children: React.ReactNode;
}

export default function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: 'var(--bg-main)' }}>
      {/* Top navigation bar — always visible */}
      <Navbar />

      {/* Below navbar: sidebar + main content */}
      <div className="flex flex-1 min-h-0 overflow-hidden" style={{ paddingTop: '56px' }}>
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          {children}
        </div>
      </div>
    </div>
  );
}
