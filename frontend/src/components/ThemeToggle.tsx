import { useState, useEffect } from 'react';
import { Sun, Moon } from 'lucide-react';

export default function ThemeToggle() {
  const [isLight, setIsLight] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem('opensecx-theme');
    if (saved === 'light') {
      setIsLight(true);
      document.documentElement.classList.add('light');
    }
  }, []);

  const toggleTheme = () => {
    if (isLight) {
      document.documentElement.classList.remove('light');
      localStorage.setItem('opensecx-theme', 'dark');
      setIsLight(false);
    } else {
      document.documentElement.classList.add('light');
      localStorage.setItem('opensecx-theme', 'light');
      setIsLight(true);
    }
  };

  return (
    <button
      onClick={toggleTheme}
      className="p-1.5 rounded-md transition-all flex items-center justify-center"
      style={{
        background: 'var(--border-light)',
        color: isLight ? '#A8C7FA' : 'var(--text-secondary)',
        border: '1px solid var(--border-medium)',
      }}
      title="Toggle Light/Dark Mode"
      onMouseEnter={(e) => {
        e.currentTarget.style.color = 'var(--text-primary)';
        e.currentTarget.style.background = 'var(--border-medium)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.color = isLight ? '#A8C7FA' : 'var(--text-secondary)';
        e.currentTarget.style.background = 'var(--border-light)';
      }}
    >
      {isLight ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
    </button>
  );
}
