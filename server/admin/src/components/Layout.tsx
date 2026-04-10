import { Link, Outlet, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/lib/auth';
import { useEffect, useState } from 'react';
import {
  LayoutDashboard,
  Monitor,
  Key,
  LogOut,
  Sun,
  Moon,
} from 'lucide-react';

function GithubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
    </svg>
  );
}

function ThemeToggle() {
  const [dark, setDark] = useState(() => {
    if (typeof window === 'undefined') return false;
    return document.documentElement.classList.contains('dark');
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setDark(!dark)}
      className="h-8 w-8 text-muted-foreground hover:text-foreground"
      aria-label="Toggle theme"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </Button>
  );
}

export default function Layout() {
  const { auth, logout, isAdmin } = useAuth();
  const location = useLocation();

  const isActive = (path: string) =>
    location.pathname === path || location.pathname.startsWith(path + '/');

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="mx-auto flex h-12 max-w-6xl items-center justify-between px-4">
          {/* Left: logo + nav */}
          <div className="flex items-center gap-1">
            <Link
              to="/admin/dashboard"
              className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-sm font-semibold tracking-tight transition-colors hover:bg-accent"
            >
              <img src="/admin/logo.svg" alt="Open Attest" className="h-4 w-4" />
              Open Attest
            </Link>

            <nav className="ml-1 flex items-center">
              {isAdmin && (
                <NavLink to="/admin/dashboard" active={isActive('/admin/dashboard')}>
                  <LayoutDashboard className="h-3.5 w-3.5" />
                  Dashboard
                </NavLink>
              )}
              <NavLink to="/admin/devices" active={isActive('/admin/devices')}>
                <Monitor className="h-3.5 w-3.5" />
                Devices
              </NavLink>
              {isAdmin && (
                <NavLink to="/admin/credentials" active={isActive('/admin/credentials')}>
                  <Key className="h-3.5 w-3.5" />
                  Credentials
                </NavLink>
              )}
            </nav>
          </div>

          {/* Right: actions */}
          <div className="flex items-center gap-0.5">
            <span className="mr-1 rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
              {auth?.type === 'admin_secret' ? 'Admin' : 'API Key'}
            </span>
            <a
              href="https://github.com/screenata/open-attest"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex"
            >
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-muted-foreground hover:text-foreground"
                aria-label="GitHub"
              >
                <GithubIcon className="h-4 w-4" />
              </Button>
            </a>
            <ThemeToggle />
            <Button
              variant="ghost"
              size="icon"
              onClick={logout}
              className="h-8 w-8 text-muted-foreground hover:text-foreground"
              aria-label="Logout"
            >
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}

function NavLink({
  to,
  active,
  children,
}: {
  to: string;
  active: boolean;
  children: React.ReactNode;
}) {
  return (
    <Link
      to={to}
      className={`relative flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors ${
        active
          ? 'font-medium text-foreground'
          : 'text-muted-foreground hover:text-foreground hover:bg-accent'
      }`}
    >
      {children}
      {active && (
        <span className="absolute -bottom-[9px] left-2 right-2 h-[2px] rounded-full bg-primary" />
      )}
    </Link>
  );
}
