import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import CreateTokenDialog from '@/components/CreateTokenDialog';
import CreateApiKeyDialog from '@/components/CreateApiKeyDialog';
import {
  Monitor,
  MonitorOff,
  ShieldCheck,
  ShieldAlert,
  Wifi,
  Ticket,
  Plus,
  Clock,
  ArrowRight,
} from 'lucide-react';

interface Stats {
  devices_total: number;
  devices_compliant: number;
  devices_non_compliant: number;
  devices_online: number;
  devices_offline: number;
  agents_revoked: number;
  tokens_available: number;
  tokens_total: number;
}

interface StatusResponse {
  status: string;
  version: string;
  stats: Stats;
}

export default function Dashboard() {
  const { auth, isAdmin } = useAuth();
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tokenDialogOpen, setTokenDialogOpen] = useState(false);
  const [apiKeyDialogOpen, setApiKeyDialogOpen] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    if (!auth || !isAdmin) return;
    setLoading(true);
    api('/v1/admin/status', { auth: auth.value })
      .then((data) => {
        setStatus(data as StatusResponse);
        setLastUpdated(new Date());
        setError('');
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [auth, isAdmin]);

  if (!isAdmin) {
    return (
      <div className="rounded-md border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
        Dashboard is only available with admin secret authentication.
      </div>
    );
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(8)].map((_, i) => (
            <Card key={i} className="shadow-sm">
              <CardHeader className="pb-2">
                <div className="h-4 w-24 rounded bg-muted animate-pulse" />
              </CardHeader>
              <CardContent>
                <div className="h-8 w-16 rounded bg-muted animate-pulse" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      </div>
    );
  }

  const s = status?.stats;

  const complianceRate = s && s.devices_total > 0
    ? Math.round((s.devices_compliant / s.devices_total) * 100)
    : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            open-attest v{status?.version}
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => setTokenDialogOpen(true)} className="gap-1.5">
            <Plus className="h-4 w-4" />
            Create Enrollment Token
          </Button>
          <Button variant="outline" onClick={() => setApiKeyDialogOpen(true)} className="gap-1.5">
            <Plus className="h-4 w-4" />
            Create API Key
          </Button>
        </div>
      </div>

      {/* Devices section */}
      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground uppercase tracking-wider">Devices</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card className="shadow-sm transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>Total Devices</CardDescription>
              <div className="rounded-md p-2 bg-blue-100 dark:bg-blue-900/30">
                <Monitor className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{s?.devices_total ?? 0}</div>
            </CardContent>
          </Card>

          <Card className="shadow-sm transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>Compliant</CardDescription>
              <div className="rounded-md p-2 bg-emerald-100 dark:bg-emerald-900/30">
                <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{s?.devices_compliant ?? 0}</div>
              {s && s.devices_total > 0 && (
                <p className="text-xs text-muted-foreground mt-1">{complianceRate}% compliance rate</p>
              )}
            </CardContent>
          </Card>

          <Card className="shadow-sm transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>Non-Compliant</CardDescription>
              <div className="rounded-md p-2 bg-red-100 dark:bg-red-900/30">
                <ShieldAlert className="h-4 w-4 text-red-600 dark:text-red-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{s?.devices_non_compliant ?? 0}</div>
            </CardContent>
          </Card>

          <Card className="shadow-sm transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>Online Now</CardDescription>
              <div className="rounded-md p-2 bg-sky-100 dark:bg-sky-900/30">
                <Wifi className="h-4 w-4 text-sky-600 dark:text-sky-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{s?.devices_online ?? 0}</div>
              <p className="text-xs text-muted-foreground mt-1">
                {s?.devices_offline ?? 0} offline
              </p>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Enrollment section */}
      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground uppercase tracking-wider">Enrollment</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card className="shadow-sm transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>Available Tokens</CardDescription>
              <div className="rounded-md p-2 bg-amber-100 dark:bg-amber-900/30">
                <Ticket className="h-4 w-4 text-amber-600 dark:text-amber-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{s?.tokens_available ?? 0}</div>
              <p className="text-xs text-muted-foreground mt-1">
                {s?.tokens_total ?? 0} total
              </p>
            </CardContent>
          </Card>

          <Card className="shadow-sm transition-shadow hover:shadow-md">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>Revoked Agents</CardDescription>
              <div className="rounded-md p-2 bg-gray-100 dark:bg-gray-800/50">
                <MonitorOff className="h-4 w-4 text-gray-600 dark:text-gray-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{s?.agents_revoked ?? 0}</div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Quick links */}
      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle className="text-base">Quick Links</CardTitle>
        </CardHeader>
        <CardContent className="flex gap-4">
          <Link
            to="/admin/devices"
            className="inline-flex items-center gap-1.5 text-sm text-primary underline-offset-4 hover:underline transition-colors"
          >
            View all devices
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
          <Link
            to="/admin/credentials"
            className="inline-flex items-center gap-1.5 text-sm text-primary underline-offset-4 hover:underline transition-colors"
          >
            Manage credentials
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </CardContent>
      </Card>

      {lastUpdated && (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Clock className="h-3 w-3" />
          Last updated {lastUpdated.toLocaleTimeString()}
        </p>
      )}

      <CreateTokenDialog open={tokenDialogOpen} onOpenChange={setTokenDialogOpen} />
      <CreateApiKeyDialog open={apiKeyDialogOpen} onOpenChange={setApiKeyDialogOpen} />
    </div>
  );
}
