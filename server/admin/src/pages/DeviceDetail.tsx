import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { CheckValueBadge, CheckStatusBadge, evaluateCompliance } from '@/components/CheckBadge';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import { toast } from 'sonner';
import {
  ArrowLeft,
  Monitor,
  Cpu,
  Tag,
  ShieldOff,
  Loader2,
  Fingerprint,
  Building2,
  Calendar,
  Clock,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

interface Device {
  agent_id: string;
  org_id: string;
  hostname: string;
  platform: string;
  platform_version: string;
  device_id: string;
  status: string;
  enrolled_at: string;
  last_seen_at: string;
}

type CheckValueWire =
  | { type: 'bool'; value: boolean }
  | { type: 'int'; value: number }
  | { type: 'string'; value: string }
  | { type: 'string_list'; value: string[] };

interface Check {
  device_id: string;
  check_key: string;
  check_value: CheckValueWire;
  observed_at: string;
  source: string;
}

export default function DeviceDetail() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const { auth, isAdmin } = useAuth();
  const navigate = useNavigate();
  const [device, setDevice] = useState<Device | null>(null);
  const [checks, setChecks] = useState<Check[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    if (!auth || !deviceId) return;
    setLoading(true);
    api(`/v1/devices/${deviceId}`, { auth: auth.value })
      .then((data) => {
        const d = data as { device: Device; checks: Check[] };
        setDevice(d.device);
        setChecks(d.checks);
        setError('');
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [auth, deviceId]);

  const handleRevoke = async () => {
    if (!auth || !device) return;
    if (!confirm(`Revoke agent ${device.hostname || device.agent_id}?`)) return;

    setRevoking(true);
    try {
      await api('/v1/admin/revoke', {
        method: 'POST',
        body: { agent_id: device.agent_id },
        auth: auth.value,
      });
      toast.success('Agent revoked');
      setDevice({ ...device, status: 'revoked' });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to revoke');
    } finally {
      setRevoking(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-6 w-48 rounded bg-muted animate-pulse" />
        <Card className="shadow-sm">
          <CardContent className="p-6">
            <div className="space-y-3">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="h-4 w-64 rounded bg-muted animate-pulse" />
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate('/admin/devices')} className="gap-1.5">
          <ArrowLeft className="h-4 w-4" />
          Back to Devices
        </Button>
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      </div>
    );
  }

  if (!device) return null;

  const infoFields = [
    { label: 'Hostname', value: device.hostname || 'N/A', icon: Monitor },
    { label: 'Platform', value: device.platform, icon: Cpu },
    { label: 'OS Version', value: device.platform_version || 'N/A', icon: Tag },
    {
      label: 'Status',
      value: device.status,
      icon: device.status === 'active' ? CheckCircle2 : XCircle,
      render: () => (
        device.status === 'active' ? (
          <Badge className="gap-1 bg-emerald-100 text-emerald-800 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400 dark:hover:bg-emerald-900/30">
            <CheckCircle2 className="h-3 w-3" />
            Active
          </Badge>
        ) : (
          <Badge variant="destructive" className="gap-1">
            <XCircle className="h-3 w-3" />
            {device.status}
          </Badge>
        )
      ),
    },
    { label: 'Agent ID', value: device.agent_id, icon: Fingerprint, mono: true },
    { label: 'Organization', value: device.org_id, icon: Building2 },
    {
      label: 'Enrolled At',
      value: new Date(device.enrolled_at).toLocaleString(),
      icon: Calendar,
    },
    {
      label: 'Last Seen',
      value: new Date(device.last_seen_at).toLocaleString(),
      icon: Clock,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate('/admin/devices')}
            className="gap-1.5"
          >
            <ArrowLeft className="h-4 w-4" />
            Back
          </Button>
          <div>
            <h1 className="text-2xl font-bold">
              {device.hostname || 'Unknown Device'}
            </h1>
            <p className="text-sm font-mono text-muted-foreground">
              {device.device_id}
            </p>
          </div>
        </div>
        {isAdmin && device.status === 'active' && (
          <Button
            variant="destructive"
            onClick={handleRevoke}
            disabled={revoking}
            className="gap-1.5"
          >
            {revoking ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Revoking...
              </>
            ) : (
              <>
                <ShieldOff className="h-4 w-4" />
                Revoke Agent
              </>
            )}
          </Button>
        )}
      </div>

      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle>Device Information</CardTitle>
          <CardDescription>
            Agent and device details
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 sm:grid-cols-2">
            {infoFields.map((field) => (
              <div key={field.label} className="flex items-start gap-3">
                <div className="mt-0.5 rounded-md bg-muted p-2">
                  <field.icon className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm text-muted-foreground">{field.label}</p>
                  {field.render ? (
                    field.render()
                  ) : (
                    <p className={`font-medium truncate ${field.mono ? 'font-mono text-sm' : ''}`}>
                      {field.value}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Separator />

      <div>
        <h2 className="text-lg font-semibold mb-4">Posture Checks</h2>
        {checks.length === 0 ? (
          <Card className="shadow-sm">
            <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Monitor className="h-8 w-8 mb-2" />
              <p className="text-sm font-medium">No posture checks reported yet</p>
              <p className="text-xs">Checks will appear here once the agent reports them.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="rounded-md border shadow-sm overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Check</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Observed At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {checks.map((check) => (
                  <TableRow key={check.check_key}>
                    <TableCell className="font-mono text-sm">
                      {check.check_key}
                    </TableCell>
                    <TableCell>
                      <CheckValueBadge checkValue={check.check_value} />
                    </TableCell>
                    <TableCell>
                      <CheckStatusBadge status={evaluateCompliance(check.check_key, check.check_value)} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{check.source}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(check.observed_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}
