import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import {
  Monitor,
  MonitorOff,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronLeft,
  ChevronRight,
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

function relativeTime(dateStr: string | null | undefined): { text: string; stale: 'ok' | 'warn' | 'error' } {
  if (!dateStr) return { text: 'never', stale: 'error' };
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  if (isNaN(then)) return { text: 'never', stale: 'error' };
  const diffMs = now - then;
  const diffMin = Math.floor(diffMs / 60000);
  const diffHr = Math.floor(diffMs / 3600000);
  const diffDay = Math.floor(diffMs / 86400000);

  let text: string;
  if (diffMin < 1) text = 'just now';
  else if (diffMin < 60) text = `${diffMin} minute${diffMin === 1 ? '' : 's'} ago`;
  else if (diffHr < 24) text = `${diffHr} hour${diffHr === 1 ? '' : 's'} ago`;
  else text = `${diffDay} day${diffDay === 1 ? '' : 's'} ago`;

  let stale: 'ok' | 'warn' | 'error' = 'ok';
  if (diffMin > 15) stale = 'warn';
  if (diffMin > 60) stale = 'error';

  return { text, stale };
}

function platformBadge(platform: string) {
  const p = platform.toLowerCase();
  if (p === 'macos' || p === 'darwin') {
    return (
      <Badge variant="secondary" className="gap-1 font-normal">
        macOS
      </Badge>
    );
  }
  if (p === 'windows') {
    return (
      <Badge variant="secondary" className="gap-1 font-normal">
        <Monitor className="h-3 w-3" />
        Windows
      </Badge>
    );
  }
  if (p === 'linux') {
    return (
      <Badge variant="secondary" className="gap-1 font-normal">
        Linux
      </Badge>
    );
  }
  return <Badge variant="secondary" className="font-normal">{platform}</Badge>;
}

export default function Devices() {
  const { auth } = useAuth();
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [cursors, setCursors] = useState<string[]>([]);
  const [currentCursor, setCurrentCursor] = useState<string | undefined>(undefined);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  const fetchDevices = (cursor?: string) => {
    if (!auth) return;
    setLoading(true);
    const params = new URLSearchParams({ limit: '20' });
    if (cursor) params.set('cursor', cursor);

    api(`/v1/devices?${params}`, { auth: auth.value })
      .then((data) => {
        const d = data as { devices: Device[]; next_cursor: string | null };
        setDevices(d.devices);
        setNextCursor(d.next_cursor);
        setError('');
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchDevices(currentCursor);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auth, currentCursor]);

  const goNext = () => {
    if (!nextCursor) return;
    setCursors((prev) => [...prev, currentCursor || '']);
    setCurrentCursor(nextCursor);
  };

  const goPrev = () => {
    if (cursors.length === 0) return;
    const prev = [...cursors];
    const last = prev.pop();
    setCursors(prev);
    setCurrentCursor(last || undefined);
  };

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Devices</h1>

      {error && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-2">
          {[...Array(5)].map((_, i) => (
            <div
              key={i}
              className="h-12 w-full rounded bg-muted animate-pulse"
            />
          ))}
        </div>
      ) : (
        <>
          <div className="rounded-md border shadow-sm overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Platform</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead>Device ID</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="h-32 text-center"
                    >
                      <div className="flex flex-col items-center gap-2 text-muted-foreground">
                        <MonitorOff className="h-8 w-8" />
                        <p className="text-sm font-medium">No devices enrolled yet</p>
                        <p className="text-xs">Devices will appear here once they enroll with an enrollment token.</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  devices.map((device) => {
                    const lastSeen = relativeTime(device.last_seen_at);
                    return (
                      <TableRow
                        key={device.device_id}
                        className="cursor-pointer transition-colors hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none"
                        tabIndex={0}
                        role="link"
                        aria-label={`View device ${device.hostname || device.device_id}`}
                        onClick={() =>
                          navigate(`/admin/devices/${device.device_id}`)
                        }
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            navigate(`/admin/devices/${device.device_id}`);
                          }
                        }}
                      >
                        <TableCell className="font-medium">
                          <div className="flex items-center gap-2">
                            <Monitor className="h-4 w-4 text-muted-foreground shrink-0" />
                            {device.hostname || 'Unknown'}
                          </div>
                        </TableCell>
                        <TableCell>{platformBadge(device.platform)}</TableCell>
                        <TableCell>
                          {device.status === 'active' ? (
                            <Badge className="gap-1 bg-emerald-100 text-emerald-800 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400 dark:hover:bg-emerald-900/30">
                              <CheckCircle2 className="h-3 w-3" />
                              Active
                            </Badge>
                          ) : (
                            <Badge variant="destructive" className="gap-1">
                              <XCircle className="h-3 w-3" />
                              {device.status}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-flex items-center gap-1.5 text-sm ${
                              lastSeen.stale === 'error'
                                ? 'text-destructive'
                                : lastSeen.stale === 'warn'
                                  ? 'text-yellow-600 dark:text-yellow-400'
                                  : 'text-muted-foreground'
                            }`}
                          >
                            <Clock className="h-3.5 w-3.5" />
                            {lastSeen.text}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {device.device_id.slice(0, 12)}...
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <Button
              variant="outline"
              size="sm"
              onClick={goPrev}
              disabled={cursors.length === 0}
              className="gap-1"
              aria-label="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={goNext}
              disabled={!nextCursor}
              className="gap-1"
              aria-label="Next page"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
