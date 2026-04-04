import { useEffect, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import CreateApiKeyDialog from '@/components/CreateApiKeyDialog';
import {
  Key,
  KeyRound,
  Ticket,
  Trash2,
  Plus,
  CheckCircle2,
  XCircle,
  Clock,
  AlertCircle,
  Loader2,
} from 'lucide-react';

type ApiKeyInfo = {
  key_hash_prefix: string;
  org_id: string;
  label: string | null;
  created_at: string;
};

type TokenInfo = {
  id: string;
  token_prefix: string;
  org_id: string;
  used: boolean;
  revoked: boolean;
  expires_at: string;
  created_at: string;
  expired: boolean;
};

export default function ApiKeys() {
  const { auth } = useAuth();
  const [apiKeys, setApiKeys] = useState<ApiKeyInfo[]>([]);
  const [tokens, setTokens] = useState<TokenInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<'keys' | 'tokens'>('keys');
  const [createKeyOpen, setCreateKeyOpen] = useState(false);
  const [deletingKey, setDeletingKey] = useState<string | null>(null);

  const isAdmin = auth?.type === 'admin_secret';

  async function loadData() {
    if (!auth || !isAdmin) return;
    setLoading(true);
    setError('');
    try {
      const [keysRes, tokensRes] = await Promise.all([
        api('/v1/admin/api-keys', { auth: auth.value }) as Promise<{ api_keys?: ApiKeyInfo[] }>,
        api('/v1/admin/tokens', { auth: auth.value }) as Promise<{ tokens?: TokenInfo[] }>,
      ]);
      setApiKeys(keysRes.api_keys || []);
      setTokens(tokensRes.tokens || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load credentials');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auth]);

  async function deleteKey(prefix: string) {
    if (!auth || !confirm('Delete this API key? Any systems using it will lose access.')) return;
    setDeletingKey(prefix);
    try {
      await api('/v1/admin/api-keys', {
        method: 'DELETE',
        body: { key_hash_prefix: prefix },
        auth: auth.value,
      });
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete API key');
    } finally {
      setDeletingKey(null);
    }
  }

  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
        <AlertCircle className="h-8 w-8 mb-2" />
        <p className="font-medium">API key management requires admin secret access.</p>
      </div>
    );
  }

  function tokenStatus(t: TokenInfo) {
    if (t.used) return (
      <Badge variant="secondary" className="gap-1">
        <CheckCircle2 className="h-3 w-3" />
        Used
      </Badge>
    );
    if (t.revoked) return (
      <Badge variant="destructive" className="gap-1">
        <XCircle className="h-3 w-3" />
        Revoked
      </Badge>
    );
    if (t.expired) return (
      <Badge variant="outline" className="gap-1 text-muted-foreground">
        <Clock className="h-3 w-3" />
        Expired
      </Badge>
    );
    return (
      <Badge className="gap-1 bg-emerald-100 text-emerald-800 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400 dark:hover:bg-emerald-900/30">
        <CheckCircle2 className="h-3 w-3" />
        Available
      </Badge>
    );
  }

  function timeAgo(iso: string) {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Credentials</h1>
      </div>

      <div className="flex gap-2 border-b pb-2">
        <Button
          variant={tab === 'keys' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => setTab('keys')}
          className="gap-1.5 transition-colors"
        >
          <Key className="h-4 w-4" />
          API Keys ({apiKeys.length})
        </Button>
        <Button
          variant={tab === 'tokens' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => setTab('tokens')}
          className="gap-1.5 transition-colors"
        >
          <Ticket className="h-4 w-4" />
          Enrollment Tokens ({tokens.length})
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 bg-destructive/10 text-destructive px-4 py-3 rounded-md">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-12 w-full rounded bg-muted animate-pulse" />
          ))}
        </div>
      ) : tab === 'keys' ? (
        <Card className="shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-lg">API Keys</CardTitle>
            <Button size="sm" onClick={() => setCreateKeyOpen(true)} className="gap-1.5">
              <Plus className="h-4 w-4" />
              Create API Key
            </Button>
            <CreateApiKeyDialog open={createKeyOpen} onOpenChange={(open) => { setCreateKeyOpen(open); if (!open) loadData(); }} />
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Org</TableHead>
                  <TableHead>Key Hash</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead><span className="sr-only">Actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apiKeys.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="h-24 text-center">
                      <div className="flex flex-col items-center gap-2 text-muted-foreground">
                        <KeyRound className="h-6 w-6" />
                        <p className="text-sm font-medium">No API keys yet</p>
                        <p className="text-xs">Create one to enable programmatic access.</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  apiKeys.map((k) => (
                    <TableRow key={k.key_hash_prefix}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <KeyRound className="h-4 w-4 text-muted-foreground shrink-0" />
                          {k.org_id}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {k.key_hash_prefix}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{timeAgo(k.created_at)}</TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="gap-1.5 text-destructive hover:text-destructive hover:bg-destructive/10 transition-colors"
                          onClick={() => deleteKey(k.key_hash_prefix)}
                          disabled={deletingKey === k.key_hash_prefix}
                          aria-label={`Delete API key for ${k.org_id}`}
                        >
                          {deletingKey === k.key_hash_prefix ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <Trash2 className="h-4 w-4" />
                          )}
                          Delete
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card className="shadow-sm">
          <CardHeader>
            <CardTitle className="text-lg">Enrollment Tokens</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Token</TableHead>
                  <TableHead>Org</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="h-24 text-center">
                      <div className="flex flex-col items-center gap-2 text-muted-foreground">
                        <Ticket className="h-6 w-6" />
                        <p className="text-sm font-medium">No enrollment tokens yet</p>
                        <p className="text-xs">Create an enrollment token from the Dashboard to enroll new devices.</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  tokens.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="font-mono text-xs">
                        <div className="flex items-center gap-2">
                          <Ticket className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                          {t.token_prefix}
                        </div>
                      </TableCell>
                      <TableCell>{t.org_id}</TableCell>
                      <TableCell>{tokenStatus(t)}</TableCell>
                      <TableCell className={t.expired ? 'text-muted-foreground' : ''}>
                        {new Date(t.expires_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{timeAgo(t.created_at)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
