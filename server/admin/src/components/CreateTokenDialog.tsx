import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { toast } from 'sonner';
import {
  Ticket,
  Building2,
  Clock,
  Users,
  Copy,
  Check,
  Link as LinkIcon,
  Plus,
  Loader2,
} from 'lucide-react';

interface CreateTokenDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function CreateTokenDialog({
  open,
  onOpenChange,
}: CreateTokenDialogProps) {
  const { auth } = useAuth();
  const [orgId, setOrgId] = useState('');
  const [expiresInHours, setExpiresInHours] = useState(168); // 7 days default
  const [maxUses, setMaxUses] = useState(50);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ token: string; enroll_url: string; expires_at: string; max_uses: number } | null>(null);
  const [copiedField, setCopiedField] = useState<'token' | 'url' | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!auth) return;
    setLoading(true);
    try {
      const data = await api('/v1/admin/tokens', {
        method: 'POST',
        body: { org_id: orgId, expires_in_hours: expiresInHours, max_uses: maxUses },
        auth: auth.value,
      }) as { token: string; enroll_url: string; expires_at: string; max_uses: number };
      setResult(data);
      toast.success('Enrollment token created');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create token');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = (open: boolean) => {
    if (!open) {
      setResult(null);
      setOrgId('');
      setExpiresInHours(168);
      setMaxUses(50);
      setCopiedField(null);
    }
    onOpenChange(open);
  };

  const copyText = (text: string, field: 'token' | 'url') => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    toast.success(field === 'url' ? 'Enrollment link copied' : 'Token copied');
    setTimeout(() => setCopiedField(null), 2000);
  };

  const reset = () => {
    setResult(null);
    setOrgId('');
    setExpiresInHours(168);
    setMaxUses(50);
    setCopiedField(null);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Ticket className="h-5 w-5" />
            Create Enrollment Token
          </DialogTitle>
          <DialogDescription>
            Generate a link to enroll devices. Copy and share it now — the full link is shown only at creation. If lost, create a new token.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="space-y-4">
            {/* Enrollment URL — primary, copy this */}
            <div className="rounded-md border p-4 bg-muted">
              <Label className="text-xs text-muted-foreground flex items-center gap-1.5">
                <LinkIcon className="h-3 w-3" />
                Enrollment Link
              </Label>
              <div className="mt-1 flex items-center gap-2">
                <code className="flex-1 text-sm break-all">{result.enroll_url}</code>
                <Button variant="outline" size="sm" onClick={() => copyText(result.enroll_url, 'url')} className="gap-1.5 shrink-0">
                  {copiedField === 'url' ? (
                    <><Check className="h-4 w-4 text-emerald-600" /> Copied</>
                  ) : (
                    <><Copy className="h-4 w-4" /> Copy</>
                  )}
                </Button>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                Send this link to employees now — it won't be shown again after you close this dialog. They'll see download and install instructions.
              </p>
            </div>

            {/* CLI token — secondary */}
            <div className="rounded-md border p-3">
              <Label className="text-xs text-muted-foreground">CLI Token (for manual enrollment)</Label>
              <div className="mt-1 flex items-center gap-2">
                <code className="flex-1 text-xs break-all text-muted-foreground">{result.token}</code>
                <Button variant="ghost" size="sm" onClick={() => copyText(result.token, 'token')} className="gap-1 shrink-0 h-7 text-xs">
                  {copiedField === 'token' ? (
                    <><Check className="h-3 w-3 text-emerald-600" /> Copied</>
                  ) : (
                    <><Copy className="h-3 w-3" /> Copy</>
                  )}
                </Button>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              <span>Expires {new Date(result.expires_at).toLocaleDateString()}</span>
              <span>{result.max_uses === 1 ? 'Single use' : `Up to ${result.max_uses} devices`}</span>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={reset} className="gap-1.5">
                <Plus className="h-4 w-4" />
                Create Another
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="orgId" className="flex items-center gap-1.5">
                <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
                Organization ID
              </Label>
              <Input
                id="orgId"
                value={orgId}
                onChange={(e) => setOrgId(e.target.value)}
                placeholder="my-org"
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="maxUses" className="flex items-center gap-1.5">
                  <Users className="h-3.5 w-3.5 text-muted-foreground" />
                  Max devices
                </Label>
                <Input
                  id="maxUses"
                  type="number"
                  min={1}
                  max={1000}
                  value={maxUses}
                  onChange={(e) => setMaxUses(parseInt(e.target.value) || 1)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="expiresInHours" className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                  Expires in (hours)
                </Label>
                <Input
                  id="expiresInHours"
                  type="number"
                  min={1}
                  value={expiresInHours}
                  onChange={(e) => setExpiresInHours(parseInt(e.target.value) || 24)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button type="submit" disabled={loading || !orgId} className="gap-1.5">
                {loading ? (
                  <><Loader2 className="h-4 w-4 animate-spin" /> Creating...</>
                ) : (
                  <><Plus className="h-4 w-4" /> Create Enrollment Token</>
                )}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
