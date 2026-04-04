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
  Copy,
  Check,
  AlertTriangle,
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
  const [expiresInHours, setExpiresInHours] = useState(24);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ token: string; expires_at: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!auth) return;
    setLoading(true);
    try {
      const data = await api('/v1/admin/tokens', {
        method: 'POST',
        body: { org_id: orgId, expires_in_hours: expiresInHours },
        auth: auth.value,
      });
      setResult(data as { token: string; expires_at: string });
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
      setExpiresInHours(24);
      setCopied(false);
    }
    onOpenChange(open);
  };

  const copyToken = () => {
    if (result) {
      navigator.clipboard.writeText(result.token);
      setCopied(true);
      toast.success('Token copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Ticket className="h-5 w-5" />
            Create Enrollment Token
          </DialogTitle>
          <DialogDescription>
            Generate a one-time enrollment token for a new device.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="space-y-4">
            <div className="rounded-md border p-4 bg-muted">
              <Label className="text-xs text-muted-foreground">
                Enrollment Token
              </Label>
              <div className="mt-1 flex items-center gap-2">
                <code className="flex-1 text-sm break-all">{result.token}</code>
                <Button variant="outline" size="sm" onClick={copyToken} className="gap-1.5 shrink-0">
                  {copied ? (
                    <>
                      <Check className="h-4 w-4 text-emerald-600" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-4 w-4" />
                      Copy
                    </>
                  )}
                </Button>
              </div>
            </div>
            <p className="text-sm text-muted-foreground">
              Expires: {new Date(result.expires_at).toLocaleString()}
            </p>
            <p className="flex items-center gap-2 text-sm font-medium text-destructive">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              This token can only be used once.
            </p>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => {
                  setResult(null);
                  setOrgId('');
                  setExpiresInHours(24);
                  setCopied(false);
                }}
                className="gap-1.5"
              >
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
            <DialogFooter>
              <Button type="submit" disabled={loading || !orgId} className="gap-1.5">
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Creating...
                  </>
                ) : (
                  <>
                    <Plus className="h-4 w-4" />
                    Create Enrollment Token
                  </>
                )}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
