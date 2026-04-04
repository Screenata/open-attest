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
  Key,
  Building2,
  Tag,
  Copy,
  Check,
  AlertTriangle,
  Plus,
  Loader2,
} from 'lucide-react';

interface CreateApiKeyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function CreateApiKeyDialog({
  open,
  onOpenChange,
}: CreateApiKeyDialogProps) {
  const { auth } = useAuth();
  const [orgId, setOrgId] = useState('');
  const [label, setLabel] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ api_key: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!auth) return;
    setLoading(true);
    try {
      const data = await api('/v1/admin/api-keys', {
        method: 'POST',
        body: { org_id: orgId, label: label || undefined },
        auth: auth.value,
      });
      setResult(data as { api_key: string });
      toast.success('API key created');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create API key');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = (open: boolean) => {
    if (!open) {
      setResult(null);
      setOrgId('');
      setLabel('');
      setCopied(false);
    }
    onOpenChange(open);
  };

  const copyKey = () => {
    if (result) {
      navigator.clipboard.writeText(result.api_key);
      setCopied(true);
      toast.success('API key copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Create API Key
          </DialogTitle>
          <DialogDescription>
            Generate an API key for programmatic access.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="space-y-4">
            <div className="rounded-md border p-4 bg-muted">
              <Label className="text-xs text-muted-foreground">API Key</Label>
              <div className="mt-1 flex items-center gap-2">
                <code className="flex-1 text-sm break-all">
                  {result.api_key}
                </code>
                <Button variant="outline" size="sm" onClick={copyKey} className="gap-1.5 shrink-0">
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
            <p className="flex items-center gap-2 text-sm font-medium text-destructive">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              Save this key — it cannot be retrieved again.
            </p>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => {
                  setResult(null);
                  setOrgId('');
                  setLabel('');
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
              <Label htmlFor="apiKeyOrgId" className="flex items-center gap-1.5">
                <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
                Organization ID
              </Label>
              <Input
                id="apiKeyOrgId"
                value={orgId}
                onChange={(e) => setOrgId(e.target.value)}
                placeholder="my-org"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="apiKeyLabel" className="flex items-center gap-1.5">
                <Tag className="h-3.5 w-3.5 text-muted-foreground" />
                Label (optional)
              </Label>
              <Input
                id="apiKeyLabel"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="production-read-only"
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
                    Create API Key
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
