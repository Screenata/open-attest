import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { useAuth } from '@/lib/auth';
import { api, ApiError } from '@/lib/api';
import { ShieldCheck, KeyRound, AlertCircle, Loader2 } from 'lucide-react';

export default function Login() {
  const [secret, setSecret] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { setAuth } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const value = secret.trim();
    if (!value) {
      setError('Please enter a secret or API key.');
      setLoading(false);
      return;
    }

    try {
      // Try as admin secret first
      await api('/v1/admin/status', { auth: value });
      setAuth({ type: 'admin_secret', value });
      navigate('/admin/dashboard');
      return;
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        // Not an admin secret, try as API key
      } else {
        setError(err instanceof Error ? err.message : 'Connection error');
        setLoading(false);
        return;
      }
    }

    try {
      // Try as API key
      await api('/v1/devices', { auth: value });
      setAuth({ type: 'api_key', value });
      navigate('/admin/devices');
      return;
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError('Invalid credentials. Check your admin secret or API key.');
      } else {
        setError(err instanceof Error ? err.message : 'Connection error');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <Card className="w-full max-w-sm shadow-lg">
        <CardHeader className="text-center pb-2">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
            <ShieldCheck className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-2xl font-bold">open-attest</CardTitle>
          <CardDescription className="text-sm">
            Endpoint attestation admin console. Enter your admin secret or API key to continue.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="secret">Admin Secret or API Key</Label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="secret"
                  type="password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder="Enter your secret..."
                  className="pl-9"
                  autoFocus
                />
              </div>
            </div>
            {error && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
                <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Authenticating...
                </>
              ) : (
                'Sign In'
              )}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
