import { Badge } from '@/components/ui/badge';
import { CheckCircle2, XCircle, AlertTriangle, Minus } from 'lucide-react';

export type CheckValueWire =
  | { type: 'bool'; value: boolean }
  | { type: 'int'; value: number }
  | { type: 'string'; value: string }
  | { type: 'string_list'; value: string[] };

export type Status = 'pass' | 'fail' | 'warn' | 'info';

export function evaluateCompliance(key: string, val: CheckValueWire): Status {
  switch (key) {
    case 'disk_encryption.enabled':
    case 'firewall.enabled':
    case 'screen_lock.password_required':
    case 'password.enabled':
    case 'auto_update.security_enabled':
      return val.type === 'bool' && val.value ? 'pass' : 'fail';
    case 'edr.present':
      return val.type === 'bool' && val.value ? 'pass' : 'warn';
    case 'mdm.enrolled':
    case 'screen_lock.managed_by_mdm':
      return val.type === 'bool' && val.value ? 'pass' : 'info';
    case 'ssh.daemon_enabled':
      return 'info';
    case 'screen_lock.timeout_minutes':
      if (val.type !== 'int') return 'fail';
      if (val.value === -1) return 'warn';
      if (val.value === 0) return 'fail';
      return val.value > 0 && val.value <= 15 ? 'pass' : 'fail';
    case 'password_policy.min_length':
      return val.type === 'int' && val.value >= 8 ? 'pass' : 'fail';
    case 'local_admin.is_admin':
      return val.type === 'bool' && !val.value ? 'pass' : 'warn';
    case 'ssh.authorized_key_count':
      if (val.type !== 'int') return 'info';
      return val.value > 0 ? 'warn' : 'pass';
    case 'users.local':
    case 'users.admins':
    case 'apps.installed':
      return 'info';
    default:
      return 'info';
  }
}

function formatScalar(val: CheckValueWire): string {
  switch (val.type) {
    case 'bool': return String(val.value);
    case 'int': return String(val.value);
    case 'string': return val.value;
    case 'string_list': return val.value.join(', ');
  }
}

/** Lists longer than this collapse behind a disclosure. */
const STRING_LIST_INLINE_LIMIT = 5;

/** Displays the raw check value as a plain text badge. Long string lists
 * collapse behind a <details> disclosure with an item-count summary. */
export function CheckValueBadge({ checkValue }: { checkValue: CheckValueWire }) {
  if (checkValue.type === 'string_list') {
    const items = checkValue.value;
    if (items.length === 0) {
      return <span className="text-xs text-muted-foreground">—</span>;
    }
    if (items.length <= STRING_LIST_INLINE_LIMIT) {
      return (
        <span className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-mono">
          {items.join(', ')}
        </span>
      );
    }
    return (
      <details className="max-w-md text-xs">
        <summary className="inline-flex cursor-pointer items-center rounded-md bg-muted px-2 py-0.5 font-mono hover:bg-muted/80">
          {items.length} items
        </summary>
        <ul className="mt-1 max-h-72 overflow-y-auto rounded-md border bg-muted/30 p-2 font-mono">
          {items.map((item, idx) => (
            <li key={idx} className="truncate py-0.5">{item}</li>
          ))}
        </ul>
      </details>
    );
  }
  return (
    <span className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-mono">
      {formatScalar(checkValue)}
    </span>
  );
}

const statusConfig: Record<Status, { icon: typeof CheckCircle2; label: string; className: string }> = {
  pass: {
    icon: CheckCircle2,
    label: 'Pass',
    className: 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400',
  },
  fail: {
    icon: XCircle,
    label: 'Fail',
    className: 'border-red-300 bg-red-50 text-red-700 dark:border-red-700 dark:bg-red-900/20 dark:text-red-400',
  },
  warn: {
    icon: AlertTriangle,
    label: 'Warning',
    className: 'border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-400',
  },
  info: {
    icon: Minus,
    label: '',
    className: 'border-transparent text-muted-foreground',
  },
};

/** Displays the compliance status as a colored badge. */
export function CheckStatusBadge({ status }: { status: Status }) {
  const config = statusConfig[status];
  const Icon = config.icon;

  if (status === 'info') {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  return (
    <Badge variant="outline" className={`gap-1 ${config.className}`}>
      <Icon className="h-3 w-3" />
      {config.label}
    </Badge>
  );
}

/** Combined component for backwards compat — not used in the table anymore. */
export default function CheckBadge({ checkKey, checkValue }: { checkKey: string; checkValue: CheckValueWire }) {
  const status = evaluateCompliance(checkKey, checkValue);
  return (
    <div className="flex items-center gap-2">
      <CheckValueBadge checkValue={checkValue} />
      <CheckStatusBadge status={status} />
    </div>
  );
}
