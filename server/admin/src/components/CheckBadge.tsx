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
      return val.type === 'bool' && val.value ? 'pass' : 'fail';
    case 'edr.present':
      return val.type === 'bool' && val.value ? 'pass' : 'warn';
    case 'mdm.enrolled':
      return val.type === 'bool' && val.value ? 'pass' : 'info';
    case 'screen_lock.timeout_minutes':
      return val.type === 'int' && val.value > 0 && val.value <= 15 ? 'pass' : 'fail';
    case 'password_policy.min_length':
      return val.type === 'int' && val.value >= 8 ? 'pass' : 'fail';
    case 'local_admin.is_admin':
      return val.type === 'bool' && !val.value ? 'pass' : 'warn';
    default:
      return 'info';
  }
}

function formatValue(val: CheckValueWire): string {
  switch (val.type) {
    case 'bool': return String(val.value);
    case 'int': return String(val.value);
    case 'string': return val.value;
    case 'string_list': return val.value.join(', ');
  }
}

/** Displays the raw check value as a plain text badge. */
export function CheckValueBadge({ checkValue }: { checkValue: CheckValueWire }) {
  return (
    <span className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-mono">
      {formatValue(checkValue)}
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
