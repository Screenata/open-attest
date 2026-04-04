import { Badge } from '@/components/ui/badge';
import { CheckCircle2, XCircle, Info } from 'lucide-react';

const POSITIVE_CHECKS = new Set([
  'disk_encryption',
  'firewall',
  'screen_lock',
  'os_updates',
  'filevault',
  'gatekeeper',
  'sip',
  'antivirus',
]);

interface CheckBadgeProps {
  checkKey: string;
  checkValue: unknown;
}

export default function CheckBadge({ checkKey, checkValue }: CheckBadgeProps) {
  if (typeof checkValue === 'boolean') {
    const passing = POSITIVE_CHECKS.has(checkKey) ? checkValue : !checkValue;
    return (
      <Badge
        variant="outline"
        className={`gap-1.5 ${
          passing
            ? 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400'
            : 'border-red-300 bg-red-50 text-red-700 dark:border-red-700 dark:bg-red-900/20 dark:text-red-400'
        }`}
      >
        {passing ? (
          <CheckCircle2 className="h-3.5 w-3.5" />
        ) : (
          <XCircle className="h-3.5 w-3.5" />
        )}
        {String(checkValue)}
      </Badge>
    );
  }

  const displayValue = typeof checkValue === 'string' ? checkValue : JSON.stringify(checkValue);

  return (
    <Badge
      variant="outline"
      className="gap-1.5 border-blue-300 bg-blue-50 text-blue-700 dark:border-blue-700 dark:bg-blue-900/20 dark:text-blue-400"
    >
      <Info className="h-3.5 w-3.5" />
      {displayValue}
    </Badge>
  );
}
