import { ErrorCode, ErrorEnvelope } from './types';

const STATUS_MAP: Record<ErrorCode, number> = {
  INVALID_REQUEST: 400,
  VALIDATION_ERROR: 400,
  INVALID_SIGNATURE: 401,
  FORBIDDEN: 403,
  AGENT_REVOKED: 403,
  TOKEN_EXPIRED: 400,
  TOKEN_ALREADY_USED: 400,
  NOT_FOUND: 404,
  ALREADY_ENROLLED: 409,
  INTERNAL_ERROR: 500,
};

export function apiError(
  code: ErrorCode,
  message: string,
  details: Record<string, unknown> = {},
): Response {
  const body: ErrorEnvelope = {
    error: { code, message, details },
  };
  return new Response(JSON.stringify(body), {
    status: STATUS_MAP[code] ?? 500,
    headers: { 'Content-Type': 'application/json' },
  });
}
