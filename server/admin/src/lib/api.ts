const BASE = '';

export async function api(
  path: string,
  options: { method?: string; body?: unknown; auth: string },
) {
  const res = await fetch(`${BASE}${path}`, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${options.auth}`,
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: { message: res.statusText } }));
    const errObj = err as { error?: { message?: string } };
    throw new ApiError(errObj.error?.message || res.statusText, res.status);
  }
  return res.json() as Promise<unknown>;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}
