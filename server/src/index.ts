import { Env } from './types';
import { apiError } from './errors';
import { route } from './router';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (err) {
      console.error('Unhandled error:', err);
      return apiError('INTERNAL_ERROR', 'An internal error occurred');
    }
  },
} satisfies ExportedHandler<Env>;
