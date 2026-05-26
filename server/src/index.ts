import { Env } from './types';
import { apiError } from './errors';
import { route } from './router';
import { createDb } from './db';
import { pollReleases } from './cron/poll-releases';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (err) {
      console.error('Unhandled error:', err);
      return apiError('INTERNAL_ERROR', 'An internal error occurred');
    }
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    // Hourly: refresh the cached GitHub release manifest.
    ctx.waitUntil(
      (async () => {
        try {
          const db = createDb(env.DB);
          const result = await pollReleases(db);
          if (result.error) {
            console.warn('[cron] poll-releases:', result.error);
          } else {
            console.log(
              `[cron] poll-releases: fetched=${result.fetched}, upserted=${result.upserted.join(',') || 'none'}, dropped=${result.dropped.join(',') || 'none'}`,
            );
          }
        } catch (e) {
          console.error('[cron] poll-releases threw:', e);
        }
      })(),
    );
  },
} satisfies ExportedHandler<Env>;
