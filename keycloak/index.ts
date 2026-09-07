// integrity-adapters/keycloak/index.ts
// Keycloak → VoidMetric adapter. Standalone Cloudflare Worker (cron).

import { resolveCell, type KeycloakEvent } from './mapping';
import { cellMaskedValue } from './f_norm';

export interface Env {
  KEYCLOAK_ADMIN_URL: string;
  KEYCLOAK_REALM: string;
  KEYCLOAK_CLIENT_ID: string;
  KEYCLOAK_CLIENT_SECRET: string;
  VOIDMETRIC_INGEST_URL: string;
  VOIDMETRIC_API_KEY: string;
  SCORING_WINDOW_SECONDS: string;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

const DEFAULT_WINDOW = 3600;

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const isManual = url.searchParams.get('run') === '1';
    const isCron = request.headers.get('cf-scheduled') === '1';

    if (!isManual && !isCron) {
      return new Response(JSON.stringify({ status: 'keycloak-adapter-ready' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      const windowSec = parseInt(env.SCORING_WINDOW_SECONDS || String(DEFAULT_WINDOW), 10);
      const now = Math.floor(Date.now() / 1000);
      const since = now - windowSec;

      const token = await getServiceAccountToken(env);
      const events = await fetchKeycloakEvents(env, token, since);

      const cellEvents: KeycloakEvent[][] = Array.from({ length: 4 }, () =>
        Array.from({ length: 3 }, () => [])
      );
      const colFrequency: number[] = [0, 0, 0];

      for (const event of events) {
        const cell = resolveCell(event);
        if (!cell) continue;
        cellEvents[cell.row][cell.col].push(event);
        colFrequency[cell.col]++;
      }

      const paddedStream = [];
      for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 3; j++) {
          paddedStream.push({
            maskedValue: cellMaskedValue(cellEvents[i][j]),
            row: i,
            col: j,
            lastTelemetryHeartbeat: now,
          });
        }
      }

      const totalFreq = colFrequency.reduce((a, b) => a + b, 0) || 1;
      const threatIntelVector = colFrequency.map(f => Math.min(1, f / (totalFreq / 3)));

      const response = await fetch(env.VOIDMETRIC_INGEST_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.VOIDMETRIC_API_KEY}`,
        },
        body: JSON.stringify({ blocks: [paddedStream], threatIntelVector, timestamp: now }),
      });

      const result = await response.json();
      console.log(`[KEYCLOAK-ADAPTER] ✅ ${JSON.stringify(result)}`);

      return new Response(JSON.stringify({
        status: 'ok',
        events_processed: events.length,
        cells_degraded: paddedStream.filter(n => n.maskedValue < 1.0).length,
        ingest_response: result,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });

    } catch (err) {
      console.error(`[KEYCLOAK-ADAPTER] ❌ ${(err as Error).message}`);
      return new Response(JSON.stringify({ error: 'Adapter error' }), { status: 500 });
    }
  },
};

async function getServiceAccountToken(env: Env): Promise<string> {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: env.KEYCLOAK_CLIENT_ID,
    client_secret: env.KEYCLOAK_CLIENT_SECRET,
  });
  const res = await fetch(
    `${env.KEYCLOAK_ADMIN_URL}/realms/${env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(10_000),
    }
  );
  if (!res.ok) throw new Error(`Keycloak token error: ${res.status}`);
  const json = await res.json();
  return json.access_token;
}

async function fetchKeycloakEvents(env: Env, token: string, since: number): Promise<KeycloakEvent[]> {
  const events: KeycloakEvent[] = [];
  let first = 0;
  const MAX = 1000;
  let currentToken = token;

  while (true) {
    const url = `${env.KEYCLOAK_ADMIN_URL}/realms/${env.KEYCLOAK_REALM}/events?first=${first}&max=${MAX}&time=gt:${since * 1000}`;
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${currentToken}`, 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });
    if (res.status === 401) {
      currentToken = await getServiceAccountToken(env);
      continue;
    }
    if (!res.ok) throw new Error(`Keycloak events error: ${res.status}`);

    const batch: KeycloakEvent[] = await res.json();
    events.push(...batch);

    if (batch.length < MAX) break;
    first += MAX;
  }

  return events;
}   