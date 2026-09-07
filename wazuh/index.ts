// integrity-adapters/wazuh/index.ts
// Wazuh → VoidMetric adapter. Standalone Cloudflare Worker (cron).
// Polls Wazuh API, builds 12-node PaddedStreamNode[], POSTs to void.fzoirm.com.

import { resolveCell, type WazuhAlert } from './mapping';
import { cellMaskedValue } from './f_norm';

export interface Env {
  WAZUH_API_URL: string;
  WAZUH_API_KEY: string;
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
      return new Response(JSON.stringify({ status: 'wazuh-adapter-ready' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      const windowSec = parseInt(env.SCORING_WINDOW_SECONDS || String(DEFAULT_WINDOW), 10);
      const now = Math.floor(Date.now() / 1000);
      const since = now - windowSec;

      const alerts = await fetchWazuhAlerts(env, since);

      const cellAlerts: WazuhAlert[][] = Array.from({ length: 4 }, () =>
        Array.from({ length: 3 }, () => [])
      );
      const colFrequency: number[] = [0, 0, 0];

      for (const alert of alerts) {
        const cell = resolveCell(alert);
        if (!cell) continue;
        cellAlerts[cell.row][cell.col].push(alert);
        colFrequency[cell.col]++;
      }

      const paddedStream = [];
      for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 3; j++) {
          paddedStream.push({
            maskedValue: cellMaskedValue(cellAlerts[i][j]),
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
      console.log(`[WAZUH-ADAPTER] ✅ ${JSON.stringify(result)}`);

      return new Response(JSON.stringify({
        status: 'ok',
        alerts_processed: alerts.length,
        cells_degraded: paddedStream.filter(n => n.maskedValue < 1.0).length,
        ingest_response: result,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });

    } catch (err) {
      console.error(`[WAZUH-ADAPTER] ❌ ${(err as Error).message}`);
      return new Response(JSON.stringify({ error: 'Adapter error' }), { status: 500 });
    }
  },
};

async function fetchWazuhAlerts(env: Env, since: number): Promise<WazuhAlert[]> {
  const items: WazuhAlert[] = [];
  let offset = 0;
  const LIMIT = 1000;

  const dateFilter = `dateFilter=gte@timestamp:${new Date(since * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '')}`;

  while (true) {
    const url = `${env.WAZUH_API_URL}/alerts?origin=agent&limit=${LIMIT}&offset=${offset}&${dateFilter}`;
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${env.WAZUH_API_KEY}`, 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`Wazuh API error: ${res.status} ${res.statusText}`);

    const json = await res.json();
    const batch: WazuhAlert[] = json.data?.items || json.items || [];
    items.push(...batch);

    if (batch.length < LIMIT) break;
    offset += LIMIT;
  }

  return items;
}   