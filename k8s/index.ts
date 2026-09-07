// integrity-adapters/k8s/index.ts
// K8s → VoidMetric adapter. Standalone Cloudflare Worker (cron).

import { resolveCell, type K8sSignal } from './mapping';
import { cellMaskedValue } from './f_norm';

export interface Env {
  K8S_API_URL: string;
  K8S_SERVICE_ACCOUNT_TOKEN: string;
  K8S_NAMESPACES: string;
  K8S_CPU_LIMIT_MILLI?: string;    // default 1000 (1 core)
  K8S_MEM_LIMIT_BYTES?: string;    // default 1073741824 (1 GiB)
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
      return new Response(JSON.stringify({ status: 'k8s-adapter-ready' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      const windowSec = parseInt(env.SCORING_WINDOW_SECONDS || String(DEFAULT_WINDOW), 10);
      const now = Math.floor(Date.now() / 1000);
      const since = now - windowSec;
      const namespaces = (env.K8S_NAMESPACES || '').split(',').map(n => n.trim()).filter(n => n.length > 0);
      if (namespaces.length === 0) {
        return new Response(JSON.stringify({ error: 'K8S_NAMESPACES not configured' }), { status: 500 });
      }

      const signals: K8sSignal[] = [];

      for (const ns of namespaces) {
        const events = await fetchK8sEvents(env, ns, since);
        for (const e of events) signals.push({ kind: 'event', data: e });
      }

      const metrics = await fetchK8sMetrics(env, namespaces);
      for (const m of metrics) signals.push({ kind: 'metric', data: m });

      // TODO: Wire to actual audit backend (Elasticsearch, Loki, etc.)
      // const auditEntries = await fetchK8sAuditDenials(env, since);
      // for (const a of auditEntries) signals.push({ kind: 'audit', data: a });

      const cellSignals: K8sSignal[][] = Array.from({ length: 4 }, () =>
        Array.from({ length: 3 }, () => [])
      );
      const colFrequency: number[] = [0, 0, 0];

      for (const signal of signals) {
        const cell = resolveCell(signal);
        if (!cell) continue;
        cellSignals[cell.row][cell.col].push(signal);
        colFrequency[cell.col]++;
      }

      const paddedStream = [];
      for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 3; j++) {
          paddedStream.push({
            maskedValue: cellMaskedValue(cellSignals[i][j]),
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
      console.log(`[K8S-ADAPTER] ✅ ${JSON.stringify(result)}`);

      return new Response(JSON.stringify({
        status: 'ok',
        signals_processed: signals.length,
        cells_degraded: paddedStream.filter(n => n.maskedValue < 1.0).length,
        ingest_response: result,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });

    } catch (err) {
      console.error(`[K8S-ADAPTER] ❌ ${(err as Error).message}`);
      return new Response(JSON.stringify({ error: 'Adapter error' }), { status: 500 });
    }
  },
};

function parseCpuMilli(value: string): number {
  if (value.endsWith('m')) return parseInt(value, 10);
  return parseInt(value, 10) * 1000;
}

async function fetchK8sEvents(env: Env, namespace: string, since: number) {
  const items: any[] = [];
  let continueToken: string | undefined;

  do {
    let url = `${env.K8S_API_URL}/api/v1/namespaces/${namespace}/events?limit=100`;
    if (continueToken) url += `&continue=${encodeURIComponent(continueToken)}`;

    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${env.K8S_SERVICE_ACCOUNT_TOKEN}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`K8s events error: ${res.status}`);

    const json = await res.json();
    items.push(...(json.items || []));
    continueToken = json.metadata?.continue;
  } while (continueToken);

  return items
    .filter((e: any) => e.type === 'Warning')
    .filter((e: any) => new Date(e.lastTimestamp).getTime() / 1000 >= since)
    .map((e: any) => ({
      type: e.type,
      reason: e.reason,
      message: e.message,
      object: e.involvedObject,
      lastTimestamp: e.lastTimestamp,
      count: e.count || 1,
    }));
}

async function fetchK8sMetrics(env: Env, namespaces: string[]) {
  const allMetrics = [];
  const cpuCap = parseInt(env.K8S_CPU_LIMIT_MILLI || '1000', 10);
  const memCap = parseInt(env.K8S_MEM_LIMIT_BYTES || '1073741824', 10);

  for (const ns of namespaces) {
    const url = `${env.K8S_API_URL}/apis/metrics.k8s.io/v1beta1/namespaces/${ns}/pods`;
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${env.K8S_SERVICE_ACCOUNT_TOKEN}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      console.warn(`[K8S-ADAPTER] ⚠️ Metrics ${res.status} for namespace ${ns}, skipping`);
      continue;
    }
    const json = await res.json();
    for (const item of json.items || []) {
      allMetrics.push({
        namespace: ns,
        name: item.metadata.name,
        kind: 'pod',
        cpu: { usage: parseCpuMilli(item.usage.cpu || '0'), capacity: cpuCap },
        memory: { usage: parseInt(item.usage.memory || '0', 10), capacity: memCap },
      });
    }
  }
  return allMetrics;
}   