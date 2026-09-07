// Dev tool — verifies scoring locally. Production path: adapters/k8s/index.ts (cron).
// Standalone K8s scoring — no Cloudflare, no queue, no KV.
// Usage: npx tsx examples/k8s-standalone.ts
// Requires: K8S_API_URL, K8S_SERVICE_ACCOUNT_TOKEN, K8S_NAMESPACES in .env

import 'dotenv/config';
import { runScoringEngine, type PaddedStreamNode } from '../src/lib/index';
import { resolveCell, type K8sSignal } from '../adapters/k8s/mapping';
import { cellMaskedValue } from '../adapters/k8s/f_norm';

function parseCpuMilli(value: string): number {
  if (value.endsWith('m')) return parseInt(value, 10);
  return parseInt(value, 10) * 1000;
}

async function main() {
  const now = Math.floor(Date.now() / 1000);
  const since = now - 3600;
  const namespaces = (process.env.K8S_NAMESPACES || '').split(',').map(n => n.trim()).filter(n => n.length > 0);
  if (namespaces.length === 0) {
    console.error('K8S_NAMESPACES not configured');
    process.exit(1);
  }
  const headers = { 'Authorization': `Bearer ${process.env.K8S_SERVICE_ACCOUNT_TOKEN!}` };

  const signals: K8sSignal[] = [];

  // Events
  for (const ns of namespaces) {
    const res = await fetch(`${process.env.K8S_API_URL}/api/v1/namespaces/${ns}/events?limit=100`, { headers });
    if (!res.ok) continue;
    const json = await res.json();
    for (const e of json.items || []) {
      if (e.type !== 'Warning') continue;
      if (new Date(e.lastTimestamp).getTime() / 1000 < since) continue;
      signals.push({
        kind: 'event',
        data: {
          type: e.type, reason: e.reason, message: e.message,
          object: e.involvedObject, lastTimestamp: e.lastTimestamp, count: e.count || 1,
        },
      });
    }
  }

  // Metrics
  for (const ns of namespaces) {
    const res = await fetch(`${process.env.K8S_API_URL}/apis/metrics.k8s.io/v1beta1/namespaces/${ns}/pods`, { headers });
    if (!res.ok) continue;
    const json = await res.json();
    for (const item of json.items || []) {
      signals.push({
        kind: 'metric',
        data: {
          namespace: ns, name: item.metadata.name, kind: 'pod',
          cpu: { usage: parseCpuMilli(item.usage.cpu || '0'), capacity: 1000 },
          memory: { usage: parseInt(item.usage.memory || '0', 10), capacity: 1073741824 },
        },
      });
    }
  }

  console.log(`Fetched ${signals.length} signals in last hour`);

  const cellSignals: K8sSignal[][] = Array.from({ length: 4 }, () => Array.from({ length: 3 }, () => []));
  for (const signal of signals) {
    const cell = resolveCell(signal);
    if (!cell) continue;
    cellSignals[cell.row][cell.col].push(signal);
  }

  const paddedStream: PaddedStreamNode[] = [];
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

  const result = runScoringEngine(now, paddedStream, [0, 0, 0]);

  console.log('\n── RESULTS ──');
  console.log(`Metric A (Compliance): ${(result.metricACompliance * 100).toFixed(1)}%`);
  console.log(`Metric B (Integrity):  ${(result.metricBIntegrity * 100).toFixed(1)}%`);
  console.log(`Status:                ${result.status}`);
  console.log(`Watermelon Index:      ${(result.watermelonIndex * 100).toFixed(1)}%`);
  console.log(`Honest Failure:        ${(result.honestFailureIndex * 100).toFixed(1)}%`);
}

main().catch(console.error);   