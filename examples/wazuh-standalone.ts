// Dev tool — verifies scoring locally. Production path: adapters/wazuh/index.ts (cron).
// Standalone Wazuh scoring — no Cloudflare, no queue, no KV.
// Usage: npx tsx examples/wazuh-standalone.ts
// Requires: WAZUH_API_URL, WAZUH_API_KEY in .env

import { runScoringEngine, type PaddedStreamNode } from '../src/lib/index';
import { resolveCell, type WazuhAlert } from '../adapters/wazuh/mapping';
import { cellMaskedValue } from '../adapters/wazuh/f_norm';

const WAZUH_API_URL = process.env.WAZUH_API_URL!;
const WAZUH_API_KEY = process.env.WAZUH_API_KEY!;

async function main() {
  const now = Math.floor(Date.now() / 1000);
  const since = now - 3600;

  // Fetch alerts (server-side time filter — no client-side pagination for demo)
  const dateFilter = `dateFilter=gte@timestamp:${new Date(since * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '')}`;
  const res = await fetch(`${WAZUH_API_URL}/alerts?origin=agent&limit=1000&offset=0&${dateFilter}`, {
    headers: { 'Authorization': `Bearer ${WAZUH_API_KEY}` },
  });
  const json = await res.json();
  const alerts: WazuhAlert[] = json.data?.items || json.items || [];

  console.log(`Fetched ${alerts.length} alerts in last hour`);

  // Build 12-node stream
  const cellAlerts: WazuhAlert[][] = Array.from({ length: 4 }, () => Array.from({ length: 3 }, () => []));
  for (const alert of alerts) {
    const cell = resolveCell(alert);
    if (!cell) continue;
    cellAlerts[cell.row][cell.col].push(alert);
  }

  const paddedStream: PaddedStreamNode[] = [];
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

  // Score
  const result = runScoringEngine(paddedStream, [0, 0, 0], undefined, undefined, undefined);

  console.log('\n── RESULTS ──');
  console.log(`Metric A (Compliance): ${(result.metric_a_compliance * 100).toFixed(1)}%`);
  console.log(`Metric B (Integrity):  ${(result.metric_b_integrity * 100).toFixed(1)}%`);
  console.log(`Status:                ${result.status}`);
  console.log(`Watermelon Index:      ${(result.watermelon_index * 100).toFixed(1)}%`);
  console.log(`Honest Failure:        ${(result.honest_failure_index * 100).toFixed(1)}%`);
  console.log(`Chaos Penalty:         ${result.spectral_analysis.chaos_index_penalty}`);
  console.log(`λmax:                  ${result.spectral_analysis.principal_eigenvalue}`);
}

main().catch(console.error);   