// Dev tool — verifies scoring locally. Production path: adapters/keycloak/index.ts (cron).
// Standalone Keycloak scoring — no Cloudflare, no queue, no KV.
// Usage: npx tsx examples/keycloak-standalone.ts
// Requires: KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET in .env

import 'dotenv/config';
import { runScoringEngine, type PaddedStreamNode } from '../src/lib/index';
import { resolveCell, type KeycloakEvent } from '../adapters/keycloak/mapping';
import { cellMaskedValue } from '../adapters/keycloak/f_norm';

async function getToken(): Promise<string> {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: process.env.KEYCLOAK_CLIENT_ID!,
    client_secret: process.env.KEYCLOAK_CLIENT_SECRET!,
  });
  const res = await fetch(
    `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
    { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }
  );
  if (!res.ok) throw new Error(`Token error: ${res.status}`);
  return (await res.json()).access_token;
}

async function main() {
  const now = Math.floor(Date.now() / 1000);
  const since = now - 3600;
  const token = await getToken();

  const res = await fetch(
    `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/events?max=1000&time=gt:${since * 1000}`,
    { headers: { 'Authorization': `Bearer ${token}` } }
  );
  const events: KeycloakEvent[] = await res.json();

  console.log(`Fetched ${events.length} events in last hour`);

  const cellEvents: KeycloakEvent[][] = Array.from({ length: 4 }, () => Array.from({ length: 3 }, () => []));
  for (const event of events) {
    const cell = resolveCell(event);
    if (!cell) continue;
    cellEvents[cell.row][cell.col].push(event);
  }

  const paddedStream: PaddedStreamNode[] = [];
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

  const result = runScoringEngine(now, paddedStream, [0, 0, 0]);

  console.log('\n── RESULTS ──');
  console.log(`Metric A (Compliance): ${(result.metricACompliance * 100).toFixed(1)}%`);
  console.log(`Metric B (Integrity):  ${(result.metricBIntegrity * 100).toFixed(1)}%`);
  console.log(`Status:                ${result.status}`);
  console.log(`Watermelon Index:      ${(result.watermelonIndex * 100).toFixed(1)}%`);
  console.log(`Honest Failure:        ${(result.honestFailureIndex * 100).toFixed(1)}%`);
}

main().catch(console.error);   