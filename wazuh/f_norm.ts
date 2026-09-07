// integrity-adapters/wazuh/f_norm.ts
// Wazuh-specific normalization: raw alert severity → maskedValue ∈ [0, 1]
// Higher severity = lower integrity. No alerts in window = healthy (1.0).

import type { WazuhAlert } from './mapping';

const SEVERITY_MAX = 15;

export function severityToMaskedValue(severity: number): number {
  const clamped = Math.max(0, Math.min(SEVERITY_MAX, severity));
  const inverted = 1 - clamped / SEVERITY_MAX;
  return inverted * inverted; // quadratic: preserves high, punishes low
}

export function cellMaskedValue(alerts: WazuhAlert[]): number {
  if (alerts.length === 0) return 1.0;
  return alerts.reduce((min, a) => Math.min(min, severityToMaskedValue(a.rule.level)), 1.0);
}