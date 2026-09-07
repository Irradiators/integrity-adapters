// K8s-specific normalization: event/metric/audit → maskedValue ∈ [0, 1]

import type { K8sSignal, K8sEvent, K8sMetric, K8sAuditEntry } from './mapping';

const EVENT_SEVERITY: Record<string, number> = {
  // Node / infrastructure
  NodeNotReady: 0.90,
  // Image / scheduling
  ErrImagePull: 0.80,
  ImagePullBackOff: 0.80,
  // Storage
  ProvisioningFailed: 0.75,
  ExternalProvisioningFailed: 0.75,
  // Mount / config
  FailedMount: 0.55,
  CreateContainerConfigError: 0.55,
};

function eventToMaskedValue(event: K8sEvent): number {
  if (event.type === 'Normal') return 1.0;
  const severity = EVENT_SEVERITY[event.reason] ?? 0.4;
  return Math.max(0, 1.0 - severity);
}

function metricToMaskedValue(metric: K8sMetric): number {
  const cpuRatio = metric.cpu.capacity > 0 ? metric.cpu.usage / metric.cpu.capacity : 0;
  const memRatio = metric.memory.capacity > 0 ? metric.memory.usage / metric.memory.capacity : 0;
  const pressure = Math.max(cpuRatio, memRatio);
  // Mapping predicate ensures pressure > 0.85; this is a safety net.
  if (pressure <= 0.85) return 1.0;
  return Math.max(0, 1.0 - (pressure - 0.85) / 0.15);
}

function auditToMaskedValue(audit: K8sAuditEntry): number {
  const { code } = audit.responseStatus;
  if (code === 403 || code === 401) return 0.7;
  if (code === 200 && audit.verb === 'get' && audit.objectRef.resource === 'secrets' &&
      !audit.user.username.startsWith('system:serviceaccount')) return 0.1;
  if (code === 200 && audit.verb === 'delete' &&
      ['configmaps', 'secrets'].includes(audit.objectRef.resource)) return 0.5;
  return 1.0;
}

export function signalToMaskedValue(signal: K8sSignal): number {
  switch (signal.kind) {
    case 'event': return eventToMaskedValue(signal.data);
    case 'metric': return metricToMaskedValue(signal.data);
    case 'audit': return auditToMaskedValue(signal.data);
  }
}

export function cellMaskedValue(signals: K8sSignal[]): number {
  if (signals.length === 0) return 1.0;
  return signals.reduce((min, s) => Math.min(min, signalToMaskedValue(s)), 1.0);
}   