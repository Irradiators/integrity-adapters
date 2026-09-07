// integrity-adapters/k8s/mapping.ts
// Static (row, col) lookup for Kubernetes signals (events, metrics, audit).

export interface K8sEvent {
  type: string;
  reason: string;
  message: string;
  object: { kind: string; name: string; namespace: string };
  lastTimestamp: string;
  count: number;
}

export interface K8sMetric {
  namespace: string;
  name: string;
  kind: string;
  cpu: { usage: number; capacity: number };
  memory: { usage: number; capacity: number };
}

export interface K8sAuditEntry {
  verb: string;
  objectRef: { resource: string; namespace: string; name: string };
  requestReceivedTimestamp: string;
  responseStatus: { code: number; reason?: string };
  user: { username: string };
}

export type K8sSignal =
  | { kind: 'event'; data: K8sEvent }
  | { kind: 'metric'; data: K8sMetric }
  | { kind: 'audit'; data: K8sAuditEntry };

export interface K8sCellMapping {
  row: number;
  col: number;
  match: (signal: K8sSignal) => boolean;
}

// Priority: first match wins. Row 0 > Row 1 > Row 2 > Row 3.
// Audit cells are inactive until audit backend is wired (see index.ts TODO).
export const CELL_MAPPINGS: K8sCellMapping[] = [
  // ── Row 0: Function ──
  { row: 0, col: 0, match: (s) =>
    s.kind === 'audit' && s.data.verb === 'create' &&
    s.data.objectRef.resource === 'serviceaccounts'
  },
  { row: 0, col: 1, match: (s) =>
    s.kind === 'event' &&
    ['ErrImagePull', 'ImagePullBackOff'].includes(s.data.reason)
  },
  { row: 0, col: 2, match: (s) =>
    s.kind === 'event' && s.data.object.kind === 'Node' &&
    s.data.reason === 'NodeNotReady'
  },

  // ── Row 1: Features ──
  { row: 1, col: 0, match: (s) =>
    s.kind === 'audit' && s.data.responseStatus.code === 403 &&
    ['pods', 'secrets', 'configmaps', 'serviceaccounts'].includes(s.data.objectRef.resource)
  },
  { row: 1, col: 1, match: (s) =>
    s.kind === 'audit' && s.data.verb === 'get' &&
    s.data.objectRef.resource === 'secrets' && s.data.responseStatus.code === 200 &&
    !s.data.user.username.startsWith('system:serviceaccount')
  },
  { row: 1, col: 2, match: (s) =>
    s.kind === 'audit' && s.data.verb === 'create' &&
    s.data.objectRef.resource === 'networkpolicies' && s.data.responseStatus.code === 201
  },

  // ── Row 2: Elements ──
  { row: 2, col: 0, match: (s) =>
    s.kind === 'event' &&
    ['FailedMount', 'CreateContainerConfigError'].includes(s.data.reason)
  },
  { row: 2, col: 1, match: (s) =>
    s.kind === 'audit' && s.data.verb === 'delete' &&
    ['configmaps', 'secrets'].includes(s.data.objectRef.resource) &&
    s.data.responseStatus.code === 200
  },
  { row: 2, col: 2, match: (s) =>
    s.kind === 'event' &&
    ['ProvisioningFailed', 'ExternalProvisioningFailed'].includes(s.data.reason)
  },

  // ── Row 3: Execution ──
  { row: 3, col: 2, match: (s) =>
    s.kind === 'metric' &&
    ((s.data.cpu.capacity > 0 && s.data.cpu.usage / s.data.cpu.capacity > 0.85) ||
     (s.data.memory.capacity > 0 && s.data.memory.usage / s.data.memory.capacity > 0.85))
  },
];

export function resolveCell(signal: K8sSignal): { row: number; col: number } | null {
  for (const m of CELL_MAPPINGS) {
    if (m.match(signal)) return { row: m.row, col: m.col };
  }
  return null;
}   