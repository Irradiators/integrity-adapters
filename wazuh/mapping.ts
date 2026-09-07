// integrity-adapters/wazuh/mapping.ts
// Static (row, col) lookup for Wazuh rule groups / decoders.
// Row = Axiomatic Domain (0=Function, 1=Features, 2=Elements, 3=Execution)
// Col = Technical Enabler (0=Structures, 1=Contents, 2=Facilities)

export interface WazuhAlert {
  rule: {
    groups: string[];
    level: number; // 0–15
    description: string;
  };
  data: {
    location?: string;
    title?: string;
    id?: string;
    [key: string]: unknown;
  };
  timestamp: string; // ISO 8601
  agent: { id: string; name: string };
}

export interface WazuhCellMapping {
  row: number;
  col: number;
  match: (alert: WazuhAlert) => boolean;
}

// Priority: first match wins. Row 0 > Row 1 > Row 2 > Row 3.
export const CELL_MAPPINGS: WazuhCellMapping[] = [
  // ── Row 0: Function ──
  { row: 0, col: 0, match: (a) => a.rule.groups.some(g => ['policy', 'compliance', 'gpd', 'cis', 'pci_dss'].includes(g)) },
  { row: 0, col: 1, match: (a) => a.rule.groups.some(g => ['sca', 'integrity', 'osquery'].includes(g)) },
  { row: 0, col: 2, match: (a) => a.rule.groups.some(g => ['aws', 'azure', 'gcp', 'cloud'].includes(g)) },

  // ── Row 1: Features ──
  { row: 1, col: 0, match: (a) => a.rule.groups.some(g => ['authentication', 'rbac', 'privilege_escalation', 'identity'].includes(g)) },
  { row: 1, col: 1, match: (a) => a.rule.groups.some(g => ['tls', 'ssl', 'certificate', 'crypto', 'weak_ciphers'].includes(g)) },
  { row: 1, col: 2, match: (a) => a.rule.groups.some(g => ['api', 'rate_limit', 'waf', 'gateway'].includes(g)) },

  // ── Row 2: Elements ──
  { row: 2, col: 0, match: (a) => a.rule.groups.some(g => ['secrets', 'configuration', 'file_integrity', 'syscollector'].includes(g)) },
  { row: 2, col: 1, match: (a) => a.rule.groups.some(g => ['data_exfiltration', 'payload', 'malware'].includes(g)) },
  { row: 2, col: 2, match: (a) => a.rule.groups.some(g => ['s3', 'storage', 'bucket', 'object_storage'].includes(g)) },

  // ── Row 3: Execution ──
  { row: 3, col: 0, match: (a) => a.rule.groups.some(g => ['process', 'runtime', 'container', 'seccomp', 'syscall'].includes(g)) },
  { row: 3, col: 1, match: (a) => a.rule.groups.some(g => ['log', 'telemetry', 'pipeline', 'collector', 'heartbeat'].includes(g)) },
  { row: 3, col: 2, match: (a) => a.rule.groups.some(g => ['oom', 'resource', 'compute', 'node', 'cpu', 'memory', 'disk'].includes(g)) },
];

export function resolveCell(alert: WazuhAlert): { row: number; col: number } | null {
  for (const m of CELL_MAPPINGS) {
    if (m.match(alert)) return { row: m.row, col: m.col };
  }
  return null;
}   