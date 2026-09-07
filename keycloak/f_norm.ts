// integrity-adapters/keycloak/f_norm.ts
// Keycloak-specific normalization: event type + error → maskedValue ∈ [0, 1]

import type { KeycloakEvent } from './mapping';

interface ErrorSeverityRule {
  severity: number;
  match: (event: KeycloakEvent) => boolean;
}

const ERROR_RULES: ErrorSeverityRule[] = [
  { severity: 1.0, match: (e) =>
    ['connection_timeout', 'node_unavailable', 'event_listener_error'].includes(e.error || '')
  },
  { severity: 0.9, match: (e) =>
    ['session_replay', 'token_reuse', 'session_hijack'].includes(e.error || '')
  },
  { severity: 0.6, match: (e) =>
    (e.type === 'VALIDATION_TOKEN' && e.error) ||
    (e.type === 'CODE_TO_TOKEN' && e.error) ||
    ['invalid_signature', 'certificate_expired'].includes(e.error || '')
  },
  { severity: 0.3, match: (e) =>
    ['LOGIN_ERROR', 'REGISTER_ERROR', 'RESET_CREDENTIALS'].includes(e.type) ||
    ['user_not_found', 'invalid_user_credentials', 'user_disabled', 'user_locked'].includes(e.error || '')
  },
];

export function eventToMaskedValue(event: KeycloakEvent): number {
  if (!event.error && !['LOGIN_ERROR', 'REGISTER_ERROR', 'RESET_CREDENTIALS'].includes(event.type)) return 1.0;
  for (const rule of ERROR_RULES) {
    if (rule.match(event)) return Math.max(0, 1.0 - rule.severity);
  }
  return 0.5; // unmatched error → moderate
}

export function cellMaskedValue(events: KeycloakEvent[]): number {
  if (events.length === 0) return 1.0;
  return events.reduce((min, e) => Math.min(min, eventToMaskedValue(e)), 1.0);
}   