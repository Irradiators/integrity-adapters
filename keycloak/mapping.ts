// integrity-adapters/keycloak/mapping.ts
// Static (row, col) lookup for Keycloak event types.

export interface KeycloakEvent {
  id: string;
  time: number; // epoch ms
  type: string;
  realmId: string;
  realmName: string;
  clientId?: string;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  error?: string;
  details?: Record<string, string>;
}

export interface KeycloakCellMapping {
  row: number;
  col: number;
  match: (event: KeycloakEvent) => boolean;
}

// Priority: first match wins. Row 0 > Row 1 > Row 2 > Row 3.
export const CELL_MAPPINGS: KeycloakCellMapping[] = [
  // ── Row 0: Function ──
  { row: 0, col: 0, match: (e) =>
    ['REALM_CREATED', 'REALM_UPDATED', 'AUTHORIZATION',
     'UPDATE_CONSENT', 'REMOVE_CONSENT'].includes(e.type)
  },
  { row: 0, col: 1, match: (e) =>
    e.type === 'CODE_TO_TOKEN' && e.details?.client_id === 'account-console'
  },
  { row: 0, col: 2, match: (e) =>
    ['IDP_INITIATED', 'IDP_REDIR',
     'IDENTITY_PROVIDER_LINKED', 'IDENTITY_PROVIDER_UNLINKED'].includes(e.type)
  },

  // ── Row 1: Features ──
  { row: 1, col: 0, match: (e) =>
    ['LOGIN', 'LOGIN_ERROR', 'LOGOUT', 'REGISTER', 'REGISTER_ERROR',
     'ROLE_MAPPING_ADDED', 'ROLE_MAPPING_REMOVED',
     'CLIENT_ROLE_MAPPING_ADDED', 'CLIENT_ROLE_MAPPING_REMOVED',
     'RESET_CREDENTIALS'].includes(e.type)
  },
  { row: 1, col: 1, match: (e) =>
    e.details?.auth_method === 'openid-connect' &&
    (e.type === 'CODE_TO_TOKEN' || e.type === 'VALIDATION_TOKEN')
  },
  { row: 1, col: 2, match: (e) =>
    ['CLIENT_LOGIN', 'CLIENT_LOGOUT', 'CLIENT_REGISTRATION',
     'UPDATE_CLIENT_ATTRIBUTES', 'UPDATE_CLIENT_ROLES', 'UPDATE_CLIENT_DESCRIPTION',
     'REMOVE_CLIENT_ATTRIBUTES', 'REMOVE_CLIENT_ROLES', 'REMOVE_CLIENT_DESCRIPTION',
     'EXPIRED_TOKEN', 'EXPIRED_CODE', 'EXPIRED_REFRESH'].includes(e.type)
  },

  // ── Row 2: Elements ──
  { row: 2, col: 0, match: (e) =>
    ['USER_UPDATE', 'USER_CREATED', 'USER_DELETED', 'CREDENTIAL_UPDATED'].includes(e.type)
  },
  { row: 2, col: 1, match: (e) =>
    (['SESSION_STARTED', 'SESSION_TERMINATED'].includes(e.type) && e.error !== 'session_expired') ||
    (e.type === 'CODE_TO_TOKEN' && e.error)
  },
  { row: 2, col: 2, match: (e) =>
    e.details?.auth_method === 'saml'
  },

  // ── Row 3: Execution ──
  { row: 3, col: 0, match: (e) =>
    (e.type === 'SESSION_STARTED' || e.type === 'SESSION_TERMINATED') && e.error === 'session_expired'
  },
  { row: 3, col: 1, match: (e) =>
    e.details?.error_description === 'event_listener_error'
  },
  { row: 3, col: 2, match: (e) =>
    e.error === 'connection_timeout' || e.error === 'node_unavailable'
  },
];

export function resolveCell(event: KeycloakEvent): { row: number; col: number } | null {
  for (const m of CELL_MAPPINGS) {
    if (m.match(event)) return { row: m.row, col: m.col };
  }
  return null;
}   