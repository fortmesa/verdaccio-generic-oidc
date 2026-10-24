/**
 * Generalized groups/roles extraction and allow-list filtering.
 *
 * Upstream only ever supported a single flat claim (string or array). Real
 * providers produce richer shapes -- notably Keycloak, which nests realm
 * roles under `realm_access.roles` and per-client roles under
 * `resource_access.<clientId>.roles` -- and there was no way to restrict
 * which of a user's IdP roles actually become Verdaccio package-access
 * groups. This module adds both, as a pure, IdP-independent layer that sits
 * between "claims we got from the token" and "groups Verdaccio sees".
 */

export type RolesAllowList = Record<string, string[]>;

export interface GroupsConfig {
  roles?: {
    /** Dot-path into the claims object, e.g. "roles" or "resource_access.myapp.roles". */
    claim?: string;
    /** Sub-key holding the role array when a map-shaped claim's values are objects (Keycloak's resource_access.<client> shape). Defaults to "roles". */
    mapKey?: string;
    /**
     * Restricts which extracted groups are surfaced to Verdaccio.
     * - Unset: fully backward compatible, every extracted group passes through.
     * - Bitbucket-style DSL string: "team1(admin|write),team2" -- team1 only
     *   included if the user's role for it is admin or write; team2 included
     *   unconditionally if present.
     * - Native map: {team1: ["admin", "write"], team2: []} -- same semantics.
     * A group not listed here at all is excluded (default-deny).
     */
    allowList?: string | RolesAllowList;
  };
}

export interface GroupsLogger {
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
  debug(obj: unknown, msg?: string): void;
}

/** roles === null means "membership only" -- the claim shape carries no per-role info to filter on. */
type ExtractedGroups = Map<string, string[] | null>;

export function getByPath(
  claims: Record<string, unknown>,
  path: string,
): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (acc, key) =>
        acc != null && typeof acc === 'object'
          ? (acc as Record<string, unknown>)[key]
          : undefined,
      claims,
    );
}

/** "team1(admin|write),team2" -> {team1: ['admin','write'], team2: []} */
function parseAllowListString(input: string): RolesAllowList {
  const result: RolesAllowList = {};
  for (const part of input.split(/\s*,\s*/).filter(Boolean)) {
    const match = part.trim().match(/^(.*?)(?:\((.*?)\))?$/);
    if (!match || !match[1]) continue;
    const [, name, rolesPart] = match;
    result[name] = rolesPart
      ? rolesPart
          .split('|')
          .map(r => r.trim())
          .filter(Boolean)
      : [];
  }
  return result;
}

function normalizeAllowList(
  input: string | RolesAllowList | undefined,
): RolesAllowList | undefined {
  if (input == null) return undefined;
  if (typeof input === 'string') return parseAllowListString(input);
  const result: RolesAllowList = {};
  for (const [key, value] of Object.entries(input)) {
    result[key] = Array.isArray(value) ? value.map(String) : [];
  }
  return result;
}

/** Normalizes any claim shape into Map<groupName, roles|null>, or null if the claim is absent/empty. */
function extractRawClaim(
  raw: unknown,
  mapRolesKey: string,
): ExtractedGroups | null {
  if (raw == null) return null;

  if (typeof raw === 'string') {
    const names = raw
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    return names.length ? new Map(names.map(n => [n, null])) : null;
  }

  if (Array.isArray(raw)) {
    // Some OIDC servers omit the claim entirely once it would be empty, but
    // not all -- treat an empty array the same as an absent claim.
    if (raw.length === 0) return null;
    return new Map(raw.map(n => [String(n), null]));
  }

  if (typeof raw === 'object') {
    // A key is a group only when its value says so: `true`, an array of
    // roles, or an object holding one under mapRolesKey. Anything else,
    // such as {"admin": false}, is not membership.
    const map: ExtractedGroups = new Map();
    for (const [name, value] of Object.entries(
      raw as Record<string, unknown>,
    )) {
      if (value === true) {
        map.set(name, null);
      } else if (Array.isArray(value)) {
        map.set(name, value.map(String));
      } else if (
        value != null &&
        typeof value === 'object' &&
        Array.isArray((value as Record<string, unknown>)[mapRolesKey])
      ) {
        map.set(
          name,
          ((value as Record<string, unknown>)[mapRolesKey] as unknown[]).map(
            String,
          ),
        );
      }
    }
    return map.size ? map : null;
  }

  return null;
}

export function extractGroups(
  claims: Record<string, unknown>,
  config: GroupsConfig,
  logger: GroupsLogger,
): string[] {
  const {claim: rolesClaim, mapKey: rolesMapRolesKey = 'roles'} =
    config.roles ?? {};
  if (!rolesClaim) return [];

  const extracted = extractRawClaim(
    getByPath(claims, rolesClaim),
    rolesMapRolesKey,
  );
  if (extracted == null) {
    logger.info(
      {rolesClaim, claims: JSON.stringify(Object.keys(claims))},
      `Missing roles claim '@{rolesClaim}'. Available claims: @{claims}`,
    );
    return [];
  }

  const allowList = normalizeAllowList(config.roles?.allowList);
  if (!allowList) {
    return [...extracted.keys()];
  }

  const result: string[] = [];
  for (const [name, roles] of extracted) {
    if (!Object.prototype.hasOwnProperty.call(allowList, name)) continue; // default-deny
    const allowedRoles = allowList[name];

    if (allowedRoles.length === 0) {
      result.push(name);
      continue;
    }

    if (roles == null) {
      logger.debug(
        {group: name, rolesClaim},
        `roles.allowList configures a role filter for group '@{group}', but the claim at '@{rolesClaim}' carries no per-role information for it (membership only) -- this filter can never match and will always exclude the group. Remove the role list to include it unconditionally, or configure the IdP to emit per-role data for this claim.`,
      );
      continue;
    }

    if (roles.some(r => allowedRoles.includes(r))) {
      result.push(name);
    }
  }
  return result;
}
