import {describe, it, expect, vi} from 'vitest';
import {extractGroups, GroupsLogger} from './groups';

function makeLogger(): GroupsLogger & {
  warnCalls: unknown[][];
  infoCalls: unknown[][];
} {
  const warnCalls: unknown[][] = [];
  const infoCalls: unknown[][] = [];
  return {
    warnCalls,
    infoCalls,
    warn: vi.fn((...args: unknown[]) => warnCalls.push(args)),
    info: vi.fn((...args: unknown[]) => infoCalls.push(args)),
  };
}

describe('extractGroups: no roles.claim configured', () => {
  it('returns an empty array', () => {
    const logger = makeLogger();
    expect(extractGroups({roles: ['a', 'b']}, {}, logger)).toEqual([]);
  });
});

describe('extractGroups: flat claim shapes, no allow-list (backward compatible)', () => {
  it('passes through an array claim unchanged', () => {
    const logger = makeLogger();
    const result = extractGroups(
      {roles: ['team1', 'team2']},
      {roles: {claim: 'roles'}},
      logger,
    );
    expect(result).toEqual(['team1', 'team2']);
  });

  it('splits a comma-separated string claim', () => {
    const logger = makeLogger();
    const result = extractGroups(
      {roles: 'team1, team2 ,team3'},
      {roles: {claim: 'roles'}},
      logger,
    );
    expect(result).toEqual(['team1', 'team2', 'team3']);
  });

  it('logs and returns empty when the claim is missing', () => {
    const logger = makeLogger();
    const result = extractGroups({}, {roles: {claim: 'roles'}}, logger);
    expect(result).toEqual([]);
    expect(logger.infoCalls).toHaveLength(1);
  });

  it('treats an empty array claim the same as a missing claim', () => {
    const logger = makeLogger();
    const result = extractGroups(
      {roles: []},
      {roles: {claim: 'roles'}},
      logger,
    );
    expect(result).toEqual([]);
    expect(logger.infoCalls).toHaveLength(1);
  });
});

describe('extractGroups: dot-path resolution (Keycloak realm_access.roles)', () => {
  it('resolves a nested array claim via dot-path', () => {
    const logger = makeLogger();
    const claims = {realm_access: {roles: ['npm-publish', 'default-roles']}};
    const result = extractGroups(
      claims,
      {roles: {claim: 'realm_access.roles'}},
      logger,
    );
    expect(result).toEqual(['npm-publish', 'default-roles']);
  });

  it('returns empty when an intermediate path segment is missing', () => {
    const logger = makeLogger();
    const result = extractGroups(
      {},
      {roles: {claim: 'realm_access.roles'}},
      logger,
    );
    expect(result).toEqual([]);
  });
});

describe('extractGroups: object-shaped claims (map -> array, e.g. verdaccio-bitbucket-style)', () => {
  it('extracts group names as keys, no allow-list means all pass through', () => {
    const logger = makeLogger();
    const claims = {teams: {team1: ['admin', 'write'], team2: []}};
    const result = extractGroups(claims, {roles: {claim: 'teams'}}, logger);
    expect(result.sort()).toEqual(['team1', 'team2']);
  });
});

describe('extractGroups: object-of-objects claims (Keycloak resource_access.<client>.roles)', () => {
  it('extracts using the default "roles" sub-key', () => {
    const logger = makeLogger();
    const claims = {
      resource_access: {
        myapp: {roles: ['admin']},
        account: {roles: ['manage-account']},
      },
    };
    const result = extractGroups(
      claims,
      {roles: {claim: 'resource_access'}},
      logger,
    );
    expect(result.sort()).toEqual(['account', 'myapp']);
  });

  it('honors a custom roles.mapKey', () => {
    const logger = makeLogger();
    const claims = {perms: {myapp: {permissions: ['admin']}}};
    const result = extractGroups(
      claims,
      {roles: {claim: 'perms', mapKey: 'permissions'}},
      logger,
    );
    expect(result).toEqual(['myapp']);
  });
});

describe('extractGroups: roles.allowList filtering (string DSL)', () => {
  const claims = {
    resource_access: {
      team1: {roles: ['write']},
      team2: {roles: []},
      team3: {roles: ['read']},
    },
  };
  const opts = {
    roles: {
      claim: 'resource_access',
      allowList: 'team1(admin|write),team2',
    },
  };

  it('includes a group whose role intersects the allowed set', () => {
    const logger = makeLogger();
    expect(extractGroups(claims, opts, logger)).toContain('team1');
  });

  it('includes a group with an empty allow-list entry unconditionally', () => {
    const logger = makeLogger();
    expect(extractGroups(claims, opts, logger)).toContain('team2');
  });

  it('excludes a group not listed in the allow-list at all (default-deny)', () => {
    const logger = makeLogger();
    expect(extractGroups(claims, opts, logger)).not.toContain('team3');
  });

  it('excludes a listed group whose role does not intersect the allowed set', () => {
    const logger = makeLogger();
    const c = {resource_access: {team1: {roles: ['read']}}};
    expect(extractGroups(c, opts, logger)).not.toContain('team1');
  });
});

describe('extractGroups: roles.allowList filtering (native map form)', () => {
  it('behaves identically to the string DSL', () => {
    const logger = makeLogger();
    const claims = {
      resource_access: {team1: {roles: ['write']}, team2: {roles: []}},
    };
    const opts = {
      roles: {
        claim: 'resource_access',
        allowList: {team1: ['admin', 'write'], team2: []},
      },
    };
    expect(extractGroups(claims, opts, logger).sort()).toEqual([
      'team1',
      'team2',
    ]);
  });
});

describe('extractGroups: unsatisfiable filter against a flat (membership-only) claim', () => {
  it('excludes the group and warns, rather than silently matching', () => {
    const logger = makeLogger();
    const claims = {roles: ['team1', 'team2']};
    const opts = {
      roles: {claim: 'roles', allowList: 'team1(admin|write)'},
    };
    const result = extractGroups(claims, opts, logger);
    expect(result).not.toContain('team1');
    expect(logger.warnCalls).toHaveLength(1);
  });

  it('does not warn for a group with an empty (but present) role dimension', () => {
    const logger = makeLogger();
    const claims = {resource_access: {team2: {roles: []}}};
    const opts = {
      roles: {claim: 'resource_access', allowList: 'team2(admin)'},
    };
    const result = extractGroups(claims, opts, logger);
    expect(result).not.toContain('team2'); // empty roles never intersects a non-empty filter
    expect(logger.warnCalls).toHaveLength(0); // but this isn't a config mistake, so no warning
  });
});
