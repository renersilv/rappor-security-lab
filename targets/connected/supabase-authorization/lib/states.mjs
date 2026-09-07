export const TABLE = "public.rappor_lab_documents";

export const STATE_ORDER = [
  "vulnerable",
  "partially-fixed",
  "fixed",
  "reintroduced",
];

const AUTHENTICATED_POLICIES = [
  {
    name: "lab_authenticated_read",
    command: "select",
    roles: ["authenticated"],
    using: "true",
    withCheck: null,
  },
  {
    name: "lab_authenticated_write",
    command: "insert",
    roles: ["authenticated"],
    using: null,
    withCheck: "true",
  },
];

export const STATES = {
  vulnerable: {
    migration: "migrations/010_vulnerable.sql",
    accessControl: {
      relation: TABLE,
      rlsEnabled: false,
      grants: {
        anon: ["select", "insert"],
        authenticated: ["select", "insert"],
      },
      policies: [],
    },
    expectedAccess: {
      anon: { read: true, write: true },
      authenticated: { read: true, write: true },
    },
  },
  "partially-fixed": {
    migration: "migrations/020_partially_fixed.sql",
    accessControl: {
      relation: TABLE,
      rlsEnabled: true,
      grants: {
        anon: ["select"],
        authenticated: ["select", "insert"],
      },
      policies: [
        {
          name: "lab_public_read",
          command: "select",
          roles: ["anon", "authenticated"],
          using: "true",
          withCheck: null,
        },
        ...AUTHENTICATED_POLICIES.filter((policy) => policy.command === "insert"),
      ],
    },
    expectedAccess: {
      anon: { read: true, write: false },
      authenticated: { read: true, write: true },
    },
  },
  fixed: {
    migration: "migrations/030_fixed.sql",
    accessControl: {
      relation: TABLE,
      rlsEnabled: true,
      grants: {
        anon: [],
        authenticated: ["select", "insert"],
      },
      policies: AUTHENTICATED_POLICIES,
    },
    expectedAccess: {
      anon: { read: false, write: false },
      authenticated: { read: true, write: true },
    },
  },
  reintroduced: {
    migration: "migrations/040_reintroduced.sql",
    accessControl: {
      relation: TABLE,
      rlsEnabled: false,
      grants: {
        anon: ["select", "insert"],
        authenticated: ["select", "insert"],
      },
      policies: [],
    },
    expectedAccess: {
      anon: { read: true, write: true },
      authenticated: { read: true, write: true },
    },
  },
};

export const OPERATIONS = {
  anonRead: {
    id: "anon-read",
    actor: "anon",
    operation: "read",
    capability: "authorization-read",
    ruleFamily: "supabase-anonymous-read-access",
    severity: "high",
    groupingKey: "supabase-anonymous-access",
    presentWhenAllowed: true,
    positiveEvidence: "An unauthenticated HEAD request can count the declared dummy seed row without returning its contents.",
    negativeEvidence: "An unauthenticated HEAD request cannot observe the declared dummy seed row.",
    functionalAssertion: "The read check uses HEAD with an exact count and never retrieves a row body.",
  },
  anonWrite: {
    id: "anon-write",
    actor: "anon",
    operation: "write",
    capability: "authorization-write",
    ruleFamily: "supabase-anonymous-write-access",
    severity: "critical",
    groupingKey: "supabase-anonymous-access",
    presentWhenAllowed: true,
    positiveEvidence: "An unauthenticated request can insert a generated dummy marker with no representation returned.",
    negativeEvidence: "An unauthenticated request cannot insert a generated dummy marker.",
    functionalAssertion: "The write check uses return=minimal and records no response body or inserted identifier.",
  },
  authenticatedRead: {
    id: "authenticated-read-denied",
    actor: "authenticated",
    operation: "read",
    capability: "authorization-read",
    ruleFamily: "supabase-authenticated-read-denied",
    severity: "high",
    groupingKey: "supabase-authenticated-denial",
    presentWhenAllowed: false,
    positiveEvidence: "The disposable authenticated user cannot count the declared dummy seed row.",
    negativeEvidence: "The disposable authenticated user can count the declared dummy seed row without receiving its contents.",
    functionalAssertion: "Authenticated access uses a short-lived user token obtained with the publishable key.",
  },
  authenticatedWrite: {
    id: "authenticated-write-denied",
    actor: "authenticated",
    operation: "write",
    capability: "authorization-write",
    ruleFamily: "supabase-authenticated-write-denied",
    severity: "high",
    groupingKey: "supabase-authenticated-denial",
    presentWhenAllowed: false,
    positiveEvidence: "The disposable authenticated user cannot insert a generated dummy marker.",
    negativeEvidence: "The disposable authenticated user can insert a generated dummy marker with no representation returned.",
    functionalAssertion: "The authenticated write returns no row representation and stores only a generated dummy marker.",
  },
};
