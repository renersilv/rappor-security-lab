// Public connected-analysis families intentionally remain separate from the
// provider advisor identifiers in states.mjs. A null mapping means HML does not
// expose a comparable public coverage check for that independent manifest case.
export const SUPABASE_ADVISOR_CANONICAL_RULES = {
  policyExistsRlsDisabled: "policyWithRlsDisabled",
  rlsEnabledNoPolicy: "enabledWithoutPolicy",
  securityDefinerView: "securityDefinerExposed",
  rlsDisabledInPublic: "disabledExposed",
  sensitiveColumnsExposed: null,
  permissiveRlsPolicy: null,
  publicBucketAllowsListing: null,
};

export const SUPABASE_CANONICAL_RULES = {
  disabledExposed: {
    ruleFamily: "supabase.rls.disabled-exposed.v1",
    severity: "critical",
  },
  enabledWithoutPolicy: {
    ruleFamily: "supabase.rls.enabled-without-policy.v1",
    severity: "info",
  },
  policyWithRlsDisabled: {
    ruleFamily: "supabase.rls.policy-with-rls-disabled.v1",
    severity: "high",
  },
  securityDefinerExposed: {
    ruleFamily: "supabase.security-definer.exposed.v1",
    severity: "high",
  },
};

export const SUPABASE_AFFECTED_ITEMS = {
  authorizationDocuments: "rappor_lab_documents",
  rlsDisabled: "rappor_lab_rls_disabled",
  policyWithoutRls: "rappor_lab_policy_without_rls",
  sensitiveProfiles: "rappor_lab_sensitive_profiles",
  permissivePolicy: "rappor_lab_permissive_policy",
  noPolicy: "rappor_lab_no_policy",
  securityView: "rappor_lab_security_view",
  publicBucket: "rappor-lab-public-listing",
};

const FULL_CANONICAL_FINDINGS = [
  {
    rule: "disabledExposed",
    affectedItems: ["authorizationDocuments", "policyWithoutRls", "rlsDisabled", "sensitiveProfiles"],
  },
  { rule: "enabledWithoutPolicy", affectedItems: ["noPolicy"] },
  {
    rule: "policyWithRlsDisabled",
    affectedItems: ["policyWithoutRls", "rlsDisabled", "sensitiveProfiles"],
  },
  { rule: "securityDefinerExposed", affectedItems: ["securityView"] },
];

export const SUPABASE_CANONICAL_STATES = {
  vulnerable: FULL_CANONICAL_FINDINGS,
  "partially-fixed": [
    { rule: "disabledExposed", affectedItems: ["sensitiveProfiles"] },
    { rule: "enabledWithoutPolicy", affectedItems: ["noPolicy"] },
    { rule: "policyWithRlsDisabled", affectedItems: ["sensitiveProfiles"] },
  ],
  fixed: [],
  reintroduced: FULL_CANONICAL_FINDINGS,
};
