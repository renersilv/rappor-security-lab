export const STATE_ORDER = [
  "vulnerable",
  "partially-fixed",
  "fixed",
  "reintroduced",
];

export const SUPABASE_RULES = {
  policyExistsRlsDisabled: {
    id: "0007-policy-exists-rls-disabled",
    ruleFamily: "supabase.security-advisor.0007-policy-exists-rls-disabled.v1",
    providerLevel: "info",
    severity: "info",
    groupingKey: "supabase-rls-configuration",
    object: "public.rappor_lab_policy_without_rls",
    positiveEvidence: "A declared synthetic table has a policy while row-level security is disabled.",
    negativeEvidence: "The declared synthetic table has row-level security enabled and an enforced restrictive policy.",
  },
  rlsEnabledNoPolicy: {
    id: "0008-rls-enabled-no-policy",
    ruleFamily: "supabase.security-advisor.0008-rls-enabled-no-policy.v1",
    providerLevel: "info",
    severity: "info",
    groupingKey: "supabase-rls-configuration",
    object: "public.rappor_lab_no_policy",
    positiveEvidence: "A declared synthetic table has row-level security enabled without any policy.",
    negativeEvidence: "The declared synthetic table has row-level security enabled with an enforced restrictive policy.",
  },
  securityDefinerView: {
    id: "0010-security-definer-view",
    ruleFamily: "supabase.security-advisor.0010-security-definer-view.v1",
    providerLevel: "error",
    severity: "high",
    groupingKey: "supabase-exposed-object",
    object: "public.rappor_lab_security_view",
    positiveEvidence: "A declared synthetic view uses creator privileges in an API-exposed schema.",
    negativeEvidence: "The declared synthetic view explicitly uses caller privileges.",
  },
  rlsDisabledInPublic: {
    id: "0013-rls-disabled-in-public",
    ruleFamily: "supabase.security-advisor.0013-rls-disabled-in-public.v1",
    providerLevel: "error",
    severity: "high",
    groupingKey: "supabase-rls-configuration",
    object: "public.rappor_lab_rls_disabled",
    positiveEvidence: "A declared synthetic table in the API-exposed schema has row-level security disabled.",
    negativeEvidence: "The declared synthetic table has row-level security enabled with an enforced restrictive policy.",
  },
  sensitiveColumnsExposed: {
    id: "0023-sensitive-columns-exposed",
    ruleFamily: "supabase.security-advisor.0023-sensitive-columns-exposed.v1",
    providerLevel: "error",
    severity: "high",
    groupingKey: "supabase-exposed-object",
    object: "public.rappor_lab_sensitive_profiles",
    positiveEvidence: "An empty synthetic table has a provider-recognized sensitive column name and row-level security disabled.",
    negativeEvidence: "The empty synthetic table has row-level security enabled with an enforced restrictive policy.",
  },
  permissiveRlsPolicy: {
    id: "0024-permissive-rls-policy",
    ruleFamily: "supabase.security-advisor.0024-permissive-rls-policy.v1",
    providerLevel: "warn",
    severity: "medium",
    groupingKey: "supabase-rls-policy",
    object: "public.rappor_lab_permissive_policy",
    positiveEvidence: "A declared synthetic update policy for authenticated users has an always-true condition.",
    negativeEvidence: "The declared synthetic update policy is restricted to the current authenticated user.",
  },
  publicBucketAllowsListing: {
    id: "0025-public-bucket-allows-listing",
    ruleFamily: "supabase.security-advisor.0025-public-bucket-allows-listing.v1",
    providerLevel: "warn",
    severity: "medium",
    groupingKey: "supabase-storage-configuration",
    object: "rappor-lab-public-listing",
    positiveEvidence: "An empty synthetic public bucket has a broad matching SELECT policy that permits listing.",
    negativeEvidence: "The empty synthetic bucket is private and has no listing policy.",
  },
};

const ALL_SUPABASE_FINDINGS = Object.fromEntries(
  Object.keys(SUPABASE_RULES).map((key) => [key, true]),
);
const NO_SUPABASE_FINDINGS = Object.fromEntries(
  Object.keys(SUPABASE_RULES).map((key) => [key, false]),
);

export const SUPABASE_STATES = {
  vulnerable: {
    migration: "supabase/migrations/010_vulnerable.sql",
    findings: ALL_SUPABASE_FINDINGS,
  },
  "partially-fixed": {
    migration: "supabase/migrations/020_partially_fixed.sql",
    findings: {
      policyExistsRlsDisabled: false,
      rlsEnabledNoPolicy: true,
      securityDefinerView: false,
      rlsDisabledInPublic: false,
      sensitiveColumnsExposed: true,
      permissiveRlsPolicy: true,
      publicBucketAllowsListing: true,
    },
  },
  fixed: {
    migration: "supabase/migrations/030_fixed.sql",
    findings: NO_SUPABASE_FINDINGS,
  },
  reintroduced: {
    migration: "supabase/migrations/040_reintroduced.sql",
    findings: ALL_SUPABASE_FINDINGS,
  },
};

export const VERCEL_RULE = {
  id: "git-fork-protection-disabled",
  ruleFamily: "vercel.git-fork-protection.disabled.v1",
  severity: "high",
  groupingKey: "vercel-project-security",
  positiveEvidence: "The official project API reports Git fork protection disabled.",
  negativeEvidence: "The official project API reports Git fork protection enabled.",
};

export const VERCEL_STATES = {
  vulnerable: {
    project: "rappor-lab-vulnerable",
    gitForkProtection: false,
  },
  "partially-fixed": {
    project: "rappor-lab-partially-fixed",
    gitForkProtection: true,
  },
  fixed: {
    project: "rappor-lab-fixed",
    gitForkProtection: true,
  },
  reintroduced: {
    project: "rappor-lab-reintroduced",
    gitForkProtection: false,
  },
};

export const VERCEL_SCOPE = "rappor-security-tests";
