const SUPPORTED_SCHEMA_MAJOR = 1;
const REQUIRED_TOP_LEVEL = [
  'schema_version',
  'generated_at',
  'coverage_window',
  'attack_families',
  'indicators',
  'indexes',
  'sources',
];
const INDICATOR_TYPES = ['package', 'file', 'process', 'github', 'network', 'mcp'];
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Validate a normalized iocs.json document. Returns { ok: true } or { ok: false, errors: [...] }.
 * Lightweight; not a full JSON Schema validator. Catches the schema contract violations
 * that would actually break downstream consumers.
 *
 * @param {Object} doc
 * @returns {{ok: true} | {ok: false, errors: string[]}}
 */
export function validate(doc) {
  const errors = [];

  for (const field of REQUIRED_TOP_LEVEL) {
    if (!(field in doc)) errors.push(`missing top-level field: ${field}`);
  }

  if (doc.schema_version) {
    const major = parseInt(String(doc.schema_version).split('.')[0], 10);
    if (major !== SUPPORTED_SCHEMA_MAJOR) {
      errors.push(`unsupported schema_version major: ${doc.schema_version}`);
    }
  }

  if (doc.indicators && typeof doc.indicators === 'object') {
    for (const type of INDICATOR_TYPES) {
      if (!Array.isArray(doc.indicators[type])) {
        errors.push(`indicators.${type} must be an array`);
      }
    }

    for (const type of INDICATOR_TYPES) {
      for (const ind of doc.indicators[type] ?? []) {
        errors.push(...validateIndicator(ind, type, doc.attack_families ?? {}));
      }
    }
  }

  if (doc.attack_families && typeof doc.attack_families === 'object') {
    for (const [key, fam] of Object.entries(doc.attack_families)) {
      errors.push(...validateAttackFamily(key, fam));
    }
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

function validateIndicator(ind, expectedType, attackFamilies) {
  const errors = [];
  const id = ind?.id ?? '(missing id)';

  if (!ind.id) errors.push(`indicator missing id`);
  if (ind.type !== expectedType) errors.push(`[${id}] type mismatch: got ${ind.type}, expected ${expectedType}`);
  if (!VALID_SEVERITIES.includes(ind.severity)) {
    errors.push(`[${id}] invalid severity: ${ind.severity}`);
  }
  if (!ind.attack_family) {
    errors.push(`[${id}] missing attack_family`);
  } else if (!attackFamilies[ind.attack_family]) {
    errors.push(`[${id}] references unknown attack_family: ${ind.attack_family}`);
  }
  if (!ind.first_seen) errors.push(`[${id}] missing first_seen`);
  if (!ind.source) errors.push(`[${id}] missing source`);
  if (!ind.description) errors.push(`[${id}] missing description`);

  // Required-fields rule: critical/high need remediation with at least one what_to_do step
  if (ind.severity === 'critical' || ind.severity === 'high') {
    if (!ind.remediation || !Array.isArray(ind.remediation.what_to_do) || ind.remediation.what_to_do.length === 0) {
      errors.push(`[${id}] severity=${ind.severity} requires remediation.what_to_do with at least one step`);
    }
  }

  return errors;
}

function validateAttackFamily(key, fam) {
  const errors = [];
  if (!fam.display_name) errors.push(`attack_family[${key}] missing display_name`);
  if (!fam.first_observed) errors.push(`attack_family[${key}] missing first_observed`);
  if (!fam.primary_external_source?.url) {
    errors.push(`attack_family[${key}] missing primary_external_source.url — required`);
  }
  if (fam.destructive_failsafe === true && !fam.failsafe_warning) {
    errors.push(`attack_family[${key}] destructive_failsafe=true requires failsafe_warning`);
  }
  return errors;
}
