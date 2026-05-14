import { readFile } from 'node:fs/promises';
import path from 'node:path';

const MANUAL_FILE = path.resolve(process.cwd(), 'data/manual-iocs.json');

/**
 * Load IoCs from data/manual-iocs.json.
 * Returns the standard source shape consumed by aggregator/normalize.js.
 *
 * @returns {Promise<{name: string, fetched_at: string, status: 'ok'|'error', indicators: Array, attack_families: Object, error?: string}>}
 */
export async function fetchManual() {
  const fetched_at = new Date().toISOString();
  try {
    const raw = await readFile(MANUAL_FILE, 'utf8');
    const data = JSON.parse(raw);

    if (data.schema_version !== '1.0') {
      throw new Error(`unsupported schema_version: ${data.schema_version}`);
    }

    return {
      name: 'manual',
      fetched_at,
      status: 'ok',
      indicators: Array.isArray(data.indicators) ? data.indicators : [],
      attack_families: data.attack_families ?? {},
    };
  } catch (err) {
    return {
      name: 'manual',
      fetched_at,
      status: 'error',
      indicators: [],
      attack_families: {},
      error: err.message,
    };
  }
}
