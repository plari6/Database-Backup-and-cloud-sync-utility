import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import cron from 'node-cron';
import { addSecret } from './util.js';
import { DRIVER_TYPES } from './drivers/index.js';

export const DEFAULT_CONFIG_FILE = 'dbbackup.config.json';

export const DEFAULTS = {
  schedule: '0 2 * * *',
  compression: 'auto',
  timeoutMinutes: 180,
  retention: { keepLast: 7, daily: 7, weekly: 4, monthly: 6, yearly: 0 },
  alertIfNoSuccessHours: 26,
};

/**
 * Replace ${VAR} and ${VAR:-default} in every string. Missing variables are collected
 * so validation can name them instead of failing with an empty value.
 */
export function interpolate(value, env = process.env, missing = new Set()) {
  if (typeof value === 'string') {
    return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_, name, def) => {
      const v = env[name];
      if (v != null && v !== '') return v;
      if (def != null) return def;
      missing.add(name);
      return '';
    });
  }
  if (Array.isArray(value)) return value.map((v) => interpolate(v, env, missing));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = interpolate(v, env, missing);
    return out;
  }
  return value;
}

export function findConfigFile(explicit) {
  const p = explicit || process.env.DBBACKUP_CONFIG || DEFAULT_CONFIG_FILE;
  return path.resolve(p);
}

export function loadConfig(file, { env = process.env } = {}) {
  const abs = findConfigFile(file);
  if (!fs.existsSync(abs)) {
    throw new ConfigError(`Config file not found: ${abs}\nRun "dbbackup init" to create one.`);
  }
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (e) {
    throw new ConfigError(`Invalid JSON in ${abs}: ${e.message}`);
  }
  return normalizeConfig(raw, { env, baseDir: path.dirname(abs), file: abs });
}

export class ConfigError extends Error {
  constructor(msg, problems = []) {
    super(msg);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

/** Interpolate, apply defaults and validate. Throws ConfigError listing every problem. */
export function normalizeConfig(raw, { env = process.env, baseDir = process.cwd(), file = '(inline)' } = {}) {
  const missing = new Set();
  const cfg = interpolate(structuredClone(raw), env, missing);
  const problems = [];
  const resolvePath = (p) => (p ? path.resolve(baseDir, p) : p);

  cfg.file = file;
  cfg.baseDir = baseDir;
  cfg.stateDir = resolvePath(cfg.stateDir || '.dbbackup');
  cfg.tempDir = cfg.tempDir ? resolvePath(cfg.tempDir) : path.join(os.tmpdir(), 'dbbackup');
  cfg.timezone = cfg.timezone || 'UTC';
  cfg.defaults = { ...DEFAULTS, ...(cfg.defaults || {}) };
  // a retention block you write IS the policy (unset units = 0); jobs override single fields on top
  cfg.defaults.retention = raw.defaults?.retention
    ? { keepLast: 0, daily: 0, weekly: 0, monthly: 0, yearly: 0, ...cfg.defaults.retention }
    : { ...DEFAULTS.retention };
  cfg.encryption = cfg.encryption || { mode: 'key', key: env.BACKUP_ENCRYPTION_KEY };
  cfg.notify = cfg.notify || {};
  cfg.destinations = cfg.destinations || {};
  cfg.jobs = Array.isArray(cfg.jobs) ? cfg.jobs : [];

  for (const k of ['key', 'passphrase', 'privateKey']) addSecret(cfg.encryption[k]);
  for (const k of String(cfg.encryption.oldKeys || '').split(/[,\s]+/)) addSecret(k);

  // destinations
  const destNames = Object.keys(cfg.destinations);
  if (!destNames.length) problems.push('No destinations configured ("destinations": { "s3": {...} })');
  for (const [name, d] of Object.entries(cfg.destinations)) {
    d.name = name;
    if (d.type === 's3') {
      if (!d.bucket) problems.push(`destinations.${name}.bucket is empty${hint(raw.destinations?.[name]?.bucket, missing)}`);
      d.prefix = (d.prefix ?? 'backups').replace(/^\/+|\/+$/g, '');
      addSecret(d.secretAccessKey);
    } else if (d.type === 'local') {
      if (!d.path) problems.push(`destinations.${name}.path is empty`);
      d.path = resolvePath(d.path);
      d.prefix = (d.prefix ?? '').replace(/^\/+|\/+$/g, '');
    } else {
      problems.push(`destinations.${name}.type must be "s3" or "local" (got "${d.type}")`);
    }
  }

  // jobs
  const seen = new Set();
  cfg.jobs = cfg.jobs.map((j, i) => {
    const job = { ...j };
    const where = `jobs[${i}]${job.name ? ` (${job.name})` : ''}`;
    if (!job.name || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(job.name)) {
      problems.push(`${where}.name must be 1-63 chars: letters, digits, . _ -`);
    } else if (seen.has(job.name)) problems.push(`${where}: duplicate job name`);
    seen.add(job.name);
    if (!DRIVER_TYPES.includes(job.type)) problems.push(`${where}.type must be one of ${DRIVER_TYPES.join(', ')}`);

    job.schedule = job.schedule === undefined ? cfg.defaults.schedule : job.schedule;
    if (job.schedule && !cron.validate(job.schedule)) problems.push(`${where}.schedule "${job.schedule}" is not a valid cron expression`);
    job.destinations = job.destinations || cfg.defaults.destinations || destNames;
    for (const d of job.destinations) if (!cfg.destinations[d]) problems.push(`${where}.destinations: unknown destination "${d}"`);
    job.retention = { ...cfg.defaults.retention, ...(j.retention || {}) };
    job.compression = job.compression || cfg.defaults.compression;
    if (!['auto', 'gzip', 'zstd', 'none'].includes(job.compression)) problems.push(`${where}.compression must be auto, gzip, zstd or none`);
    job.timeoutMinutes = Number(job.timeoutMinutes ?? cfg.defaults.timeoutMinutes);
    job.alertIfNoSuccessHours = Number(job.alertIfNoSuccessHours ?? cfg.defaults.alertIfNoSuccessHours);
    job.enabled = job.enabled !== false;

    // required connection fields per type (name the env var if it is missing)
    const rawJob = raw.jobs?.[i] || {};
    const need = { postgres: ['url'], mysql: ['url'], mongodb: ['uri'], sqlite: ['path'], command: ['dump'] }[job.type] || [];
    for (const f of need) {
      if (!job[f]) problems.push(`${where}.${f} is empty${hint(rawJob[f], missing)}`);
    }
    if (job.type === 'sqlite' && job.path) job.path = resolvePath(job.path);
    for (const f of ['url', 'uri', 'password']) addSecret(passwordOf(job[f]));
    return job;
  });
  if (!cfg.jobs.length) problems.push('No jobs configured ("jobs": [ ... ])');

  if (problems.length) {
    throw new ConfigError(`Invalid config ${file}:\n  - ${problems.join('\n  - ')}`, problems);
  }
  return cfg;
}

function hint(rawValue, missing) {
  const names = [...String(rawValue ?? '').matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]).filter((n) => missing.has(n));
  return names.length ? ` (environment variable ${names.join(', ')} is not set)` : '';
}

function passwordOf(v) {
  if (!v) return null;
  try {
    const u = new URL(v);
    return u.password ? decodeURIComponent(u.password) : null;
  } catch {
    return null;
  }
}

export function selectJobs(cfg, names = [], { includeDisabled = false } = {}) {
  if (!names.length) return cfg.jobs.filter((j) => includeDisabled || j.enabled);
  return names.map((n) => {
    const j = cfg.jobs.find((x) => x.name === n);
    if (!j) throw new ConfigError(`Unknown job "${n}". Jobs: ${cfg.jobs.map((x) => x.name).join(', ')}`);
    return j;
  });
}
