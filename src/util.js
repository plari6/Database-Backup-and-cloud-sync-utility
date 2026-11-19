import crypto from 'node:crypto';
import { Transform } from 'node:stream';

const secrets = new Set();

/** Register a value that must never appear in logs / alerts. */
export function addSecret(v) {
  if (v && String(v).length >= 4) secrets.add(String(v));
}

/** Mask credentials in connection strings and registered secrets. */
export function redact(input) {
  let s = String(input ?? '');
  s = s.replace(/(\b[a-z][a-z0-9+.-]*:\/\/)([^:/@\s]+):([^@\s]+)@/gi, '$1$2:***@');
  s = s.replace(/(password|passwd|pwd|passphrase|secret|token)(\s*[=:]\s*)([^\s&;,'"]+)/gi, '$1$2***');
  for (const v of secrets) if (s.includes(v)) s = s.split(v).join('***');
  return s;
}

/** Counting + hashing pass-through stream. */
export class Meter extends Transform {
  constructor(algo = 'sha256') {
    super();
    this.bytes = 0;
    this.hash = algo ? crypto.createHash(algo) : null;
  }
  _transform(chunk, _enc, cb) {
    this.bytes += chunk.length;
    this.hash?.update(chunk);
    cb(null, chunk);
  }
  digest() {
    if (!this._digest) this._digest = this.hash ? this.hash.digest('hex') : null;
    return this._digest;
  }
}

export function formatBytes(n) {
  if (n == null || Number.isNaN(n)) return '-';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
}

export function formatDuration(ms) {
  if (ms == null) return '-';
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.round(s % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function formatAge(ms) {
  if (ms == null) return 'never';
  const h = ms / 3600000;
  if (h < 1) return `${Math.round(ms / 60000)} min ago`;
  if (h < 48) return `${h.toFixed(1)} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

/** 2026-11-19T02:00:00.123Z -> 20261119T020000Z */
export function backupId(date) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
}

export function parseBackupId(id) {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(id);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

export async function retry(fn, { attempts = 3, baseMs = 1000, onRetry } = {}) {
  let last;
  for (let i = 1; i <= attempts; i++) {
    try {
      return await fn(i);
    } catch (e) {
      last = e;
      if (i < attempts) {
        onRetry?.(e, i);
        await new Promise((r) => setTimeout(r, baseMs * 2 ** (i - 1)));
      }
    }
  }
  throw last;
}

/** Run async fns with a concurrency limit; returns settled results in order. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      try { out[i] = { status: 'fulfilled', value: await fn(items[i], i) }; }
      catch (e) { out[i] = { status: 'rejected', reason: e }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
