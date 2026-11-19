import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Writable, PassThrough } from 'node:stream';
import { createDriver } from './drivers/index.js';
import { getDestination, objectKeys } from './destinations/index.js';
import { createEncryptStream, createDecryptStream, createKeyring } from './crypto.js';
import { applyRetention } from './retention.js';
import { createState } from './state.js';
import { notify, ping } from './notify.js';
import { log } from './log.js';
import { Meter, backupId, parseBackupId, retry, mapLimit, formatBytes, formatDuration, redact } from './util.js';

export const APP_VERSION = '1.0.0';
const ZSTD = typeof zlib.createZstdCompress === 'function';

export class BackupError extends Error {}

/**
 * Shared context for all operations.
 * opts: { now: () => Date, destOverrides: { [destName]: { client } }, keyring }
 */
export function createContext(cfg, opts = {}) {
  return {
    cfg,
    state: createState(cfg.stateDir),
    keyring: opts.keyring || createKeyring(cfg.encryption),
    now: opts.now || (() => new Date()),
    dest: (name) => getDestination(cfg, name, opts.destOverrides?.[name] || {}),
  };
}

// ---------- compression ----------

export function pickCompression(job, driver) {
  if (job.compression === 'auto') return driver.compressedByTool ? 'none' : (ZSTD && job.preferZstd ? 'zstd' : 'gzip');
  if (job.compression === 'zstd' && !ZSTD) {
    log.warn(`zstd is not available in Node ${process.version}; using gzip`);
    return 'gzip';
  }
  return job.compression;
}

function compressor(kind, level) {
  if (kind === 'gzip') return zlib.createGzip({ level: level ?? 6 });
  if (kind === 'zstd') {
    return zlib.createZstdCompress(level ? { params: { [zlib.constants.ZSTD_c_compressionLevel]: level } } : {});
  }
  return null;
}

function decompressor(kind) {
  if (kind === 'gzip') return zlib.createGunzip();
  if (kind === 'zstd') {
    if (!ZSTD) throw new BackupError('This backup is zstd-compressed; use Node >= 22.15 to restore it');
    return zlib.createZstdDecompress();
  }
  return null;
}

const compExt = (kind) => ({ gzip: '.gz', zstd: '.zst' }[kind] || '');

// ---------- backup ----------

export async function backupJob(ctx, job, { dryRun = false } = {}) {
  const { cfg, state, keyring } = ctx;
  const started = ctx.now();
  const id = backupId(started);
  const t0 = Date.now();
  const run = { job: job.name, id, startedAt: started.toISOString(), status: 'running', destinations: {} };
  const previous = state.lastRun(job.name);
  let unlock = () => {};
  let tmpFile = null;
  let dump = null;

  try {
    unlock = state.lock(job.name);
    if (!keyring.canEncrypt) throw new BackupError(`Encryption is not configured (${keyring.describe()}). Run "dbbackup keygen".`);
    const driver = createDriver(job);
    const compression = pickCompression(job, driver);
    const fileExt = `${driver.ext}${compExt(compression)}`;
    const keys = objectKeys(job.name, id, fileExt);
    log.info(`[${job.name}] backup ${id} started: ${driver.describe()} -> ${job.destinations.join(', ')}`);
    if (dryRun) {
      log.info(`[${job.name}] dry run: would write ${keys.data} (compression ${compression}, encryption ${keyring.describe()})`);
      run.status = 'dry-run';
      return run;
    }
    await ping(job.healthcheckUrl, 'start');

    fs.mkdirSync(cfg.tempDir, { recursive: true });
    checkDiskSpace(cfg.tempDir, state.lastRun(job.name, 'success')?.bytes);
    tmpFile = path.join(cfg.tempDir, `${job.name}-${id}-${process.pid}.dbbk.partial`);

    const toolVersion = await driver.version().catch(() => 'unknown');
    const params = await keyring.encryptParams();
    dump = await driver.dump();

    const plain = new Meter('sha256');
    const enc = new Meter('sha256');
    const md5 = new Meter('md5');
    const stages = [dump.stream, plain];
    const comp = compressor(compression, job.compressionLevel);
    if (comp) stages.push(comp);
    stages.push(createEncryptStream(params), enc, md5, fs.createWriteStream(tmpFile));

    try {
      await Promise.all([pipeline(stages), dump.done]);
    } catch (e) {
      dump.abort?.();
      throw e;
    }
    if (plain.bytes === 0) throw new BackupError('Dump produced 0 bytes. Check credentials, database name and permissions.');

    const finishedAt = ctx.now();
    const manifest = {
      format: 'dbbackup/1',
      id,
      job: job.name,
      type: job.type,
      source: redact(driver.describe()),
      host: os.hostname(),
      createdAt: started.toISOString(),
      finishedAt: finishedAt.toISOString(),
      dumpDurationMs: Date.now() - t0,
      dataKey: keys.data,
      dump: { ext: driver.ext, bytes: plain.bytes, sha256: plain.digest(), tool: toolVersion },
      compression,
      encryption: { mode: keyring.mode, keyId: params.keyId.toString('hex'), cipher: 'AES-256-GCM-STREAM/HKDF-SHA256' },
      file: { bytes: enc.bytes, sha256: enc.digest() },
      app: `dbbackup ${APP_VERSION}`,
    };
    log.info(`[${job.name}] dump ${formatBytes(plain.bytes)} -> ${formatBytes(enc.bytes)} encrypted (${compression}) in ${formatDuration(Date.now() - t0)}`);

    // upload data first, manifest last: a manifest means "this backup is complete"
    const results = await mapLimit(job.destinations, 3, async (name) => {
      const dest = ctx.dest(name);
      const tUp = Date.now();
      await retry(() => dest.putFile(keys.data, tmpFile, {
        size: enc.bytes, sha256: manifest.file.sha256, md5: md5.digest(),
        metadata: { sha256: manifest.file.sha256, job: job.name, 'backup-id': id },
      }), { attempts: 3, baseMs: ctx.cfg.retryBaseMs ?? 2000, onRetry: (e, i) => log.warn(`[${job.name}] upload to ${name} failed (attempt ${i}): ${e.message}`) });
      await retry(() => dest.putJson(keys.manifest, { ...manifest, destination: name }), { attempts: 3, baseMs: ctx.cfg.retryBaseMs ?? 1000 });
      log.info(`[${job.name}] uploaded to ${name} (${dest.describe()}) in ${formatDuration(Date.now() - tUp)}`);
    });
    results.forEach((r, i) => {
      const name = job.destinations[i];
      run.destinations[name] = r.status === 'fulfilled' ? { ok: true } : { ok: false, error: redact(r.reason?.message) };
      if (r.status === 'rejected') log.error(`[${job.name}] destination ${name} failed: ${r.reason?.message}`);
    });
    const okCount = Object.values(run.destinations).filter((d) => d.ok).length;
    run.status = okCount === job.destinations.length ? 'success' : okCount ? 'partial' : 'failure';
    if (!okCount) run.error = 'All destinations failed';
    run.bytes = enc.bytes;
    run.plainBytes = plain.bytes;
    run.sha256 = manifest.file.sha256;
    run.dataKey = keys.data;

    // retention only where this backup landed safely
    if (okCount) {
      let pruned = 0;
      for (const [name, r] of Object.entries(run.destinations)) {
        if (!r.ok) continue;
        try {
          pruned += (await pruneDestination(ctx, job, name)).removed.length;
        } catch (e) {
          log.warn(`[${job.name}] retention on ${name} failed: ${e.message}`);
        }
      }
      run.pruned = pruned;
    }
  } catch (e) {
    run.status = 'failure';
    run.error = redact(e.message);
    log.error(`[${job.name}] backup failed: ${run.error}`);
  } finally {
    if (tmpFile) fs.rmSync(tmpFile, { force: true });
    try { dump?.cleanup?.(); } catch { /* ignore */ }
    unlock();
  }

  run.finishedAt = ctx.now().toISOString();
  run.durationMs = Date.now() - t0;
  state.recordRun(run);
  if (run.status === 'success') log.info(`[${job.name}] backup ${id} OK in ${formatDuration(run.durationMs)}`);

  const ev = { job: job.name, run, host: os.hostname() };
  if (run.status === 'success') {
    state.clearAlert(`stale:${job.name}`);
    await ping(job.healthcheckUrl, 'success', `backup ${id} ${formatBytes(run.bytes)}`);
    const recovered = previous && previous.status !== 'success';
    await notify(ctx.cfg, { ...ev, type: recovered ? 'recovered' : 'success' });
  } else {
    await ping(job.healthcheckUrl, 'fail', run.error || run.status);
    await notify(ctx.cfg, { ...ev, type: run.status === 'partial' ? 'partial' : 'failure', lastSuccess: state.lastRun(job.name, 'success')?.finishedAt || 'never' });
  }
  return run;
}

function checkDiskSpace(dir, lastBytes) {
  if (!lastBytes || typeof fs.statfsSync !== 'function') return;
  try {
    const s = fs.statfsSync(dir);
    const free = Number(s.bavail) * Number(s.bsize);
    if (free < lastBytes * 1.5) {
      log.warn(`Low disk space in temp dir ${dir}: ${formatBytes(free)} free, last backup was ${formatBytes(lastBytes)}. Set "tempDir" to a bigger volume.`);
    }
  } catch { /* not supported */ }
}

// ---------- catalog ----------

/** List backups of a job on one destination (no manifest downloads needed). */
export async function listBackups(ctx, job, destName) {
  const dest = ctx.dest(destName);
  const objects = await dest.list(`${job.name}/`);
  const esc = job.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?:^|/)${esc}-(\\d{8}T\\d{6}Z)\\.(.+)$`);
  const byId = new Map();
  for (const o of objects) {
    const m = re.exec(o.key);
    if (!m) continue;
    const [, id, rest] = m;
    const e = byId.get(id) || { id, createdAt: parseBackupId(id), destination: destName };
    if (rest === 'manifest.json') e.manifestKey = o.key;
    else if (rest.endsWith('.dbbk')) { e.dataKey = o.key; e.size = o.size; e.lastModified = o.lastModified; }
    byId.set(id, e);
  }
  return [...byId.values()]
    .map((e) => ({ ...e, complete: Boolean(e.manifestKey && e.dataKey) }))
    .sort((a, b) => b.createdAt - a.createdAt);
}

export async function resolveBackup(ctx, job, ref = 'latest', destName) {
  const dests = destName ? [destName] : job.destinations;
  const errors = [];
  for (const d of dests) {
    try {
      const list = (await listBackups(ctx, job, d)).filter((b) => b.complete);
      const found = ref === 'latest' ? list[0] : list.find((b) => b.id === ref || b.dataKey.endsWith(ref));
      if (found) return found;
      errors.push(`${d}: ${list.length ? `no backup "${ref}"` : 'no backups'}`);
    } catch (e) {
      errors.push(`${d}: ${e.message}`);
    }
  }
  throw new BackupError(`Backup "${ref}" of job ${job.name} not found (${errors.join('; ')})`);
}

// ---------- verify & restore ----------

/**
 * Download, check the file hash, decrypt (authenticates every block), decompress and compare the dump hash.
 * deep: also run the driver's archive check (pg_restore --list, SQLite integrity_check...).
 */
export async function verifyBackup(ctx, job, ref = 'latest', { dest, deep = false } = {}) {
  const t0 = Date.now();
  const entry = await resolveBackup(ctx, job, ref, dest);
  const d = ctx.dest(entry.destination);
  const manifest = await d.getJson(entry.manifestKey);
  const enc = new Meter('sha256');
  const plain = new Meter('sha256');
  let deepFile = null;
  const stages = [await d.getStream(entry.dataKey), enc, createDecryptStream(ctx.keyring)];
  const dc = decompressor(manifest.compression);
  if (dc) stages.push(dc);
  stages.push(plain);
  if (deep) {
    fs.mkdirSync(ctx.cfg.tempDir, { recursive: true });
    deepFile = path.join(ctx.cfg.tempDir, `verify-${job.name}-${entry.id}-${process.pid}.${manifest.dump.ext}`);
    stages.push(fs.createWriteStream(deepFile));
  } else {
    stages.push(new Writable({ write(_c, _e, cb) { cb(); } }));
  }

  const report = { job: job.name, id: entry.id, destination: entry.destination, checks: [], ok: false };
  try {
    await pipeline(stages);
    const fileOk = enc.digest() === manifest.file.sha256 && enc.bytes === manifest.file.bytes;
    report.checks.push({ name: 'file sha256', ok: fileOk, detail: `${formatBytes(enc.bytes)} ${enc.digest().slice(0, 16)}...` });
    report.checks.push({ name: 'decrypt + authenticate', ok: true, detail: `${manifest.encryption.mode} ${manifest.encryption.keyId}` });
    const dumpOk = plain.digest() === manifest.dump.sha256 && plain.bytes === manifest.dump.bytes;
    report.checks.push({ name: 'dump sha256', ok: dumpOk, detail: `${formatBytes(plain.bytes)} raw` });
    if (deep && fileOk && dumpOk) {
      const driver = createDriver(job);
      if (driver.deepVerify) {
        try {
          report.checks.push({ name: 'archive check', ok: true, detail: await driver.deepVerify(deepFile) });
        } catch (e) {
          report.checks.push({ name: 'archive check', ok: false, detail: redact(e.message) });
        }
      }
    }
  } catch (e) {
    report.checks.push({ name: 'decrypt + authenticate', ok: false, detail: redact(e.message) });
  } finally {
    if (deepFile) fs.rmSync(deepFile, { force: true });
  }
  report.ok = report.checks.length > 0 && report.checks.every((c) => c.ok);
  report.durationMs = Date.now() - t0;
  return report;
}

/**
 * Restore a backup. Exactly one of:
 *   toFile: write the decrypted, decompressed dump to a file (for manual inspection / other tools)
 *   target: database URL / path to restore into (default: the job's own source, needs confirm=true)
 */
export async function restoreBackup(ctx, job, ref = 'latest', { dest, toFile, target, clean = false, confirm = false, args = [] } = {}) {
  const entry = await resolveBackup(ctx, job, ref, dest);
  const d = ctx.dest(entry.destination);
  const manifest = await d.getJson(entry.manifestKey);
  if (manifest.job !== job.name) throw new BackupError(`Manifest belongs to job ${manifest.job}`);
  if (!toFile && !target && !confirm) {
    throw new BackupError(`Refusing to restore into the job's own source database without confirmation (use --yes, or --target / --to-file).`);
  }

  // 1. download the encrypted file and check its hash BEFORE touching any database
  fs.mkdirSync(ctx.cfg.tempDir, { recursive: true });
  const encFile = path.join(ctx.cfg.tempDir, `restore-${job.name}-${entry.id}-${process.pid}.dbbk`);
  try {
    const enc = new Meter('sha256');
    await pipeline(await d.getStream(entry.dataKey), enc, fs.createWriteStream(encFile));
    if (enc.digest() !== manifest.file.sha256) {
      throw new BackupError(`Downloaded file hash does not match the manifest (corrupted or tampered). Expected ${manifest.file.sha256}, got ${enc.digest()}`);
    }
    log.info(`[${job.name}] downloaded ${entry.id} from ${entry.destination} (${formatBytes(enc.bytes)}), hash OK`);

    // 2. decrypt + decompress, streaming into the target
    const plain = new Meter('sha256');
    const stages = [fs.createReadStream(encFile), createDecryptStream(ctx.keyring)];
    const dc = decompressor(manifest.compression);
    if (dc) stages.push(dc);
    stages.push(plain);

    if (toFile) {
      const out = path.resolve(toFile);
      await pipeline([...stages, fs.createWriteStream(out)]);
      if (plain.digest() !== manifest.dump.sha256) throw new BackupError('Restored dump hash mismatch');
      return { id: entry.id, destination: entry.destination, toFile: out, bytes: plain.bytes };
    }

    const driver = createDriver(job);
    const pass = new PassThrough();
    // if the restore tool dies early, unblock the pipeline (backpressure would otherwise hang it)
    const restoring = driver.restore({ input: pass, target, clean, args }).catch((e) => {
      pass.destroy(e);
      throw e;
    });
    await Promise.all([pipeline([...stages, pass]), restoring]);
    if (plain.digest() !== manifest.dump.sha256) throw new BackupError('Restored dump hash mismatch');
    return { id: entry.id, destination: entry.destination, target: target ? redact(target) : '(job source)', bytes: plain.bytes };
  } finally {
    fs.rmSync(encFile, { force: true });
  }
}

// ---------- retention ----------

export async function pruneDestination(ctx, job, destName, { dryRun = false } = {}) {
  const dest = ctx.dest(destName);
  const all = await listBackups(ctx, job, destName);
  const complete = all.filter((b) => b.complete);
  const { keep, remove } = applyRetention(complete, job.retention, { timeZone: ctx.cfg.timezone });
  const removeSet = new Set(remove);
  const keys = [];
  for (const b of complete) if (removeSet.has(b.id)) keys.push(b.dataKey, b.manifestKey);

  // incomplete uploads (data without manifest) older than a day
  const dayAgo = ctx.now().getTime() - 86400_000;
  const orphans = all.filter((b) => !b.complete && b.createdAt.getTime() < dayAgo);
  for (const o of orphans) keys.push(...[o.dataKey, o.manifestKey].filter(Boolean));

  if (keys.length && !dryRun) {
    await dest.remove(keys);
    log.info(`[${job.name}] retention on ${destName}: kept ${keep.size}, deleted ${remove.length}${orphans.length ? ` + ${orphans.length} incomplete` : ''}`);
  }
  return {
    destination: destName,
    kept: complete.filter((b) => keep.has(b.id)).map((b) => ({ id: b.id, reasons: keep.get(b.id) })),
    removed: remove,
    orphans: orphans.map((o) => o.id),
  };
}

export async function pruneJob(ctx, job, opts = {}) {
  const dests = opts.dest ? [opts.dest] : job.destinations;
  const out = [];
  for (const d of dests) out.push(await pruneDestination(ctx, job, d, opts));
  return out;
}

// ---------- status ----------

export function jobStatus(ctx, job) {
  const last = ctx.state.lastRun(job.name);
  const ok = ctx.state.lastRun(job.name, 'success');
  const ageMs = ok ? ctx.now() - new Date(ok.finishedAt) : null;
  const stale = job.enabled && Boolean(job.schedule) && (ageMs == null || ageMs > job.alertIfNoSuccessHours * 3600_000);
  return { job: job.name, type: job.type, schedule: job.schedule || '(manual)', last, lastSuccess: ok, ageMs, stale };
}

/** Called hourly by the daemon: alert once a day per job with no recent success. */
export async function checkStale(ctx, jobs, { since } = {}) {
  const alerts = [];
  for (const job of jobs) {
    const s = jobStatus(ctx, job);
    if (!s.stale) continue;
    // a brand-new install has no history: give it the full window before alerting
    if (!s.lastSuccess && since && ctx.now() - since < job.alertIfNoSuccessHours * 3600_000) continue;
    const key = `stale:${job.name}`;
    if (ctx.state.alertSentWithin(key, 24 * 3600_000)) continue;
    ctx.state.markAlert(key);
    alerts.push(job.name);
    await notify(ctx.cfg, { type: 'stale', job: job.name, hours: job.alertIfNoSuccessHours, lastSuccess: s.lastSuccess?.finishedAt || 'never', host: os.hostname() });
  }
  return alerts;
}
