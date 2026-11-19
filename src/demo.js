// Offline end-to-end demo: real SQLite database, real AWS SDK against an in-process S3 server,
// a second "NAS" folder, alerts to a local webhook. Proves every promise the tool makes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { startFakeS3 } from './dev/fake-s3.js';
import { normalizeConfig } from './config.js';
import { createContext, backupJob, listBackups, verifyBackup, restoreBackup, pruneJob, jobStatus } from './engine.js';
import { createKeyring, generateSymmetricKey, generateRecipientKeyPair } from './crypto.js';
import { applyRetention } from './retention.js';
import { clearDestinationCache } from './destinations/index.js';
import { setLogSink } from './log.js';
import { formatBytes } from './util.js';

export async function runDemo({ keep = false, verbose = false, out = console.log } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dbbackup-demo-'));
  const results = [];
  const check = (name, ok, detail = '') => {
    results.push({ name, ok });
    out(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  - ${detail}` : ''}`);
  };
  if (!verbose) setLogSink(() => {});

  const s3 = await startFakeS3();
  const alerts = [];
  const hook = http.createServer((req, res) => {
    let b = '';
    req.on('data', (d) => { b += d; });
    req.on('end', () => {
      const ts = req.headers['x-dbbackup-timestamp'];
      const sig = req.headers['x-dbbackup-signature'];
      const expected = 'sha256=' + crypto.createHmac('sha256', 'demo-webhook-secret').update(`${ts}.${b}`).digest('hex');
      alerts.push({ body: JSON.parse(b), signed: sig === expected });
      res.end('ok');
    });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));

  try {
    // ---- sample production database ----
    const dbFile = path.join(root, 'shop.sqlite');
    seedDatabase(dbFile, 3000);
    const key = generateSymmetricKey();
    const env = { DEMO_KEY: key };
    const raw = {
      stateDir: path.join(root, 'state'),
      tempDir: path.join(root, 'tmp'),
      retryBaseMs: 50,
      encryption: { mode: 'key', key: '${DEMO_KEY}' },
      destinations: {
        s3: { type: 's3', bucket: 'client-backups', prefix: 'acme', endpoint: s3.endpoint, forcePathStyle: true, region: 'us-east-1', accessKeyId: 'demo', secretAccessKey: 'demo-secret' },
        nas: { type: 'local', path: path.join(root, 'nas') },
      },
      notify: { on: ['failure', 'partial', 'recovered'], webhook: { url: `http://127.0.0.1:${hook.address().port}/alerts`, secret: 'demo-webhook-secret' } },
      defaults: { retention: { keepLast: 3, daily: 7, weekly: 4, monthly: 6 } },
      jobs: [
        { name: 'shop-db', type: 'sqlite', path: dbFile, schedule: '0 2 * * *' },
        { name: 'broken-db', type: 'command', dump: 'node -e "process.stderr.write(\'FATAL: password authentication failed\'); process.exit(2)"', schedule: null },
      ],
    };
    clearDestinationCache();
    const cfg = normalizeConfig(raw, { env, baseDir: root, file: path.join(root, 'dbbackup.config.json') });
    let clock = new Date('2026-08-01T02:00:00Z');
    const ctx = createContext(cfg, { now: () => clock });
    const job = cfg.jobs[0];

    out(`\nDemo workspace: ${root}`);
    out(`Fake S3 endpoint: ${s3.endpoint}  (real AWS SDK v3 calls)\n`);

    out('1. Backup');
    const run1 = await backupJob(ctx, job);
    check('backup succeeds to S3 + NAS', run1.status === 'success' && run1.destinations.s3.ok && run1.destinations.nas.ok,
      `${formatBytes(run1.plainBytes)} -> ${formatBytes(run1.bytes)} encrypted`);
    const list = await listBackups(ctx, job, 's3');
    check('backup is listed with manifest', list.length === 1 && list[0].complete, list[0]?.dataKey);

    const stored = s3.buckets.get('client-backups').get(`acme/${list[0].dataKey}`).body;
    check('stored file is encrypted (no customer e-mails readable)', !stored.includes('customer1@example.com') && stored.subarray(0, 4).toString() === 'DBBK');

    out('\n2. Verify & restore');
    const v = await verifyBackup(ctx, job, 'latest', { deep: true });
    check('verify --deep: hash + decrypt + SQLite integrity', v.ok, v.checks.map((c) => c.detail).join(' | '));
    const restored = path.join(root, 'restored', 'shop.sqlite');
    await restoreBackup(ctx, job, 'latest', { target: restored });
    check('restore into a new database: row counts match', JSON.stringify(countRows(restored)) === JSON.stringify(countRows(dbFile)), JSON.stringify(countRows(restored)));

    out('\n3. Attacks & accidents');
    s3.tamper('client-backups', `acme/${list[0].dataKey}`, 5000);
    const vt = await verifyBackup(ctx, job, 'latest', { dest: 's3' });
    check('tampered/bit-rotted S3 object is detected', !vt.ok, vt.checks.find((c) => !c.ok)?.detail.slice(0, 70));
    let refused = false;
    try { await restoreBackup(ctx, job, 'latest', { dest: 's3', toFile: path.join(root, 'x.sqlite') }); } catch { refused = true; }
    check('restore refuses the corrupted copy', refused);
    const vn = await verifyBackup(ctx, job, 'latest', { dest: 'nas' });
    check('second copy on NAS is still good (3-2-1 rule)', vn.ok);

    const wrongCtx = createContext(cfg, { now: () => clock, keyring: createKeyring({ mode: 'key', key: generateSymmetricKey() }) });
    const vw = await verifyBackup(wrongCtx, job, 'latest', { dest: 'nas' });
    check('stolen backup is useless without the key', !vw.ok, vw.checks.find((c) => !c.ok)?.detail.slice(0, 60));

    out('\n4. Reliability');
    clock = new Date('2026-08-02T02:00:00Z');
    s3.failNext(2);
    const run2 = await backupJob(ctx, job);
    check('S3 outage (2x HTTP 503) is retried and recovers', run2.status === 'success');

    const bad = await backupJob(ctx, cfg.jobs[1]);
    await new Promise((r) => setTimeout(r, 100));
    const alert = alerts.find((a) => a.body.job === 'broken-db');
    check('failed dump is reported, not silently uploaded', bad.status === 'failure' && /password authentication failed/.test(bad.error));
    check('failure alert sent to webhook (HMAC signed)', Boolean(alert?.signed), alert ? `"${alert.body.title}"` : 'no alert');

    out('\n5. Retention (simulating 90 nightly backups)');
    for (let d = 3; d <= 92; d++) {
      clock = new Date(Date.UTC(2026, 7, d, 2, 0, 0));
      const r = await backupJob(ctx, job);
      if (r.status !== 'success') throw new Error(`simulated night ${d} failed: ${r.error}`);
    }
    const after = (await listBackups(ctx, job, 's3')).filter((b) => b.complete);
    const all = Array.from({ length: 92 }, (_, i) => ({ id: String(i), createdAt: new Date(Date.UTC(2026, 7, i + 1, 2)) }));
    const expected = applyRetention(all, job.retention).keep.size;
    check(`GFS retention keeps ${after.length} of 92 backups (last 3 + 7 daily + 4 weekly + 6 monthly)`, after.length === expected,
      `oldest kept ${after.at(-1)?.id}, newest ${after[0]?.id}`);
    const dryRun = await pruneJob(ctx, job, { dryRun: true });
    check('prune --dry-run shows why each backup is kept', dryRun[0].kept.length === expected, dryRun[0].kept[0]?.reasons.join(', '));
    const status = jobStatus(ctx, job);
    check('status: last success recorded, not stale', status.lastSuccess && !status.stale);

    out('\n6. Public-key mode (backup server cannot read its own backups)');
    const pair = generateRecipientKeyPair();
    const encOnly = createContext({ ...cfg, encryption: { mode: 'recipient', publicKey: pair.publicKeyPem } }, { now: () => new Date('2026-11-01T02:00:00Z'), keyring: createKeyring({ mode: 'recipient', publicKey: pair.publicKeyPem }) });
    const rr = await backupJob(encOnly, job);
    const vr = await verifyBackup(encOnly, job, rr.id, { dest: 'nas' });
    check('backup with public key only; server cannot decrypt', rr.status === 'success' && !vr.ok);
    const offline = createContext(cfg, { keyring: createKeyring({ mode: 'recipient', privateKey: pair.privateKeyPem }) });
    const vo = await verifyBackup(offline, job, rr.id, { dest: 'nas', deep: true });
    check('restore machine with the private key can decrypt', vo.ok);
  } finally {
    setLogSink(null);
    await s3.close();
    await new Promise((r) => hook.close(r));
    if (!keep) fs.rmSync(root, { recursive: true, force: true });
  }

  const passed = results.filter((r) => r.ok).length;
  out(`\n${passed}/${results.length} checks passed${keep ? `  (workspace kept: ${root})` : ''}`);
  return { passed, total: results.length, ok: passed === results.length };
}

function seedDatabase(file, n) {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode=WAL;
    CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, name TEXT, created_at TEXT);
    CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, total_cents INTEGER, status TEXT);
  `);
  const c = db.prepare('INSERT INTO customers (email, name, created_at) VALUES (?, ?, ?)');
  const o = db.prepare('INSERT INTO orders (customer_id, total_cents, status) VALUES (?, ?, ?)');
  db.exec('BEGIN');
  for (let i = 1; i <= n; i++) {
    c.run(`customer${i}@example.com`, `Customer ${i}`, new Date(Date.UTC(2025, 0, 1) + i * 3600_000).toISOString());
    o.run(i, 1000 + ((i * 7919) % 50000), i % 10 ? 'paid' : 'refunded');
  }
  db.exec('COMMIT');
  db.close();
}

function countRows(file) {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    return {
      customers: db.prepare('SELECT count(*) n FROM customers').get().n,
      orders: db.prepare('SELECT count(*) n FROM orders').get().n,
    };
  } finally {
    db.close();
  }
}
