import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {
  backupJob, listBackups, verifyBackup, restoreBackup, pruneJob, checkStale, jobStatus,
} from '../src/engine.js';
import { setup, nodeCommandJob, NODE } from './helpers/setup.js';

const payload = (n) => `process.stdout.write('row,'.repeat(${n}))`;

test('backup -> both destinations, manifest, list, verify, restore to file', async () => {
  const t = await setup({ jobs: [nodeCommandJob('app', payload(50000), { ext: 'csv' })] });
  try {
    const job = t.cfg.jobs[0];
    const run = await backupJob(t.ctx, job);
    assert.equal(run.status, 'success', run.error);
    assert.deepEqual(Object.keys(run.destinations), ['s3', 'local']);
    assert.equal(run.plainBytes, 200000);
    assert.ok(run.bytes < run.plainBytes, 'compressed');

    const [entry] = await listBackups(t.ctx, job, 's3');
    assert.ok(entry.complete);
    assert.match(entry.dataKey, /^app\/\d{4}\/\d{2}\/app-\d{8}T\d{6}Z\.csv\.gz\.dbbk$/);
    const stored = t.s3.buckets.get('b').get(`p/${entry.dataKey}`);
    assert.equal(stored.metadata.sha256, run.sha256);

    const manifest = await t.ctx.dest('local').getJson(entry.manifestKey);
    assert.equal(manifest.compression, 'gzip');
    assert.equal(manifest.dump.bytes, 200000);
    assert.equal(manifest.encryption.mode, 'key');

    for (const d of ['s3', 'local']) {
      const v = await verifyBackup(t.ctx, job, 'latest', { dest: d });
      assert.ok(v.ok, JSON.stringify(v.checks));
    }
    const out = path.join(t.root, 'restored.csv');
    const r = await restoreBackup(t.ctx, job, entry.id, { toFile: out });
    assert.equal(r.bytes, 200000);
    assert.equal(fs.readFileSync(out, 'utf8'), 'row,'.repeat(50000));
  } finally {
    await t.close();
  }
});

test('a failing dump uploads nothing, reports stderr, alerts webhook', async () => {
  const hits = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { hits.push(JSON.parse(b)); res.end(); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const t = await setup({
    jobs: [nodeCommandJob('bad', "process.stdout.write('partial data'); process.stderr.write('ERROR: permission denied for table users'); process.exit(1)")],
    notify: { webhook: { url: `http://127.0.0.1:${srv.address().port}` } },
  });
  try {
    const run = await backupJob(t.ctx, t.cfg.jobs[0]);
    assert.equal(run.status, 'failure');
    assert.match(run.error, /exited with code 1[\s\S]*permission denied/);
    assert.equal((await listBackups(t.ctx, t.cfg.jobs[0], 's3')).length, 0);
    assert.equal(fs.readdirSync(t.cfg.tempDir).length, 0, 'temp file removed');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].event, 'failure');
  } finally {
    await t.close();
    srv.close();
  }
});

test('empty dump is a failure', async () => {
  const t = await setup({ jobs: [nodeCommandJob('empty', '0')] });
  try {
    const run = await backupJob(t.ctx, t.cfg.jobs[0]);
    assert.equal(run.status, 'failure');
    assert.match(run.error, /0 bytes/);
  } finally {
    await t.close();
  }
});

test('S3 503s are retried; a dead destination makes the run "partial"', async () => {
  const t = await setup({ jobs: [nodeCommandJob('app', payload(100))] });
  try {
    const job = t.cfg.jobs[0];
    t.s3.failNext(2);
    assert.equal((await backupJob(t.ctx, job)).status, 'success');

    // break the local destination: its root path is a file
    const blocker = path.join(t.root, 'blocker');
    fs.writeFileSync(blocker, 'x');
    t.cfg.destinations.local.path = blocker;
    const { clearDestinationCache } = await import('../src/destinations/index.js');
    clearDestinationCache();
    const run = await backupJob(t.ctx, job);
    assert.equal(run.status, 'partial');
    assert.equal(run.destinations.s3.ok, true);
    assert.equal(run.destinations.local.ok, false);
  } finally {
    await t.close();
  }
});

test('large backups use S3 multipart upload and still verify', async () => {
  const t = await setup({
    jobs: [nodeCommandJob('big', "const c=require('crypto');for(let i=0;i<12;i++)process.stdout.write(c.randomBytes(1048576))", { compression: 'none' })],
    extraDest: { s3: { multipartThresholdMB: 5, partSizeMB: 5 } },
  });
  try {
    const job = t.cfg.jobs[0];
    const run = await backupJob(t.ctx, job);
    assert.equal(run.status, 'success', run.error);
    assert.ok(t.s3.stats.multipart >= 1, 'multipart used');
    assert.ok((await verifyBackup(t.ctx, job, 'latest', { dest: 's3' })).ok);
  } finally {
    await t.close();
  }
});

test('tampered object: verify fails, restore refuses before touching the target', async () => {
  const t = await setup({ jobs: [nodeCommandJob('app', payload(1000))] });
  try {
    const job = t.cfg.jobs[0];
    await backupJob(t.ctx, job);
    const [e] = await listBackups(t.ctx, job, 's3');
    t.s3.tamper('b', `p/${e.dataKey}`, 100);
    const v = await verifyBackup(t.ctx, job, 'latest', { dest: 's3' });
    assert.equal(v.ok, false);
    const out = path.join(t.root, 'never.txt');
    await assert.rejects(restoreBackup(t.ctx, job, 'latest', { dest: 's3', toFile: out }), /hash does not match/);
    assert.equal(fs.existsSync(out), false);
  } finally {
    await t.close();
  }
});

test('restore into the source database needs explicit confirmation', async () => {
  const t = await setup({ jobs: [nodeCommandJob('app', payload(10), { restore: `"${NODE}" -e "process.stdin.resume()"` })] });
  try {
    await backupJob(t.ctx, t.cfg.jobs[0]);
    await assert.rejects(restoreBackup(t.ctx, t.cfg.jobs[0], 'latest'), /without confirmation/);
    await restoreBackup(t.ctx, t.cfg.jobs[0], 'latest', { confirm: true });
  } finally {
    await t.close();
  }
});

test('a restore tool that fails does not hang the pipeline', async () => {
  const t = await setup({ jobs: [nodeCommandJob('app', payload(400000), { restore: `"${NODE}" -e "process.exit(3)"` })] });
  try {
    await backupJob(t.ctx, t.cfg.jobs[0]);
    await assert.rejects(restoreBackup(t.ctx, t.cfg.jobs[0], 'latest', { confirm: true }), /exited with code 3/);
  } finally {
    await t.close();
  }
});

test('retention prunes after each backup and removes stale incomplete uploads', async () => {
  let clock = new Date('2026-01-01T02:00:00Z');
  const t = await setup({ jobs: [nodeCommandJob('app', payload(10))], retention: { keepLast: 2 }, now: () => clock });
  try {
    const job = t.cfg.jobs[0];
    // an upload that died before its manifest was written
    await t.ctx.dest('s3').putJson('app/2025/12/app-20251230T020000Z.bin.gz.dbbk', { junk: true });
    for (let d = 1; d <= 5; d++) {
      clock = new Date(Date.UTC(2026, 0, d, 2));
      assert.equal((await backupJob(t.ctx, job)).status, 'success');
    }
    for (const d of ['s3', 'local']) {
      const ids = (await listBackups(t.ctx, job, d)).map((b) => b.id);
      assert.deepEqual(ids, ['20260105T020000Z', '20260104T020000Z'], d);
    }
    const dry = await pruneJob(t.ctx, job, { dryRun: true });
    assert.equal(dry[0].removed.length, 0);
  } finally {
    await t.close();
  }
});

test('lock prevents two runs of the same job', async () => {
  const t = await setup({ jobs: [nodeCommandJob('slow', "setTimeout(()=>process.stdout.write('x'),800)")] });
  try {
    const job = t.cfg.jobs[0];
    const [a, b] = await Promise.all([backupJob(t.ctx, job), new Promise((r) => setTimeout(r, 100)).then(() => backupJob(t.ctx, job))]);
    assert.equal(a.status, 'success');
    assert.equal(b.status, 'failure');
    assert.match(b.error, /already running/);
  } finally {
    await t.close();
  }
});

test('stale watchdog alerts once per day, status flags it', async () => {
  let clock = new Date('2026-05-01T02:00:00Z');
  const hits = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { hits.push(JSON.parse(b)); res.end(); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const t = await setup({
    jobs: [nodeCommandJob('app', payload(10), { schedule: '0 2 * * *' })],
    notify: { webhook: { url: `http://127.0.0.1:${srv.address().port}` } },
    now: () => clock,
  });
  try {
    const job = t.cfg.jobs[0];
    await backupJob(t.ctx, job);
    assert.equal(jobStatus(t.ctx, job).stale, false);
    clock = new Date('2026-05-02T06:00:00Z'); // 28 h later
    assert.equal(jobStatus(t.ctx, job).stale, true);
    assert.deepEqual(await checkStale(t.ctx, [job]), ['app']);
    assert.deepEqual(await checkStale(t.ctx, [job]), [], 'not twice');
    assert.equal(hits.filter((h) => h.event === 'stale').length, 1);
  } finally {
    await t.close();
    srv.close();
  }
});
