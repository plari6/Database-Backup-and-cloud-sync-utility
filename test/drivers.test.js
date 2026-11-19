import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { backupJob, restoreBackup, verifyBackup, listBackups } from '../src/engine.js';
import { toolCommand } from '../src/drivers/common.js';
import { setup, FAKE_TOOL, NODE } from './helpers/setup.js';

const fake = { pg_dump: [NODE, FAKE_TOOL], pg_dumpall: [NODE, FAKE_TOOL], pg_restore: [NODE, FAKE_TOOL], psql: [NODE, FAKE_TOOL],
  mongodump: [NODE, FAKE_TOOL], mongorestore: [NODE, FAKE_TOOL], mysqldump: [NODE, FAKE_TOOL], mysql: [NODE, FAKE_TOOL] };

async function dumpRecord(t, job) {
  const run = await backupJob(t.ctx, job);
  assert.equal(run.status, 'success', run.error);
  const out = path.join(t.root, `${job.name}.out`);
  await restoreBackup(t.ctx, job, 'latest', { toFile: out });
  return { run, record: JSON.parse(fs.readFileSync(out, 'utf8').split('\n')[0]) };
}

test('postgres: password only in env, custom format, no double compression, restore args', async () => {
  const t = await setup({ jobs: [{ name: 'pg', type: 'postgres', url: 'postgres://app:pa%24%24word@db.internal:6543/shop?sslmode=require', tools: fake, schedule: null }] });
  try {
    const job = t.cfg.jobs[0];
    const { record } = await dumpRecord(t, job);
    assert.deepEqual(record.argv, ['--format=custom', '--no-password']);
    assert.equal(record.env.PGPASSWORD, 'pa$$word');
    assert.equal(record.env.PGHOST, 'db.internal');
    assert.equal(record.env.PGPORT, '6543');
    assert.equal(record.env.PGDATABASE, 'shop');
    assert.equal(record.env.PGSSLMODE, 'require');
    assert.ok(!JSON.stringify(record.argv).includes('pa$$word'));
    const m = await t.ctx.dest('s3').getJson((await listBackups(t.ctx, job, 's3'))[0].manifestKey);
    assert.equal(m.compression, 'none', 'pg custom format is already compressed');
    assert.ok(!m.source.includes('pa$$word'));

    const restoreOut = path.join(t.root, 'pg-restore.json');
    process.env.FAKE_RESTORE_OUT = restoreOut;
    try {
      await restoreBackup(t.ctx, job, 'latest', { target: 'postgres://u:pw@staging:5432/shop_copy', clean: true });
    } finally {
      delete process.env.FAKE_RESTORE_OUT;
    }
    const r = JSON.parse(fs.readFileSync(restoreOut, 'utf8'));
    assert.deepEqual(r.restore.argv, ['--no-password', '--dbname', 'shop_copy', '--clean', '--if-exists', '--no-owner']);
    assert.equal(r.restore.env.PGHOST, 'staging');
    assert.match(r.input, /--format=custom/);
  } finally {
    await t.close();
  }
});

test('postgres: failed pg_dump surfaces stderr and redacts nothing useful away', async () => {
  const t = await setup({ jobs: [{ name: 'pg', type: 'postgres', url: 'postgres://app:hunter22@db/shop', tools: fake, schedule: null }] });
  process.env.FAKE_EXIT = '1';
  try {
    const run = await backupJob(t.ctx, t.cfg.jobs[0]);
    assert.equal(run.status, 'failure');
    assert.match(run.error, /password authentication failed/);
    assert.ok(!run.error.includes('hunter22'));
  } finally {
    delete process.env.FAKE_EXIT;
    await t.close();
  }
});

test('mongodb: URI goes through a private --config file that is deleted afterwards', async () => {
  const t = await setup({ jobs: [{ name: 'mg', type: 'mongodb', uri: 'mongodb+srv://app:s3cret@cluster0.x.mongodb.net/shop', tools: fake, args: ['--readPreference=secondary'], schedule: null }] });
  try {
    const { record, run } = await dumpRecord(t, t.cfg.jobs[0]);
    assert.equal(record.argv[0], '--config');
    assert.deepEqual(record.argv.slice(2), ['--archive', '--readPreference=secondary']);
    assert.equal(record.credFile.trim(), 'uri: "mongodb+srv://app:s3cret@cluster0.x.mongodb.net/shop"');
    assert.ok(!fs.existsSync(record.argv[1]), 'credential file removed');
    assert.ok(run.bytes > 0);
  } finally {
    await t.close();
  }
});

test('mysql: credentials via --defaults-extra-file, consistent single-transaction dump', async () => {
  const t = await setup({ jobs: [{ name: 'my', type: 'mysql', url: 'mysql://root:p%22w@127.0.0.1:3307/crm', tools: fake, schedule: null }] });
  try {
    const { record } = await dumpRecord(t, t.cfg.jobs[0]);
    assert.match(record.argv[0], /^--defaults-extra-file=/);
    assert.ok(record.argv.includes('--single-transaction'));
    assert.deepEqual(record.argv.slice(-2), ['--databases', 'crm']);
    assert.match(record.credFile, /password="p\\"w"/);
    assert.match(record.credFile, /port=3307/);
  } finally {
    await t.close();
  }
});

test('docker mode passes secrets by env NAME only', () => {
  const c = toolCommand({ docker: 'pg-prod' }, 'pg_dump', ['--format=custom'], { PGPASSWORD: 'x', PGUSER: 'app' });
  assert.equal(c.cmd, 'docker');
  assert.deepEqual(c.args, ['exec', '-i', '-e', 'PGPASSWORD', '-e', 'PGUSER', 'pg-prod', 'pg_dump', '--format=custom']);
  assert.ok(!c.args.includes('x'));
  assert.equal(c.env.PGPASSWORD, 'x');
});

test('sqlite: online backup of a WAL database, deep verify, restore with --clean only', async () => {
  const t = await setup({ jobs: [{ name: 'lite', type: 'sqlite', path: 'app.sqlite', schedule: null }] });
  try {
    const job = t.cfg.jobs[0];
    const db = new DatabaseSync(job.path);
    db.exec("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (1),(2),(3);");
    // keep the connection open (app still running) while we back up
    const run = await backupJob(t.ctx, job);
    db.close();
    assert.equal(run.status, 'success', run.error);
    const v = await verifyBackup(t.ctx, job, 'latest', { deep: true });
    assert.ok(v.ok, JSON.stringify(v.checks));
    assert.match(v.checks.at(-1).detail, /integrity_check ok, 1 tables/);
    await assert.rejects(restoreBackup(t.ctx, job, 'latest', { confirm: true }), /exists. Use --clean/);
    const copy = path.join(t.root, 'copy.sqlite');
    await restoreBackup(t.ctx, job, 'latest', { target: copy });
    const c = new DatabaseSync(copy);
    assert.equal(c.prepare('SELECT count(*) n FROM t').get().n, 3);
    c.close();
  } finally {
    await t.close();
  }
});
