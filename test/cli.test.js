import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { tmpDir } from './helpers/setup.js';

const BIN = path.resolve('bin/dbbackup.js');
const run = (cwd, ...args) => {
  const env = { ...process.env };
  delete env.BACKUP_ENCRYPTION_KEY; // .env values never override real env vars
  delete env.DBBACKUP_CONFIG;
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', env });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test('CLI: init -> doctor -> backup -> list -> verify -> status -> decrypt', () => {
  const dir = tmpDir('dbbk-cli-');
  try {
    // tiny SQLite "production" database
    const db = new DatabaseSync(path.join(dir, 'app.sqlite'));
    db.exec("CREATE TABLE notes(t TEXT); INSERT INTO notes VALUES ('hello backup');");
    db.close();

    let r = run(dir, 'init');
    assert.equal(r.code, 0, r.err);
    const env = fs.readFileSync(path.join(dir, '.env'), 'utf8');
    assert.match(env, /^BACKUP_ENCRYPTION_KEY=base64:[A-Za-z0-9+/=]{44}$/m);
    assert.equal(run(dir, 'init').code, 0, 'second init leaves existing files alone');
    assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), env);

    // replace the example jobs with the SQLite one + local destination only
    fs.writeFileSync(path.join(dir, 'dbbackup.config.json'), JSON.stringify({
      encryption: { key: '${BACKUP_ENCRYPTION_KEY}' },
      destinations: { local: { type: 'local', path: './backups' } },
      jobs: [{ name: 'notes', type: 'sqlite', path: 'app.sqlite' }],
    }));

    r = run(dir, 'doctor');
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, /OK\s+encryption\s+key .*round trip OK/);
    assert.match(r.out, /OK\s+destination\s+local .*write\/read\/list\/delete OK/);
    assert.match(r.out, /WARN\s+alerts/);

    r = run(dir, 'backup');
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /^SUCCESS\s+notes/m);

    r = run(dir, 'list', '--json');
    const rows = JSON.parse(r.out);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].state, 'ok');

    r = run(dir, 'verify', 'notes', '--deep');
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, /integrity_check ok/);

    r = run(dir, 'status');
    assert.equal(r.code, 0);
    assert.match(r.out, /notes\s+0 2 \* \* \*\s+success/);

    // disaster recovery: only the file + key
    const file = path.join(dir, 'backups', rows[0].key);
    r = run(dir, 'inspect', file);
    assert.equal(JSON.parse(r.out).mode, 'key');
    const key = env.match(/^BACKUP_ENCRYPTION_KEY=(.+)$/m)[1];
    r = run(dir, 'decrypt', file, '--key', key, '-o', 'plain.sqlite');
    assert.equal(r.code, 0, r.err);
    const restored = new DatabaseSync(path.join(dir, 'plain.sqlite'));
    assert.equal(restored.prepare('SELECT t FROM notes').get().t, 'hello backup');
    restored.close();

    // restore into the live source requires --yes when not interactive
    r = run(dir, 'restore', 'notes');
    assert.notEqual(r.code, 0);
    assert.match(r.err, /needs --yes/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI: missing config and bad config give clear messages and exit codes', () => {
  const dir = tmpDir('dbbk-cli-');
  try {
    let r = run(dir, 'status');
    assert.equal(r.code, 3);
    assert.match(r.err, /Config file not found[\s\S]*dbbackup init/);
    fs.writeFileSync(path.join(dir, 'dbbackup.config.json'), JSON.stringify({
      destinations: { s3: { type: 's3', bucket: '${NOPE_BUCKET}' } },
      jobs: [{ name: 'x', type: 'postgres', url: '${NOPE_URL}' }],
    }));
    r = run(dir, 'backup');
    assert.equal(r.code, 3);
    assert.match(r.err, /NOPE_URL is not set/);
    assert.match(r.err, /NOPE_BUCKET is not set/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
