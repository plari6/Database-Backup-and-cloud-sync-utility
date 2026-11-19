import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyRetention, bucketOf } from '../src/retention.js';
import { normalizeConfig, interpolate, ConfigError } from '../src/config.js';
import { redact } from '../src/util.js';

const daily = (n, start = Date.UTC(2026, 0, 1, 2)) =>
  Array.from({ length: n }, (_, i) => ({ id: `b${i}`, createdAt: new Date(start + i * 86400_000) }));

test('GFS: last N + daily + weekly + monthly', () => {
  const backups = daily(400);
  const { keep, remove } = applyRetention(backups, { keepLast: 2, daily: 7, weekly: 4, monthly: 12 });
  // newest 7 days cover keepLast; 4 weekly overlap the newest days partially; 12 months
  assert.ok(keep.has('b399'));
  assert.ok(keep.size >= 7 + 12 - 1 && keep.size <= 2 + 7 + 4 + 12);
  assert.equal(keep.size + remove.length, 400);
  // every kept monthly backup is the newest of its month
  for (const [id, reasons] of keep) {
    if (reasons.some((r) => r.startsWith('monthly'))) {
      const b = backups.find((x) => x.id === id);
      const next = new Date(b.createdAt.getTime() + 86400_000);
      assert.ok(next.getUTCMonth() !== b.createdAt.getUTCMonth() || id === 'b399', `${id} newest of month`);
    }
  }
});

test('keepLast only, several backups per day', () => {
  const many = Array.from({ length: 10 }, (_, i) => ({ id: `x${i}`, createdAt: new Date(Date.UTC(2026, 0, 1, i)) }));
  const { keep, remove } = applyRetention(many, { keepLast: 3 });
  assert.deepEqual([...keep.keys()], ['x9', 'x8', 'x7']);
  assert.equal(remove.length, 7);
});

test('empty policy never deletes the newest backup', () => {
  const { keep, remove } = applyRetention(daily(5), {});
  assert.deepEqual([...keep.keys()], ['b4']);
  assert.equal(remove.length, 4);
});

test('day buckets honour the configured timezone', () => {
  const late = new Date('2026-03-01T23:30:00Z');
  assert.equal(bucketOf(late, 'daily', 'UTC'), '2026-3-1');
  assert.equal(bucketOf(late, 'daily', 'Asia/Dubai'), '2026-3-2');
  assert.equal(bucketOf(new Date('2026-01-01T12:00:00Z'), 'weekly'), '2026-W01');
  assert.equal(bucketOf(new Date('2027-01-01T12:00:00Z'), 'weekly'), '2026-W53');
});

const base = (jobs, extra = {}) => ({
  encryption: { key: '${K}' },
  destinations: { s3: { type: 's3', bucket: '${BUCKET}' } },
  jobs,
  ...extra,
});

test('config: env interpolation with defaults, and missing variables are named', () => {
  assert.equal(interpolate('${A:-x}-${B}', { B: 'y' }), 'x-y');
  try {
    normalizeConfig(base([{ name: 'db', type: 'postgres', url: '${PG_URL}' }]), { env: {} });
    assert.fail('should throw');
  } catch (e) {
    assert.ok(e instanceof ConfigError);
    assert.match(e.message, /jobs\[0\] \(db\)\.url is empty \(environment variable PG_URL is not set\)/);
    assert.match(e.message, /bucket is empty \(environment variable BUCKET is not set\)/);
  }
});

test('config: defaults applied and validation errors collected', () => {
  const cfg = normalizeConfig(base([{ name: 'db', type: 'mongodb', uri: 'mongodb://u:p4ss@h/db' }]), { env: { BUCKET: 'bk' } });
  const j = cfg.jobs[0];
  assert.equal(j.schedule, '0 2 * * *');
  assert.deepEqual(j.destinations, ['s3']);
  assert.equal(j.retention.daily, 7);
  assert.equal(cfg.destinations.s3.prefix, 'backups');
  assert.ok(!redact('connecting with p4ss now').includes('p4ss'), 'password registered as secret');

  assert.throws(() => normalizeConfig(base([
    { name: 'a', type: 'postgres', url: 'postgres://x', schedule: 'every day' },
    { name: 'a', type: 'oracle' },
    { name: 'bad name!', type: 'sqlite', path: 'x', destinations: ['gcs'] },
  ]), { env: { BUCKET: 'b' } }), (e) => {
    assert.match(e.message, /not a valid cron/);
    assert.match(e.message, /duplicate job name/);
    assert.match(e.message, /type must be one of/);
    assert.match(e.message, /name must be/);
    assert.match(e.message, /unknown destination "gcs"/);
    return true;
  });
});

test('redact hides credentials in URLs and key=value pairs', () => {
  assert.equal(redact('postgres://app:S3cr3t@db:5432/x'), 'postgres://app:***@db:5432/x');
  assert.equal(redact('password=hunter2 token: abc'), 'password=*** token: ***');
});
