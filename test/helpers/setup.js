import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFakeS3 } from '../../src/dev/fake-s3.js';
import { normalizeConfig } from '../../src/config.js';
import { createContext } from '../../src/engine.js';
import { generateSymmetricKey } from '../../src/crypto.js';
import { clearDestinationCache } from '../../src/destinations/index.js';
import { setLogSink } from '../../src/log.js';

export const FAKE_TOOL = path.resolve('test/helpers/fake-tool.js');
export const NODE = process.execPath;

export function tmpDir(prefix = 'dbbk-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** Engine context wired to an in-process S3 + a local folder. */
export async function setup({ jobs, retention, notify, extraDest = {}, now } = {}) {
  const root = tmpDir();
  const s3 = await startFakeS3();
  const logs = [];
  setLogSink((l) => logs.push(l));
  clearDestinationCache();
  const raw = {
    stateDir: path.join(root, 'state'),
    tempDir: path.join(root, 'tmp'),
    retryBaseMs: 10,
    encryption: { mode: 'key', key: '${KEY}' },
    destinations: {
      s3: { type: 's3', bucket: 'b', prefix: 'p', endpoint: s3.endpoint, forcePathStyle: true, region: 'us-east-1', accessKeyId: 'a', secretAccessKey: 'secret-value', ...extraDest.s3 },
      local: { type: 'local', path: path.join(root, 'nas'), ...extraDest.local },
    },
    notify: notify || {},
    defaults: { retention: retention || { keepLast: 3, daily: 0, weekly: 0, monthly: 0 } },
    jobs,
  };
  const env = { KEY: generateSymmetricKey() };
  const cfg = normalizeConfig(raw, { env, baseDir: root, file: path.join(root, `cfg-${Math.random()}.json`) });
  const ctx = createContext(cfg, now ? { now } : {});
  return {
    root, s3, cfg, ctx, logs, env,
    async close() {
      setLogSink(null);
      await s3.close();
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

/** Command-type job that dumps the given text via node. */
export function nodeCommandJob(name, script, extra = {}) {
  return { name, type: 'command', dump: `"${NODE}" -e "${script}"`, schedule: null, ...extra };
}
