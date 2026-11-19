import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { DatabaseSync, backup } from 'node:sqlite';

// job: { path } - online, consistent copy via the SQLite backup API (safe while the app writes).
export function sqliteDriver(job) {
  return {
    type: 'sqlite',
    ext: 'sqlite',
    compressedByTool: false,
    describe: () => `sqlite ${job.path}`,
    version: async () => `node:sqlite (Node ${process.version})`,

    async dump() {
      if (!fs.existsSync(job.path)) throw new Error(`SQLite file not found: ${job.path}`);
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dbbk-sqlite-'));
      const copy = path.join(dir, 'snapshot.sqlite');
      const src = new DatabaseSync(job.path, { readOnly: true });
      try {
        await backup(src, copy);
      } finally {
        src.close();
      }
      const stream = fs.createReadStream(copy);
      const done = new Promise((resolve, reject) => {
        stream.on('close', resolve);
        stream.on('error', reject);
      });
      return { stream, done, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
    },

    async restore({ input, target, clean = false }) {
      const dest = path.resolve(target || job.path);
      if (fs.existsSync(dest) && !clean) {
        throw new Error(`Target ${dest} exists. Use --clean to overwrite it (or restore to another --target path).`);
      }
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      const tmp = `${dest}.restoring-${process.pid}`;
      await pipeline(input, fs.createWriteStream(tmp));
      verifyFile(tmp);
      fs.rmSync(`${dest}-wal`, { force: true });
      fs.rmSync(`${dest}-shm`, { force: true });
      fs.renameSync(tmp, dest);
    },

    async deepVerify(file) {
      return verifyFile(file);
    },
  };
}

function verifyFile(file) {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const r = db.prepare('PRAGMA integrity_check').get();
    const ok = Object.values(r)[0];
    if (ok !== 'ok') throw new Error(`SQLite integrity_check failed: ${ok}`);
    const tables = db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table'").get().n;
    return `SQLite integrity_check ok, ${tables} tables`;
  } finally {
    db.close();
  }
}
