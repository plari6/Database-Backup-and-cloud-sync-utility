import { feed, dumpResult, spawnTool, toolVersion, privateTempFile, safeUrl, extraArgs } from './common.js';

// job: { uri, args, restoreArgs, docker, binDir }
// Host mode passes the URI through a private --config file (mongodump/mongorestore >= 100.3),
// so the password is not visible in the process list.
export function mongodbDriver(job, { timeoutMs } = {}) {
  const prepare = (tool, uri, args) => {
    if (job.docker) {
      // inside the container: pass the URI via env var name, expanded by sh
      const p = spawnTool(
        { ...job, tools: {} },
        'sh',
        ['-c', `exec ${tool} --uri "$DBBACKUP_MONGO_URI" "$@"`, tool, ...args],
        { DBBACKUP_MONGO_URI: uri },
        { timeoutMs, stdin: tool === 'mongodump' ? 'ignore' : 'pipe', stdout: tool === 'mongodump' ? 'pipe' : 'ignore' },
      );
      return { p, cleanup() {} };
    }
    const cfg = privateTempFile(`uri: ${JSON.stringify(uri)}\n`, '.yaml');
    const p = spawnTool(job, tool, ['--config', cfg.file, ...args], {}, {
      timeoutMs,
      stdin: tool === 'mongodump' ? 'ignore' : 'pipe',
      stdout: tool === 'mongodump' ? 'pipe' : 'ignore',
    });
    p.done.finally(cfg.cleanup).catch(() => {});
    return { p, cleanup: cfg.cleanup };
  };

  return {
    type: 'mongodb',
    ext: 'archive',
    compressedByTool: false,
    describe: () => `mongodump ${safeUrl(job.uri)}`,
    version: () => toolVersion(job, 'mongodump'),

    async dump() {
      const { p, cleanup } = prepare('mongodump', job.uri, ['--archive', ...extraArgs(job.args)]);
      return dumpResult(p, cleanup);
    },

    async restore({ input, target, clean = false, args = [] }) {
      const { p } = prepare('mongorestore', target || job.uri, [
        '--archive', ...(clean ? ['--drop'] : []), ...extraArgs(job.restoreArgs), ...args,
      ]);
      feed(input, p);
      await p.done;
    },

    async deepVerify(file) {
      // no server needed: check the archive magic number of the decrypted dump
      const fs = await import('node:fs');
      const fh = await fs.promises.open(file, 'r');
      const b = Buffer.alloc(4);
      await fh.read(b, 0, 4, 0);
      await fh.close();
      // mongodump archive magic number 0x8199e26d (little endian)
      if (b.readUInt32LE(0) !== 0x8199e26d) throw new Error('Not a mongodump archive (bad magic number)');
      return 'mongodump archive header OK';
    },
  };
}
