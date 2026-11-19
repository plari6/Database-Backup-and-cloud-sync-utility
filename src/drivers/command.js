import { runTool, capture } from '../proc.js';
import { feed, dumpResult } from './common.js';

// Generic driver for anything that can write a dump to stdout and read it from stdin:
// redis-cli --rdb -, sqlcmd, influx backup, a vendor export script...
// job: { dump: "shell command", restore: "shell command", ext: "rdb", env: {}, version: "cmd --version" }
export function commandDriver(job, { timeoutMs } = {}) {
  const env = job.env || {};
  return {
    type: 'command',
    ext: job.ext || 'bin',
    compressedByTool: Boolean(job.compressedByTool),
    describe: () => `command: ${job.dump}`,
    version: async () => (job.version ? capture(job.version, [], { shell: true, env, timeoutMs: 20000 }) : 'custom command'),

    async dump() {
      const p = runTool(job.dump, [], { shell: true, env, timeoutMs, label: `dump command (${job.name})`, stdin: 'ignore' });
      return dumpResult(p);
    },

    async restore({ input }) {
      if (!job.restore) throw new Error(`Job "${job.name}" has no "restore" command. Use --to-file to download the dump instead.`);
      const p = runTool(job.restore, [], { shell: true, env, timeoutMs, label: `restore command (${job.name})`, stdout: 'ignore' });
      feed(input, p);
      await p.done;
    },
  };
}
