import { feed, dumpResult, spawnTool, toolVersion, privateTempFile, parseDbUrl, safeUrl, extraArgs } from './common.js';

// job: { url: mysql://user:pass@host:3306/db (no db = all databases), args, restoreArgs, docker, binDir }
export function mysqlDriver(job, { timeoutMs } = {}) {
  const conn = (url) => parseDbUrl(url);

  const launch = (tool, url, args, io) => {
    const c = conn(url);
    if (job.docker) {
      const a = [...(c.host ? ['-h', c.host] : []), ...(c.port ? ['-P', c.port] : []), ...(c.user ? ['-u', c.user] : []), ...args];
      return { p: spawnTool(job, tool, a, { MYSQL_PWD: c.password }, { timeoutMs, ...io }), cleanup() {} };
    }
    const lines = ['[client]'];
    if (c.host) lines.push(`host=${c.host}`);
    if (c.port) lines.push(`port=${c.port}`);
    if (c.user) lines.push(`user=${c.user}`);
    if (c.password) lines.push(`password="${c.password.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
    if (c.params.ssl_ca) lines.push(`ssl-ca=${c.params.ssl_ca}`);
    const f = privateTempFile(lines.join('\n') + '\n');
    const p = spawnTool(job, tool, [`--defaults-extra-file=${f.file}`, ...args], {}, { timeoutMs, ...io });
    p.done.finally(f.cleanup).catch(() => {});
    return { p, cleanup: f.cleanup };
  };

  return {
    type: 'mysql',
    ext: 'sql',
    compressedByTool: false,
    describe: () => `mysqldump ${safeUrl(job.url)}`,
    version: () => toolVersion(job, 'mysqldump'),

    async dump() {
      const db = conn(job.url).database;
      const args = ['--single-transaction', '--quick', '--routines', '--triggers', '--events', '--hex-blob',
        ...extraArgs(job.args), ...(db ? ['--databases', db] : ['--all-databases'])];
      const { p, cleanup } = launch('mysqldump', job.url, args, { stdin: 'ignore' });
      return dumpResult(p, cleanup);
    },

    async restore({ input, target, args = [] }) {
      const { p } = launch('mysql', target || job.url, [...extraArgs(job.restoreArgs), ...args], { stdout: 'ignore' });
      feed(input, p);
      await p.done;
    },

    async deepVerify(file) {
      const fs = await import('node:fs');
      const text = fs.readFileSync(file, { encoding: 'utf8' }).slice(-300);
      if (!/Dump completed/.test(text)) throw new Error('mysqldump footer "Dump completed" not found: dump may be incomplete');
      return 'mysqldump footer "Dump completed" found';
    },
  };
}
