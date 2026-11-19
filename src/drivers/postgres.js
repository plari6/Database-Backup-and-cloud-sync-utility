import { feed, dumpResult, spawnTool, toolVersion, parseDbUrl, safeUrl, extraArgs } from './common.js';

// job: { url, format: 'custom' | 'plain', all: false (pg_dumpall), args, restoreArgs, docker, binDir }
export function postgresDriver(job, { timeoutMs } = {}) {
  const all = Boolean(job.all);
  const format = all ? 'plain' : (job.format || 'custom');
  if (!['custom', 'plain'].includes(format)) throw new Error(`postgres format must be "custom" or "plain"`);

  const envFor = (url) => {
    const p = parseDbUrl(url);
    const env = {};
    if (p.host) env.PGHOST = p.host;
    if (p.port) env.PGPORT = p.port;
    if (p.user) env.PGUSER = p.user;
    if (p.password) env.PGPASSWORD = p.password;
    if (p.database) env.PGDATABASE = p.database;
    if (p.params.sslmode) env.PGSSLMODE = p.params.sslmode;
    if (p.params.sslrootcert) env.PGSSLROOTCERT = p.params.sslrootcert;
    if (p.params.application_name) env.PGAPPNAME = p.params.application_name;
    else env.PGAPPNAME = 'dbbackup';
    return env;
  };

  return {
    type: 'postgres',
    ext: format === 'custom' ? 'dump' : 'sql',
    // pg_dump custom format is already compressed, gzip on top gains ~nothing
    compressedByTool: format === 'custom',
    describe: () => `${all ? 'pg_dumpall' : `pg_dump (${format})`} ${safeUrl(job.url)}`,
    version: () => toolVersion(job, all ? 'pg_dumpall' : 'pg_dump'),

    async dump() {
      const env = envFor(job.url);
      const tool = all ? 'pg_dumpall' : 'pg_dump';
      const args = all
        ? ['--no-password', ...extraArgs(job.args)]
        : [`--format=${format}`, '--no-password', ...extraArgs(job.args)];
      const p = spawnTool(job, tool, args, env, { timeoutMs, stdin: 'ignore' });
      return dumpResult(p);
    },

    /** input: decompressed dump stream. target: connection URL (defaults to the job's url). */
    async restore({ input, target, clean = false, args = [] }) {
      const env = envFor(target || job.url);
      let tool;
      let a;
      if (format === 'custom') {
        tool = 'pg_restore';
        a = ['--no-password', '--dbname', env.PGDATABASE || 'postgres', ...(clean ? ['--clean', '--if-exists'] : []),
          ...(job.restoreNoOwner === false ? [] : ['--no-owner']), ...extraArgs(job.restoreArgs), ...args];
      } else {
        tool = 'psql';
        a = ['--no-password', '--set', 'ON_ERROR_STOP=1', '--quiet', '--dbname', env.PGDATABASE || 'postgres', ...extraArgs(job.restoreArgs), ...args];
      }
      const p = spawnTool(job, tool, a, env, { timeoutMs, stdout: 'ignore' });
      feed(input, p);
      await p.done;
    },

    /** Check that a decrypted dump file is a readable archive (restore drill without a database). */
    async deepVerify(file) {
      if (format !== 'custom') return 'plain SQL dump (no archive listing available)';
      const p = spawnTool(job, 'pg_restore', ['--list'], {}, { timeoutMs, stdin: 'pipe' });
      const fs = await import('node:fs');
      let out = '';
      p.stdout.on('data', (d) => { out += d.toString(); });
      fs.createReadStream(file).pipe(p.stdin);
      await p.done;
      const entries = out.split('\n').filter((l) => l && !l.startsWith(';')).length;
      if (!entries) throw new Error('pg_restore --list returned no entries');
      return `pg_restore --list: ${entries} archive entries`;
    },
  };
}
