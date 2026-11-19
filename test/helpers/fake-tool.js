// Stand-in for pg_dump / mongodump / mysqldump / pg_restore / mongorestore / mysql in tests.
// Dump mode (no stdin): prints a JSON "dump" describing how it was invoked (argv, env, credential file).
// Restore mode (FAKE_RESTORE_OUT set): copies stdin to that file plus an invocation record.
import fs from 'node:fs';

const argv = process.argv.slice(2);
const credFlag = argv.find((a) => a.startsWith('--defaults-extra-file='));
const cfgIdx = argv.indexOf('--config');
const credFile = credFlag ? credFlag.split('=')[1] : cfgIdx >= 0 ? argv[cfgIdx + 1] : null;
const record = {
  argv,
  env: Object.fromEntries(Object.entries(process.env).filter(([k]) => /^(PG|MYSQL_PWD|DBBACKUP_)/.test(k))),
  credFile: credFile ? fs.readFileSync(credFile, 'utf8') : null,
};

if (process.env.FAKE_EXIT) {
  process.stderr.write('pg_dump: error: connection to server failed: FATAL: password authentication failed\n');
  process.exit(Number(process.env.FAKE_EXIT));
}

if (process.env.FAKE_RESTORE_OUT) {
  const chunks = [];
  process.stdin.on('data', (c) => chunks.push(c));
  process.stdin.on('end', () => {
    fs.writeFileSync(process.env.FAKE_RESTORE_OUT, JSON.stringify({ restore: record, input: Buffer.concat(chunks).toString() }));
  });
} else {
  const size = Number(process.env.FAKE_DUMP_PAD || 0);
  process.stdout.write(JSON.stringify(record) + '\n');
  if (size) process.stdout.write('x'.repeat(size));
}
