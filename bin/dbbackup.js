#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { Writable } from 'node:stream';
import readline from 'node:readline/promises';
import { Command } from 'commander';
import { loadConfig, selectJobs, ConfigError, findConfigFile } from '../src/config.js';
import {
  createContext, backupJob, listBackups, verifyBackup, restoreBackup, pruneJob, jobStatus, APP_VERSION,
} from '../src/engine.js';
import {
  createKeyring, createEncryptStream, createDecryptStream, generateSymmetricKey, generateRecipientKeyPair, readFileHeader,
} from '../src/crypto.js';
import { startDaemon, osSchedulerHelp } from '../src/scheduler.js';
import { notify } from '../src/notify.js';
import { createDriver } from '../src/drivers/index.js';
import { log, setLogLevel, setLogJson } from '../src/log.js';
import { formatBytes, formatAge, formatDuration, redact, Meter } from '../src/util.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BIN = fileURLToPath(import.meta.url);

const program = new Command();
program
  .name('dbbackup')
  .description('Encrypted database backups (PostgreSQL, MongoDB, MySQL, SQLite) to S3 and local storage')
  .version(APP_VERSION)
  .option('-c, --config <file>', 'config file (default: dbbackup.config.json or $DBBACKUP_CONFIG)')
  .option('--env-file <file>', 'env file to load (default: .env next to the config, then ./.env)')
  .option('--log-json', 'JSON log lines (for Loki, CloudWatch, Datadog)')
  .option('-q, --quiet', 'only warnings and errors')
  .option('--debug', 'verbose logs')
  .hook('preAction', (cmd) => {
    const o = cmd.opts();
    if (o.quiet) setLogLevel('warn');
    if (o.debug) setLogLevel('debug');
    if (o.logJson) setLogJson(true);
    loadEnv(o);
  });

function loadEnv(o) {
  const candidates = o.envFile
    ? [path.resolve(o.envFile)]
    : [path.join(path.dirname(findConfigFile(o.config)), '.env'), path.resolve('.env')];
  for (const f of [...new Set(candidates)]) {
    if (fs.existsSync(f)) {
      process.loadEnvFile(f);
      return;
    }
  }
  if (o.envFile) fail(`Env file not found: ${o.envFile}`);
}

function ctxFromOpts() {
  const cfg = loadConfig(program.opts().config);
  return createContext(cfg);
}

function fail(msg, code = 1) {
  console.error(redact(msg));
  process.exit(code);
}

const print = (s = '') => process.stdout.write(s + '\n');

function table(rows, cols) {
  if (!rows.length) return print('(none)');
  const w = cols.map((c) => Math.max(c.length, ...rows.map((r) => String(r[c] ?? '').length)));
  print(cols.map((c, i) => c.toUpperCase().padEnd(w[i])).join('  '));
  for (const r of rows) print(cols.map((c, i) => String(r[c] ?? '').padEnd(w[i])).join('  '));
}

// ---------------- init / keygen ----------------

program.command('init')
  .description('create dbbackup.config.json and .env (with a fresh encryption key) in the current folder')
  .option('--force', 'overwrite an existing config file')
  .action((opts) => {
    const cfgFile = path.resolve('dbbackup.config.json');
    if (fs.existsSync(cfgFile) && !opts.force) {
      print(`Config already exists: ${cfgFile} (use --force to overwrite)`);
    } else {
      fs.copyFileSync(path.join(ROOT, 'examples', 'dbbackup.config.json'), cfgFile);
      print(`Created ${cfgFile}`);
    }
    const envFile = path.resolve('.env');
    const current = fs.existsSync(envFile) ? fs.readFileSync(envFile, 'utf8') : '';
    if (/^BACKUP_ENCRYPTION_KEY=.+/m.test(current)) {
      print(`.env already has BACKUP_ENCRYPTION_KEY (left unchanged)`);
    } else {
      const template = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8')
        .replace(/^BACKUP_ENCRYPTION_KEY=.*$/m, `BACKUP_ENCRYPTION_KEY=${generateSymmetricKey()}`);
      fs.writeFileSync(envFile, current ? `${current.trimEnd()}\n\n${template}` : template, { mode: 0o600 });
      print(`Wrote ${envFile} with a new BACKUP_ENCRYPTION_KEY`);
    }
    print('\nIMPORTANT: copy BACKUP_ENCRYPTION_KEY into a password manager NOW. Without it no backup can be restored.');
    print('Next: edit the config + .env, then run "dbbackup doctor" and "dbbackup backup".');
  });

program.command('keygen')
  .description('generate an encryption key (or an X25519 key pair for encrypt-only backup servers)')
  .option('--recipient', 'generate a public/private key pair instead of a shared key')
  .option('--out <dir>', 'with --recipient: write backup-public.pem / backup-private.pem into this folder')
  .action((opts) => {
    if (!opts.recipient) {
      print(`BACKUP_ENCRYPTION_KEY=${generateSymmetricKey()}`);
      print('# store it in a password manager; losing it means losing every backup');
      return;
    }
    const { publicKeyPem, privateKeyPem } = generateRecipientKeyPair();
    if (opts.out) {
      fs.mkdirSync(opts.out, { recursive: true });
      const pub = path.resolve(opts.out, 'backup-public.pem');
      const priv = path.resolve(opts.out, 'backup-private.pem');
      fs.writeFileSync(pub, publicKeyPem);
      fs.writeFileSync(priv, privateKeyPem, { mode: 0o600 });
      print(`Public key  (put on the backup server): ${pub}`);
      print(`Private key (keep OFFLINE, needed to restore): ${priv}`);
    } else {
      print(publicKeyPem + privateKeyPem);
    }
    print('Config: "encryption": { "mode": "recipient", "publicKey": "${BACKUP_PUBLIC_KEY}", "privateKey": "${BACKUP_PRIVATE_KEY:-}" }');
  });

// ---------------- doctor ----------------

program.command('doctor')
  .description('check config, encryption, dump tools and real read/write access to every destination')
  .option('--no-write', 'skip the write/read/delete probe on destinations')
  .action(async (opts) => {
    const checks = [];
    const add = (area, name, ok, detail = '') => {
      checks.push({ area, name, ok });
      print(`${ok === true ? ' OK ' : ok === 'warn' ? 'WARN' : 'FAIL'}  ${area.padEnd(12)} ${name}${detail ? `  - ${redact(detail)}` : ''}`);
    };
    let ctx;
    try {
      ctx = ctxFromOpts();
      add('config', ctx.cfg.file, true, `${ctx.cfg.jobs.length} job(s), ${Object.keys(ctx.cfg.destinations).length} destination(s)`);
    } catch (e) {
      add('config', 'load', false, e.message);
      process.exit(1);
    }

    // encryption round trip
    try {
      const kr = ctx.keyring;
      if (!kr.canEncrypt) throw new Error(`cannot encrypt: ${kr.describe()}`);
      const params = await kr.encryptParams();
      const chunks = [];
      await pipeline(
        async function* () { yield Buffer.from('dbbackup doctor'); },
        createEncryptStream(params),
        new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } }),
      );
      let detail = kr.describe();
      try {
        const out = [];
        await pipeline(async function* () { yield Buffer.concat(chunks); }, createDecryptStream(kr), new Writable({ write(c, _e, cb) { out.push(c); cb(); } }));
        if (Buffer.concat(out).toString() !== 'dbbackup doctor') throw new Error('round trip mismatch');
        detail += ', encrypt+decrypt round trip OK';
        add('encryption', ctx.keyring.mode, true, detail);
      } catch (e) {
        if (kr.mode === 'recipient') add('encryption', kr.mode, true, `${detail} (encrypt-only host: restores need BACKUP_PRIVATE_KEY)`);
        else throw e;
      }
    } catch (e) {
      add('encryption', ctx.keyring.mode, false, e.message);
    }

    // temp dir
    try {
      fs.mkdirSync(ctx.cfg.tempDir, { recursive: true });
      const s = fs.statfsSync?.(ctx.cfg.tempDir);
      add('temp', ctx.cfg.tempDir, true, s ? `${formatBytes(Number(s.bavail) * Number(s.bsize))} free` : '');
    } catch (e) {
      add('temp', ctx.cfg.tempDir, false, e.message);
    }

    for (const job of ctx.cfg.jobs) {
      try {
        const d = createDriver(job);
        const v = await d.version();
        add('job', job.name, true, `${d.describe()} | ${v.split('\n')[0]}`);
      } catch (e) {
        add('job', job.name, false, e.message);
      }
    }

    for (const name of Object.keys(ctx.cfg.destinations)) {
      const dest = ctx.dest(name);
      if (opts.write === false) {
        try {
          await dest.list('_dbbackup-probe/');
          add('destination', name, true, `${dest.describe()} (list OK)`);
        } catch (e) {
          add('destination', name, false, `${dest.describe()}: ${e.name} ${e.message}`);
        }
        continue;
      }
      const key = `_dbbackup-probe/${crypto.randomBytes(6).toString('hex')}.json`;
      try {
        await dest.putJson(key, { probe: true, at: new Date().toISOString() });
        const back = await dest.getJson(key);
        if (!back.probe) throw new Error('read back mismatch');
        await dest.list('_dbbackup-probe/');
        await dest.remove([key]);
        add('destination', name, true, `${dest.describe()} (write/read/list/delete OK)`);
      } catch (e) {
        add('destination', name, false, `${dest.describe()}: ${e.name} ${e.message}`);
      }
    }

    const n = ctx.cfg.notify;
    const channels = ['slack', 'discord', 'teams', 'telegram', 'webhook', 'email'].filter((c) => n[c] && (typeof n[c] === 'string' ? n[c] : Object.values(n[c]).some(Boolean)));
    add('alerts', channels.length ? channels.join(', ') : 'none', channels.length ? true : 'warn', channels.length ? 'run "dbbackup notify-test"' : 'no alert channel: failed backups would go unnoticed');

    const failed = checks.filter((c) => c.ok === false).length;
    print(`\n${failed ? `${failed} problem(s) found` : 'All checks passed'}`);
    process.exit(failed ? 1 : 0);
  });

// ---------------- backup ----------------

program.command('backup')
  .description('run backups now (all enabled jobs, or the named ones)')
  .argument('[jobs...]', 'job names')
  .option('--all', 'all enabled jobs (default when no job is named)')
  .option('--dry-run', 'show what would happen without dumping')
  .action(async (names, opts) => {
    const ctx = ctxFromOpts();
    const jobs = selectJobs(ctx.cfg, names);
    let worst = 0;
    for (const job of jobs) {
      const r = await backupJob(ctx, job, { dryRun: opts.dryRun });
      if (r.status === 'failure') worst = Math.max(worst, 1);
      if (r.status === 'partial') worst = Math.max(worst, 2);
      print(`${r.status.toUpperCase().padEnd(8)} ${job.name}  ${r.id}  ${r.bytes != null ? formatBytes(r.bytes) : ''}  ${formatDuration(r.durationMs)}${r.error ? `  ${r.error.split('\n')[0]}` : ''}`);
    }
    process.exit(worst === 0 ? 0 : worst === 1 ? 1 : 2);
  });

// ---------------- list ----------------

program.command('list')
  .description('list backups stored on the destinations')
  .argument('[jobs...]', 'job names (default: all)')
  .option('--dest <name>', 'only this destination')
  .option('--json', 'JSON output')
  .action(async (names, opts) => {
    const ctx = ctxFromOpts();
    const rows = [];
    for (const job of selectJobs(ctx.cfg, names, { includeDisabled: true })) {
      for (const d of opts.dest ? [opts.dest] : job.destinations) {
        try {
          for (const b of await listBackups(ctx, job, d)) {
            rows.push({ job: job.name, dest: d, id: b.id, age: formatAge(Date.now() - b.createdAt), size: formatBytes(b.size), state: b.complete ? 'ok' : 'INCOMPLETE', key: b.dataKey, bytes: b.size });
          }
        } catch (e) {
          rows.push({ job: job.name, dest: d, id: '-', state: `ERROR ${e.message}` });
        }
      }
    }
    if (opts.json) return print(JSON.stringify(rows, null, 2));
    table(rows, ['job', 'dest', 'id', 'age', 'size', 'state']);
  });

// ---------------- verify ----------------

program.command('verify')
  .description('download a backup, check its hash, decrypt and decompress it (restore drill without touching a database)')
  .argument('[job]', 'job name (default: every job)')
  .argument('[backup]', 'backup id or "latest"', 'latest')
  .option('--dest <name>', 'destination to read from (default: each destination of the job)')
  .option('--deep', 'also validate the archive itself (pg_restore --list, SQLite integrity_check, ...)')
  .option('--json', 'JSON output')
  .action(async (jobName, ref, opts) => {
    const ctx = ctxFromOpts();
    const jobs = selectJobs(ctx.cfg, jobName ? [jobName] : []);
    const reports = [];
    for (const job of jobs) {
      for (const d of opts.dest ? [opts.dest] : job.destinations) {
        try {
          reports.push(await verifyBackup(ctx, job, ref, { dest: d, deep: opts.deep }));
        } catch (e) {
          reports.push({ job: job.name, destination: d, id: ref, ok: false, checks: [{ name: 'find', ok: false, detail: e.message }] });
        }
      }
    }
    if (opts.json) print(JSON.stringify(reports, null, 2));
    else {
      for (const r of reports) {
        print(`${r.ok ? 'OK  ' : 'FAIL'}  ${r.job} ${r.id} @ ${r.destination}${r.durationMs ? `  (${formatDuration(r.durationMs)})` : ''}`);
        for (const c of r.checks) print(`        ${c.ok ? '✓' : '✗'} ${c.name}: ${c.detail}`);
      }
    }
    process.exit(reports.every((r) => r.ok) ? 0 : 1);
  });

// ---------------- restore ----------------

program.command('restore')
  .description('restore a backup into a database, or decrypt it to a file')
  .argument('<job>', 'job name')
  .argument('[backup]', 'backup id or "latest"', 'latest')
  .option('--dest <name>', 'destination to download from (default: first one that has it)')
  .option('--to-file <path>', 'write the decrypted dump to a file instead of restoring')
  .option('--target <url|path>', 'restore into this database URL / SQLite path instead of the job source')
  .option('--clean', 'drop existing objects first (pg_restore --clean, mongorestore --drop, overwrite SQLite file)')
  .option('-y, --yes', 'do not ask for confirmation when restoring into the job source database')
  .option('--args <args>', 'extra arguments for pg_restore / psql / mongorestore / mysql')
  .action(async (jobName, ref, opts) => {
    const ctx = ctxFromOpts();
    const [job] = selectJobs(ctx.cfg, [jobName], { includeDisabled: true });
    let confirm = Boolean(opts.yes);
    if (!opts.toFile && !opts.target && !confirm) {
      if (!process.stdin.isTTY) fail('Restoring into the source database needs --yes (non-interactive), or use --target / --to-file.');
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const answer = await rl.question(`This will restore "${ref}" INTO THE LIVE SOURCE of job "${job.name}"${opts.clean ? ' and DROP existing objects' : ''}.\nType the job name to continue: `);
      rl.close();
      if (answer.trim() !== job.name) fail('Aborted.');
      confirm = true;
    }
    const t0 = Date.now();
    try {
      const r = await restoreBackup(ctx, job, ref, {
        dest: opts.dest, toFile: opts.toFile, target: opts.target, clean: opts.clean, confirm,
        args: opts.args ? opts.args.split(/\s+/).filter(Boolean) : [],
      });
      print(`Restored ${job.name} ${r.id} from ${r.destination} -> ${r.toFile || r.target} (${formatBytes(r.bytes)} in ${formatDuration(Date.now() - t0)})`);
    } catch (e) {
      fail(`Restore failed: ${e.message}`);
    }
  });

// ---------------- prune ----------------

program.command('prune')
  .description('apply the retention policy (runs automatically after each backup)')
  .argument('[jobs...]', 'job names (default: all)')
  .option('--dest <name>', 'only this destination')
  .option('--dry-run', 'show what would be kept / deleted')
  .action(async (names, opts) => {
    const ctx = ctxFromOpts();
    for (const job of selectJobs(ctx.cfg, names, { includeDisabled: true })) {
      for (const r of await pruneJob(ctx, job, { dest: opts.dest, dryRun: opts.dryRun })) {
        print(`\n${job.name} @ ${r.destination}: keep ${r.kept.length}, ${opts.dryRun ? 'would delete' : 'deleted'} ${r.removed.length}${r.orphans.length ? ` + ${r.orphans.length} incomplete` : ''}`);
        if (opts.dryRun) {
          for (const k of r.kept) print(`  keep    ${k.id}  (${k.reasons.join(', ')})`);
          for (const id of r.removed) print(`  delete  ${id}`);
          for (const id of r.orphans) print(`  delete  ${id}  (incomplete upload)`);
        }
      }
    }
  });

// ---------------- status / history ----------------

program.command('status')
  .description('last run and last success per job; exit code 1 if any scheduled job is stale (for monitoring)')
  .option('--json', 'JSON output')
  .action((opts) => {
    const ctx = ctxFromOpts();
    const rows = ctx.cfg.jobs.map((j) => jobStatus(ctx, j));
    if (opts.json) print(JSON.stringify(rows, null, 2));
    else {
      table(rows.map((s) => ({
        job: s.job,
        schedule: s.schedule,
        'last run': s.last ? `${s.last.status} ${formatAge(Date.now() - new Date(s.last.finishedAt))}` : 'never',
        'last success': s.lastSuccess ? formatAge(s.ageMs) : 'never',
        size: s.lastSuccess ? formatBytes(s.lastSuccess.bytes) : '-',
        health: s.stale ? 'STALE' : 'ok',
      })), ['job', 'schedule', 'last run', 'last success', 'size', 'health']);
    }
    process.exit(rows.some((r) => r.stale) ? 1 : 0);
  });

program.command('history')
  .description('recent backup runs')
  .argument('[job]', 'job name')
  .option('-n, --limit <n>', 'number of runs', '20')
  .action((jobName, opts) => {
    const ctx = ctxFromOpts();
    const runs = ctx.state.runs(jobName).slice(-Number(opts.limit)).reverse();
    table(runs.map((r) => ({
      job: r.job, id: r.id, status: r.status, size: formatBytes(r.bytes), duration: formatDuration(r.durationMs),
      error: (r.error || '').split('\n')[0].slice(0, 60),
    })), ['job', 'id', 'status', 'size', 'duration', 'error']);
  });

// ---------------- daemon ----------------

program.command('daemon')
  .alias('run')
  .description('run scheduled backups in the foreground (Docker / pm2 / systemd service)')
  .option('--run-now', 'also run every job once at start-up')
  .action(async (opts) => {
    const ctx = ctxFromOpts();
    const jobs = selectJobs(ctx.cfg);
    log.info(`dbbackup ${APP_VERSION} daemon: ${jobs.length} job(s), encryption ${ctx.keyring.describe()}`);
    const d = startDaemon(ctx, jobs, { runOnStart: opts.runNow });
    const shutdown = async (sig) => {
      log.info(`${sig} received, waiting for running backups to finish...`);
      await d.stop();
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });

program.command('schedule-help')
  .description('print cron / systemd / Windows Task Scheduler snippets as an alternative to the daemon')
  .action(() => {
    let schedule = '0 2 * * *';
    try { schedule = ctxFromOpts().cfg.defaults.schedule; } catch { /* no config yet */ }
    print(osSchedulerHelp({ cwd: process.cwd(), bin: BIN, schedule }));
  });

program.command('notify-test')
  .description('send a test alert to every configured channel')
  .action(async () => {
    const ctx = ctxFromOpts();
    const res = await notify(ctx.cfg, { type: 'test', job: 'test', host: (await import('node:os')).hostname() });
    if (!res.length) fail('No alert channels configured in "notify".');
    for (const r of res) print(`${r.ok ? 'OK  ' : 'FAIL'}  ${r.channel}${r.error ? `  ${r.error}` : ''}`);
    process.exit(res.every((r) => r.ok) ? 0 : 1);
  });

// ---------------- emergency tools ----------------

program.command('inspect')
  .description('show the header of an encrypted .dbbk file (mode, key id)')
  .argument('<file>')
  .action(async (file) => {
    const h = await readFileHeader(file);
    print(JSON.stringify({ mode: h.modeName, keyId: h.keyId.toString('hex'), chunkSize: h.chunkSize, size: fs.statSync(file).size }, null, 2));
  });

program.command('decrypt')
  .description('decrypt a downloaded .dbbk file without any config (disaster recovery: only the key is needed)')
  .argument('<file>', 'encrypted file, e.g. app-db-20261119T020000Z.dump.dbbk or .sql.gz.dbbk')
  .requiredOption('-o, --out <file>', 'output file for the plain dump')
  .option('--key <key>', 'symmetric key (default: $BACKUP_ENCRYPTION_KEY)')
  .option('--private-key <pem|path>', 'X25519 private key for recipient-mode backups (default: $BACKUP_PRIVATE_KEY)')
  .option('--no-decompress', 'keep .gz / .zst compression')
  .action(async (file, opts) => {
    const keyring = createKeyring({
      mode: 'key',
      key: opts.key || process.env.BACKUP_ENCRYPTION_KEY || undefined,
      oldKeys: process.env.BACKUP_OLD_KEYS,
      passphrase: process.env.BACKUP_PASSPHRASE,
      privateKey: opts.privateKey || process.env.BACKUP_PRIVATE_KEY || undefined,
    });
    // passphrase-mode files: decryptMaster reads the passphrase regardless of keyring mode
    const stages = [fs.createReadStream(file), createDecryptStream(keyring)];
    const base = path.basename(file).replace(/\.dbbk$/, '');
    if (opts.decompress !== false && base.endsWith('.gz')) stages.push(zlib.createGunzip());
    if (opts.decompress !== false && base.endsWith('.zst')) stages.push(zlib.createZstdDecompress());
    const m = new Meter('sha256');
    try {
      await pipeline([...stages, m, fs.createWriteStream(opts.out)]);
    } catch (e) {
      fs.rmSync(opts.out, { force: true });
      fail(`Decrypt failed: ${e.message}`);
    }
    print(`Wrote ${opts.out} (${formatBytes(m.bytes)}, sha256 ${m.digest()})`);
  });

program.command('demo')
  .description('offline end-to-end demo (SQLite + in-process S3 + NAS folder): backup, verify, tamper, restore, retention')
  .option('--keep', 'keep the demo workspace')
  .option('--verbose', 'show engine logs')
  .action(async (opts) => {
    const { runDemo } = await import('../src/demo.js');
    const r = await runDemo({ keep: opts.keep, verbose: opts.verbose });
    process.exit(r.ok ? 0 : 1);
  });

program.parseAsync().catch((e) => {
  if (e instanceof ConfigError) fail(e.message, 3);
  fail(`Error: ${e.message}`);
});
