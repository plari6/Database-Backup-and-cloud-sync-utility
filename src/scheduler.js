import cron from 'node-cron';
import { backupJob, checkStale } from './engine.js';
import { log } from './log.js';

/**
 * Long-running daemon: one cron task per job (no overlapping runs), hourly stale-backup watchdog,
 * graceful shutdown that waits for running backups.
 */
export function startDaemon(ctx, jobs, { runOnStart = false } = {}) {
  const started = ctx.now();
  const running = new Set();
  const tasks = [];

  const runJob = async (job) => {
    if (running.has(job.name)) {
      log.warn(`[${job.name}] previous run still in progress, skipping this slot`);
      return;
    }
    running.add(job.name);
    try {
      await backupJob(ctx, job);
    } catch (e) {
      log.error(`[${job.name}] unexpected error: ${e.message}`);
    } finally {
      running.delete(job.name);
    }
  };

  // jobs run one at a time per job, but different jobs may overlap; a global queue keeps
  // a small server from dumping every database at the same moment
  const maxParallel = Math.max(1, ctx.cfg.maxParallelJobs || 1);
  const queue = [];
  let active = 0;
  const enqueue = (job) => {
    if (queue.some((j) => j.name === job.name) || running.has(job.name)) {
      log.warn(`[${job.name}] already queued or running, skipping this slot`);
      return;
    }
    queue.push(job);
    pump();
  };
  const pump = () => {
    while (active < maxParallel && queue.length) {
      const job = queue.shift();
      active++;
      runJob(job).finally(() => { active--; pump(); });
    }
  };

  for (const job of jobs) {
    if (!job.schedule) {
      log.info(`[${job.name}] no schedule (manual only)`);
      continue;
    }
    const task = cron.schedule(job.schedule, () => enqueue(job), { timezone: ctx.cfg.timezone, name: `backup:${job.name}` });
    tasks.push(task);
    log.info(`[${job.name}] scheduled "${job.schedule}" (${ctx.cfg.timezone})`);
  }

  const watchdog = cron.schedule('17 * * * *', async () => {
    try {
      const stale = await checkStale(ctx, jobs, { since: started });
      if (stale.length) log.warn(`Stale backups alerted: ${stale.join(', ')}`);
    } catch (e) {
      log.error(`Stale check failed: ${e.message}`);
    }
  }, { timezone: ctx.cfg.timezone, name: 'stale-watchdog' });
  tasks.push(watchdog);

  if (runOnStart) for (const job of jobs) enqueue(job);

  const stop = async () => {
    for (const t of tasks) t.stop();
    queue.length = 0;
    while (active > 0) await new Promise((r) => setTimeout(r, 500));
  };
  return { stop, tasks, running, enqueue };
}

/** Snippets for people who prefer the OS scheduler over the daemon. */
export function osSchedulerHelp({ cwd, node = process.execPath, bin, schedule = '0 2 * * *' }) {
  const [min, hour] = schedule.split(/\s+/);
  const hh = String(hour).padStart(2, '0');
  const mm = String(min).padStart(2, '0');
  return `
# Option A (recommended): run the daemon as a service
#   docker compose up -d          (see docker-compose.yml)
#   or: pm2 start "${bin} daemon" --name dbbackup --cwd "${cwd}"

# Option B: Linux / macOS crontab -e
${schedule} cd "${cwd}" && "${node}" "${bin}" backup --all >> "${cwd}/.dbbackup/cron.log" 2>&1

# Option C: systemd timer (/etc/systemd/system/dbbackup.service + dbbackup.timer)
[Service]
Type=oneshot
WorkingDirectory=${cwd}
ExecStart=${node} ${bin} backup --all
[Timer]
OnCalendar=*-*-* ${hh}:${mm}:00
Persistent=true

# Option D: Windows Task Scheduler (run in an elevated PowerShell)
schtasks /Create /TN "dbbackup" /SC DAILY /ST ${hh}:${mm} /RU SYSTEM /TR "cmd /c cd /d \\"${cwd}\\" && \\"${node}\\" \\"${bin}\\" backup --all"
`.trim();
}
