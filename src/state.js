import fs from 'node:fs';
import path from 'node:path';

/** Run history (JSONL) + per-job locks. Lives in cfg.stateDir. */
export function createState(stateDir) {
  fs.mkdirSync(stateDir, { recursive: true });
  const runsFile = path.join(stateDir, 'runs.jsonl');
  const alertsFile = path.join(stateDir, 'alerts.json');

  const readRuns = () => {
    if (!fs.existsSync(runsFile)) return [];
    return fs.readFileSync(runsFile, 'utf8').split('\n').filter(Boolean).flatMap((l) => {
      try { return [JSON.parse(l)]; } catch { return []; }
    });
  };

  return {
    dir: stateDir,

    recordRun(run) {
      fs.appendFileSync(runsFile, JSON.stringify(run) + '\n');
      // keep the file small: last 5000 runs
      const st = fs.statSync(runsFile);
      if (st.size > 5 * 1024 * 1024) {
        const runs = readRuns().slice(-5000);
        fs.writeFileSync(runsFile, runs.map((r) => JSON.stringify(r)).join('\n') + '\n');
      }
    },

    runs(job) {
      const all = readRuns();
      return job ? all.filter((r) => r.job === job) : all;
    },

    lastRun(job, status) {
      const runs = this.runs(job);
      for (let i = runs.length - 1; i >= 0; i--) if (!status || runs[i].status === status) return runs[i];
      return null;
    },

    /** Exclusive per-job lock; a lock left by a dead process is taken over. */
    lock(job) {
      const file = path.join(stateDir, `${job}.lock`);
      if (heldHere.has(file)) throw new Error(`Job "${job}" is already running in this process`);
      const tryCreate = () => {
        try {
          fs.writeFileSync(file, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }), { flag: 'wx' });
          return true;
        } catch (e) {
          if (e.code !== 'EEXIST') throw e;
          return false;
        }
      };
      if (!tryCreate()) {
        let holder = null;
        try { holder = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* corrupt lock */ }
        if (holder && isAlive(holder.pid) && holder.pid !== process.pid) {
          throw new Error(`Job "${job}" is already running (pid ${holder.pid} since ${holder.at})`);
        }
        fs.rmSync(file, { force: true });
        if (!tryCreate()) throw new Error(`Could not lock job "${job}"`);
      }
      heldHere.add(file);
      return () => {
        heldHere.delete(file);
        fs.rmSync(file, { force: true });
      };
    },

    /** Remember when an alert was sent, to avoid spamming (stale-backup alerts). */
    alertSentWithin(key, ms) {
      const a = readJson(alertsFile);
      return a[key] && Date.now() - a[key] < ms;
    },
    markAlert(key) {
      const a = readJson(alertsFile);
      a[key] = Date.now();
      fs.writeFileSync(alertsFile, JSON.stringify(a, null, 2));
    },
    clearAlert(key) {
      const a = readJson(alertsFile);
      if (a[key]) { delete a[key]; fs.writeFileSync(alertsFile, JSON.stringify(a, null, 2)); }
    },
  };
}

const heldHere = new Set();

function readJson(f) {
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return {}; }
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}
