// Grandfather-father-son retention. Pure function, easy to test and to explain to a client:
//   keepLast N most recent + newest backup of each of the last D days, W weeks, M months, Y years.

const fmtCache = new Map();
function parts(date, timeZone) {
  let f = fmtCache.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' });
    fmtCache.set(timeZone, f);
  }
  const p = Object.fromEntries(f.formatToParts(date).map((x) => [x.type, x.value]));
  return { y: +p.year, m: +p.month, d: +p.day };
}

function isoWeek({ y, m, d }) {
  const date = new Date(Date.UTC(y, m - 1, d));
  const day = date.getUTCDay() || 7;
  date.setUTCDate(date.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((date - yearStart) / 86400000 + 1) / 7);
  return `${date.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

export function bucketOf(date, unit, timeZone = 'UTC') {
  const p = parts(date, timeZone);
  switch (unit) {
    case 'daily': return `${p.y}-${p.m}-${p.d}`;
    case 'weekly': return isoWeek(p);
    case 'monthly': return `${p.y}-${p.m}`;
    case 'yearly': return `${p.y}`;
    default: throw new Error(unit);
  }
}

/**
 * @param {{id:string, createdAt: Date|string}[]} backups
 * @param {{keepLast?:number, daily?:number, weekly?:number, monthly?:number, yearly?:number}} policy
 * @returns {{ keep: Map<string,string[]>, remove: string[] }}
 */
export function applyRetention(backups, policy = {}, { timeZone = 'UTC' } = {}) {
  const list = backups
    .map((b) => ({ ...b, createdAt: new Date(b.createdAt) }))
    .sort((a, b) => b.createdAt - a.createdAt);
  const keep = new Map();
  const mark = (b, reason) => {
    if (!keep.has(b.id)) keep.set(b.id, []);
    keep.get(b.id).push(reason);
  };

  list.slice(0, Math.max(0, policy.keepLast || 0)).forEach((b, i) => mark(b, `last #${i + 1}`));

  for (const unit of ['daily', 'weekly', 'monthly', 'yearly']) {
    const n = Math.max(0, policy[unit] || 0);
    if (!n) continue;
    let last = null;
    let count = 0;
    for (const b of list) {
      const bucket = bucketOf(b.createdAt, unit, timeZone);
      if (bucket === last) continue;
      last = bucket;
      mark(b, `${unit} ${bucket}`);
      if (++count >= n) break;
    }
  }

  // safety net: never delete the newest backup
  if (list.length && !keep.size) mark(list[0], 'newest (safety)');

  return { keep, remove: list.filter((b) => !keep.has(b.id)).map((b) => b.id) };
}
