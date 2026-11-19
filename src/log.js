import { redact } from './util.js';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
let level = LEVELS[process.env.DBBACKUP_LOG_LEVEL] ?? LEVELS.info;
let json = process.env.DBBACKUP_LOG_FORMAT === 'json';
let sink = null;

export function setLogLevel(l) { if (LEVELS[l] != null) level = LEVELS[l]; }
export function setLogJson(v) { json = Boolean(v); }
/** Capture log lines (tests / demo). Pass null to restore stderr. */
export function setLogSink(fn) { sink = fn; }

function write(lvl, msg, fields) {
  if (LEVELS[lvl] < level) return;
  const text = redact(msg);
  const safeFields = fields ? JSON.parse(redact(JSON.stringify(fields))) : undefined;
  let line;
  if (json) line = JSON.stringify({ time: new Date().toISOString(), level: lvl, msg: text, ...safeFields });
  else {
    const tag = { debug: 'DBG', info: 'INF', warn: 'WRN', error: 'ERR' }[lvl];
    const extra = safeFields && Object.keys(safeFields).length
      ? ' ' + Object.entries(safeFields).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' ')
      : '';
    line = `${new Date().toISOString().slice(11, 19)} ${tag} ${text}${extra}`;
  }
  if (sink) sink(line, lvl);
  else process.stderr.write(line + '\n');
}

export const log = {
  debug: (m, f) => write('debug', m, f),
  info: (m, f) => write('info', m, f),
  warn: (m, f) => write('warn', m, f),
  error: (m, f) => write('error', m, f),
};
