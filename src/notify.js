import crypto from 'node:crypto';
import { log } from './log.js';
import { redact, formatBytes, formatDuration } from './util.js';

// cfg.notify: {
//   on: ["failure", "partial", "stale", "success"],     (default: failure, partial, stale, recovered)
//   slack: "https://hooks.slack.com/...", discord: "https://discord.com/api/webhooks/...",
//   teams: "https://...webhook.office.com/...",
//   telegram: { botToken, chatId },
//   webhook: { url, secret }                              (JSON, HMAC-SHA256 signed)
//   email: { resendApiKey, from, to }                     (Resend HTTP API)
// }
// Per job: healthcheckUrl (healthchecks.io / Uptime Kuma / Better Stack heartbeat)

const DEFAULT_ON = ['failure', 'partial', 'stale', 'recovered'];
const TIMEOUT = 10_000;

export function formatEvent(ev) {
  const icon = { success: '✅', failure: '❌', partial: '⚠️', stale: '⏰', recovered: '✅', test: '🔔' }[ev.type] || 'ℹ️';
  const title = {
    success: `Backup OK: ${ev.job}`,
    failure: `Backup FAILED: ${ev.job}`,
    partial: `Backup PARTIAL: ${ev.job} (some destinations failed)`,
    stale: `No successful backup for ${ev.job} in ${ev.hours} h`,
    recovered: `Backup recovered: ${ev.job}`,
    test: 'dbbackup test notification',
  }[ev.type] || ev.type;
  const lines = [];
  if (ev.run) {
    const r = ev.run;
    if (r.id) lines.push(`Backup: ${r.id}`);
    if (r.bytes != null) lines.push(`Size: ${formatBytes(r.bytes)} encrypted (${formatBytes(r.plainBytes)} raw)`);
    if (r.durationMs != null) lines.push(`Duration: ${formatDuration(r.durationMs)}`);
    if (r.destinations) lines.push(`Destinations: ${Object.entries(r.destinations).map(([k, v]) => `${k}=${v.ok ? 'ok' : 'FAILED'}`).join(', ')}`);
    if (r.error) lines.push(`Error: ${r.error}`);
    if (r.pruned) lines.push(`Retention: deleted ${r.pruned} old backup(s)`);
  }
  if (ev.lastSuccess) lines.push(`Last success: ${ev.lastSuccess}`);
  if (ev.host) lines.push(`Host: ${ev.host}`);
  return { icon, title, text: redact(lines.join('\n')) };
}

async function post(url, body, headers = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} ${(await res.text().catch(() => '')).slice(0, 200)}`);
}

export async function notify(cfg, ev) {
  const n = cfg.notify || {};
  const on = n.on || DEFAULT_ON;
  if (ev.type !== 'test' && !on.includes(ev.type)) return [];
  const { icon, title, text } = formatEvent(ev);
  const msg = `${icon} ${title}\n${text}`;
  const sends = [];

  if (n.slack) sends.push(['slack', () => post(n.slack, { text: `*${icon} ${title}*\n\`\`\`${text}\`\`\`` })]);
  if (n.discord) sends.push(['discord', () => post(n.discord, { content: `**${icon} ${title}**\n\`\`\`${text}\`\`\``.slice(0, 1990) })]);
  if (n.teams) sends.push(['teams', () => post(n.teams, { text: `**${icon} ${title}**\n\n${text.replace(/\n/g, '\n\n')}` })]);
  if (n.telegram?.botToken && n.telegram?.chatId) {
    sends.push(['telegram', () => post(`https://api.telegram.org/bot${n.telegram.botToken}/sendMessage`, {
      chat_id: n.telegram.chatId, text: msg, disable_web_page_preview: true,
    })]);
  }
  if (n.webhook?.url) {
    const payload = JSON.stringify({ event: ev.type, job: ev.job ?? null, title, run: ev.run ?? null, at: new Date().toISOString() });
    const headers = {};
    if (n.webhook.secret) {
      const ts = Math.floor(Date.now() / 1000);
      headers['x-dbbackup-timestamp'] = String(ts);
      headers['x-dbbackup-signature'] = 'sha256=' + crypto.createHmac('sha256', n.webhook.secret).update(`${ts}.${payload}`).digest('hex');
    }
    sends.push(['webhook', () => post(n.webhook.url, payload, headers)]);
  }
  if (n.email?.resendApiKey && n.email?.to) {
    sends.push(['email', () => post('https://api.resend.com/emails', {
      from: n.email.from || 'backups@resend.dev',
      to: [].concat(n.email.to),
      subject: `${icon} ${title}`,
      text,
    }, { authorization: `Bearer ${n.email.resendApiKey}` })]);
  }

  const results = await Promise.allSettled(sends.map(([, fn]) => fn()));
  return results.map((r, i) => {
    const channel = sends[i][0];
    if (r.status === 'rejected') log.warn(`Notification via ${channel} failed: ${r.reason.message}`);
    return { channel, ok: r.status === 'fulfilled', error: r.reason?.message };
  });
}

/** Heartbeat ping (healthchecks.io style): <url>/start, <url>, <url>/fail */
export async function ping(url, kind = 'success', body = '') {
  if (!url) return;
  const target = kind === 'success' ? url : `${url.replace(/\/$/, '')}/${kind}`;
  try {
    await fetch(target, { method: 'POST', body: redact(body).slice(0, 10_000), signal: AbortSignal.timeout(TIMEOUT) });
  } catch (e) {
    log.warn(`Heartbeat ping ${kind} failed: ${e.message}`);
  }
}
