import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { runTool, capture } from '../proc.js';

/**
 * Build the command for a tool, either local or inside a Docker container.
 * Secret env vars are passed to docker by NAME only (`-e PGPASSWORD`), so the value
 * never shows up in the host process list.
 */
export function toolCommand(job, tool, args, env = {}) {
  // tools.<name> may be a path ("C:/PostgreSQL/17/bin/pg_dump.exe") or a command prefix (["wsl", "pg_dump"])
  const override = job.tools?.[tool];
  if (Array.isArray(override) && override.length) return { cmd: override[0], args: [...override.slice(1), ...args], env };
  const bin = override || (job.binDir ? path.join(job.binDir, tool) : tool);
  if (!job.docker) return { cmd: bin, args, env };
  const envFlags = Object.keys(env).flatMap((k) => ['-e', k]);
  return { cmd: 'docker', args: ['exec', '-i', ...envFlags, job.docker, tool, ...args], env };
}

export function spawnTool(job, tool, args, env, opts = {}) {
  const c = toolCommand(job, tool, args, env);
  return runTool(c.cmd, c.args, { env: c.env, label: tool, ...opts });
}

export async function toolVersion(job, tool) {
  const c = toolCommand(job, tool, ['--version']);
  return capture(c.cmd, c.args, { env: c.env, label: tool, timeoutMs: 20000 });
}

/** Write a private temp file (credentials for --defaults-extra-file / --config). */
export function privateTempFile(content, ext = '.cnf') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dbbk-'));
  const file = path.join(dir, crypto.randomBytes(6).toString('hex') + ext);
  fs.writeFileSync(file, content, { mode: 0o600 });
  return {
    file,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

export function parseDbUrl(url) {
  const u = new URL(url);
  return {
    protocol: u.protocol.replace(/:$/, ''),
    host: decodeURIComponent(u.hostname || ''),
    port: u.port || '',
    user: decodeURIComponent(u.username || ''),
    password: decodeURIComponent(u.password || ''),
    database: decodeURIComponent(u.pathname.replace(/^\//, '')),
    params: Object.fromEntries(u.searchParams),
  };
}

/** "postgres://user:***@host:5432/db" for logs. */
export function safeUrl(url) {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    u.search = '';
    return u.toString();
  } catch {
    return '(invalid url)';
  }
}

/** Pipe a stream into a tool's stdin; if the stream errors, stop the tool instead of hanging. */
export function feed(input, p) {
  input.on('error', () => {
    p.stdin?.destroy();
    p.child.kill();
  });
  input.pipe(p.stdin);
}

/** Wrap a spawned dump process in the driver dump() result shape. */
export function dumpResult(p, cleanup = () => {}) {
  return { stream: p.stdout, done: p.done, cleanup, abort: () => p.child.kill() };
}

export function extraArgs(v) {
  if (!v) return [];
  return Array.isArray(v) ? v.map(String) : String(v).split(/\s+/).filter(Boolean);
}
