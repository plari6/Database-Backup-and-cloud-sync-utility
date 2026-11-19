import { spawn } from 'node:child_process';
import { redact } from './util.js';

export class ProcessError extends Error {
  constructor(message, { code, stderr } = {}) {
    super(message);
    this.name = 'ProcessError';
    this.code = code;
    this.stderr = stderr;
  }
}

/**
 * Spawn a dump/restore tool. Secrets go via env, never argv.
 * Returns { child, stdin, stdout, done } where done resolves when the process exits 0
 * (rejects with the tail of stderr otherwise).
 */
export function runTool(cmd, args = [], { env = {}, shell = false, timeoutMs = 0, label = cmd, stdin = 'pipe', stdout = 'pipe' } = {}) {
  const child = spawn(cmd, args, {
    env: { ...process.env, ...env },
    shell,
    windowsHide: true,
    stdio: [stdin, stdout, 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (d) => {
    stderr += d.toString();
    if (stderr.length > 64 * 1024) stderr = stderr.slice(-32 * 1024);
  });

  let timer = null;
  let timedOut = false;
  if (timeoutMs > 0) {
    timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 5000).unref();
    }, timeoutMs);
    timer.unref();
  }

  const done = new Promise((resolve, reject) => {
    child.on('error', (err) => {
      clearTimeout(timer);
      if (err.code === 'ENOENT') {
        reject(new ProcessError(`${label}: command "${cmd}" not found. Install it or set the tool path / "docker" container in the job config.`, { code: 'ENOENT' }));
      } else reject(new ProcessError(`${label}: ${err.message}`, { code: err.code }));
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (timedOut) return reject(new ProcessError(`${label}: timed out after ${Math.round(timeoutMs / 1000)}s`, { code: 'ETIMEDOUT', stderr }));
      if (code === 0) return resolve({ stderr });
      const tail = redact(stderr.trim().split(/\r?\n/).slice(-8).join('\n'));
      reject(new ProcessError(`${label} exited with ${signal ? `signal ${signal}` : `code ${code}`}${tail ? `:\n${tail}` : ''}`, { code, stderr: tail }));
    });
  });
  // never leave an unhandled rejection if the caller only awaits the stream
  done.catch(() => {});
  // an EPIPE on stdin (tool exited early) is reported via `done`, not as a crash
  child.stdin?.on('error', () => {});

  return { child, stdin: child.stdin, stdout: child.stdout, done };
}

/** Run to completion and capture stdout (for --version checks). */
export async function capture(cmd, args = [], opts = {}) {
  const p = runTool(cmd, args, { ...opts, stdin: 'ignore' });
  let out = '';
  p.stdout.on('data', (d) => { out += d.toString(); });
  const { stderr } = await p.done;
  return (out || stderr).trim();
}
