# Database Backup & Cloud Sync Utility (`dbbackup`)

Nightly, **encrypted**, **verified** backups of PostgreSQL, MongoDB, MySQL/MariaDB and SQLite databases, uploaded to **AWS S3** (or Cloudflare R2, Backblaze B2, Wasabi, MinIO, DigitalOcean Spaces) and a second local/NAS copy. It also handles retention, restore drills and alerts when something goes wrong.

**Stack:** JavaScript (Node.js 24, ESM). The project card names Node.js, and this is a CLI plus a cron daemon. Dependencies: `@aws-sdk/client-s3`, `@aws-sdk/lib-storage`, `commander`, `node-cron`. No LLM calls.

```
pg_dump / mongodump / mysqldump / SQLite backup API
   └─► gzip/zstd ─► AES-256-GCM stream encryption ─► temp file (encrypted only)
                                                      ├─► S3 (Content-MD5/SHA-256 checked, multipart for big files)
                                                      └─► NAS / local folder
   manifest.json (sizes + SHA-256 of dump and file) written last = "backup complete"
   then: GFS retention ─► run history ─► Slack / Discord / Teams / Telegram / e-mail / webhook / heartbeat
```

## Why it is safe to rely on

| Problem a client fears | What `dbbackup` does |
|---|---|
| Someone steals the bucket | Every file is encrypted **before** it leaves the server (AES-256-GCM, per-file key via HKDF). Optional **public-key mode**: the server can only encrypt, and the private key stays offline. |
| A backup is silently corrupt or truncated | Data is authenticated per 1 MB block, and the last block is flagged, so cutting the file anywhere is detected. SHA-256 of the file and of the raw dump is stored in the manifest. Uploads are checked server-side (Content-MD5 / SHA-256) and confirmed with HEAD. |
| "We had backups, but they didn't restore" | `verify --deep` downloads, decrypts and validates the archive (`pg_restore --list`, SQLite `integrity_check`, mongodump magic, mysqldump footer). Schedule it weekly. |
| The dump failed but an empty file was uploaded | Dump tool exit code, stderr and 0-byte output are all checked. Nothing is uploaded, and an alert is sent with the tool's error message. |
| The backup job quietly stopped running | A stale watchdog alerts when a job has had no success for 26 h, plus healthchecks.io-style heartbeats and a `status` exit code for monitoring. |
| S3 has a bad moment | Retries with backoff, per-destination results, and a `partial` status when one copy failed. |
| Ransomware / an admin deletes backups | Two destinations (3-2-1 rule), S3 Object Lock (`objectLock: { mode, days }`) and SSE-KMS support. |
| Passwords leak into logs / `ps` | Credentials travel via env vars or private temp files (`PGPASSWORD`, `--defaults-extra-file`, mongodump `--config`), never on the command line. All logs and alerts are redacted. |
| Storage bill grows forever | GFS retention: last N + daily/weekly/monthly/yearly, timezone-aware. `prune --dry-run` explains every keep decision. |

## Quick start

```bash
npm install
node bin/dbbackup.js demo          # 17-step offline proof: backup, verify, tamper, restore, retention, public-key mode

node bin/dbbackup.js init          # creates dbbackup.config.json + .env with a fresh BACKUP_ENCRYPTION_KEY
#   -> save the key in a password manager, fill in PG_URL / MONGO_URI / S3_BUCKET in .env
node bin/dbbackup.js doctor        # config, key round trip, tool versions, real write/read/delete on every destination
node bin/dbbackup.js backup        # run all enabled jobs now
node bin/dbbackup.js daemon        # keep running and back up on each job's cron schedule
```

Docker (includes `pg_dump`, `mongodump` and `mysqldump`):

```bash
docker compose up -d dbbackup                 # production: needs .env + dbbackup.config.json
docker compose --profile lab up -d            # optional lab: Postgres 17 + Mongo 8 + MinIO to try it end to end
```

## Commands

| Command | What it does |
|---|---|
| `init` / `keygen [--recipient --out dir]` | Config + key, or an X25519 key pair for encrypt-only servers |
| `doctor [--no-write]` | Checks everything a backup needs; exits 1 on any problem |
| `backup [jobs...] [--dry-run]` | Runs now. Exit 0 = ok, 1 = failure, 2 = partial |
| `list [jobs...] [--dest s3] [--json]` | Backups on each destination (incomplete uploads flagged) |
| `verify [job] [id\|latest] [--deep] [--dest]` | Hash + decrypt + decompress + archive check, without touching a database |
| `restore <job> [id\|latest] --target <url\|path> [--clean]` | Restores into another database (e.g. staging) |
| `restore <job> --to-file dump.sql` | Decrypts to a file for manual work |
| `restore <job> --yes` | Restores into the job's own source database (interactive confirmation otherwise) |
| `prune [jobs...] [--dry-run]` | Applies retention (also runs automatically after each backup) |
| `status [--json]` / `history [job]` | Last run and last success per job. `status` exits 1 if any job is stale |
| `daemon [--run-now]` | Scheduler with no overlapping runs, a stale watchdog and graceful shutdown |
| `schedule-help` | cron / systemd timer / Windows Task Scheduler snippets if you prefer the OS scheduler |
| `notify-test` | Sends a test alert to every channel |
| `inspect <file>` / `decrypt <file> -o out [--key ...]` | **Disaster recovery without config**: only the `.dbbk` file and the key are needed |

## Configuration

`dbbackup.config.json` (see [examples/dbbackup.config.json](examples/dbbackup.config.json)). Every `${VAR}` / `${VAR:-default}` is read from the environment or `.env`. Missing variables are reported by name.

```jsonc
{
  "timezone": "Europe/Berlin",          // cron + retention day boundaries
  "encryption": { "mode": "key", "key": "${BACKUP_ENCRYPTION_KEY}", "oldKeys": "${BACKUP_OLD_KEYS:-}" },
  "destinations": {
    "s3":  { "type": "s3", "bucket": "${S3_BUCKET}", "region": "eu-central-1", "prefix": "acme",
             "storageClass": "STANDARD_IA", "sse": "aws:kms", "kmsKeyId": "...",
             "objectLock": { "mode": "GOVERNANCE", "days": 30 } },
    "r2":  { "type": "s3", "bucket": "acme-backups", "endpoint": "https://<acct>.r2.cloudflarestorage.com", "region": "auto",
             "accessKeyId": "${R2_KEY}", "secretAccessKey": "${R2_SECRET}" },
    "nas": { "type": "local", "path": "/mnt/nas/db-backups" }
  },
  "defaults": { "schedule": "0 2 * * *", "destinations": ["s3", "nas"],
                "retention": { "keepLast": 7, "daily": 7, "weekly": 4, "monthly": 6, "yearly": 1 } },
  "notify": { "on": ["failure", "partial", "stale", "recovered"], "slack": "${SLACK_WEBHOOK_URL}" },
  "jobs": [
    { "name": "app-pg",   "type": "postgres", "url": "${PG_URL}", "format": "custom", "healthcheckUrl": "${HC_URL}" },
    { "name": "cluster",  "type": "postgres", "url": "${PG_ADMIN_URL}", "all": true },           // pg_dumpall
    { "name": "app-mongo","type": "mongodb",  "uri": "${MONGO_URI}", "args": ["--oplog"], "schedule": "30 */6 * * *" },
    { "name": "crm",      "type": "mysql",    "url": "${MYSQL_URL}" },
    { "name": "local-db", "type": "sqlite",   "path": "./data/app.sqlite" },
    { "name": "redis",    "type": "command",  "dump": "redis-cli --rdb -", "ext": "rdb" },
    { "name": "pg-in-docker", "type": "postgres", "url": "postgres://app:${PW}@localhost/app", "docker": "pg-container" }
  ]
}
```

- **Job options:** `schedule` (cron, or `null` for manual only), `destinations`, `retention` (overrides single fields of the defaults), `compression` (`auto` \| `gzip` \| `zstd` \| `none`; `auto` skips gzip for pg custom format, which is already compressed), `timeoutMinutes`, `alertIfNoSuccessHours`, `enabled`, `args` / `restoreArgs` (extra tool flags), `docker` (run the tool inside a container), `binDir` or `tools: { "pg_dump": "C:/PostgreSQL/17/bin/pg_dump.exe" }` or a command prefix like `["wsl", "pg_dump"]`.
- **Retention:** a `defaults.retention` you write *is* the policy (units you leave out = 0). Without it, the built-in default is 7 last / 7 daily / 4 weekly / 6 monthly.
- **Encryption modes:** `key` (32-byte key), `passphrase` (scrypt, `BACKUP_PASSPHRASE`), `recipient` (`publicKey` on the server, `privateKey` only on the restore machine).
- **Key rotation:** put the new key in `BACKUP_ENCRYPTION_KEY` and the old one in `BACKUP_OLD_KEYS`. Each file header carries its key id.
- **Alerts:** `slack`, `discord`, `teams`, `telegram {botToken, chatId}`, `webhook {url, secret}` (HMAC-SHA256 over `timestamp.body` in `x-dbbackup-signature`, for n8n / Make / Zapier), `email {resendApiKey, from, to}`, plus a per-job `healthcheckUrl`.

### Least-privilege S3 policy for the backup user

```json
{ "Version": "2012-10-17", "Statement": [
  { "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"], "Resource": "arn:aws:s3:::BUCKET/backups/*" },
  { "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::BUCKET", "Condition": { "StringLike": { "s3:prefix": "backups/*" } } } ] }
```

With Object Lock, or a policy without `s3:DeleteObject`, retention deletes fail with a warning. Use an S3 lifecycle rule instead.

## File format

`<prefix>/<job>/<yyyy>/<mm>/<job>-<20261119T020000Z>.<dump|archive|sql|sqlite>[.gz|.zst].dbbk`, plus a `.manifest.json` beside it.

`.dbbk` = `DBBK` magic, version, mode, key id, salt, nonce prefix, chunk size, then AES-256-GCM frames (1 MiB plaintext + 16-byte tag). The nonce is `prefix || counter || last-flag` and the header is the AAD of every frame. Restoring needs only this tool's `decrypt` command and the key, and the format is documented in [src/crypto.js](src/crypto.js).

## Tests

```bash
npm test     # 35 tests, offline, about 7 s
```

The tests run the real AWS SDK against an in-process S3 server ([src/dev/fake-s3.js](src/dev/fake-s3.js)) covering multipart, 503 injection and tampering. The real postgres / mongodb / mysql driver code runs against a stand-in tool that records argv and env, to prove that passwords never reach the command line. SQLite runs for real, and the CLI is tested end to end.

**Not tested in CI:** live `pg_dump` / `mongodump` / `mysqldump` against real servers, and real AWS. Use `docker compose --profile lab up -d` and point `.env` at it for a full live run.

## Library use

```js
import { loadConfig, createContext, backupJob, verifyBackup } from 'db-backup-cloud-sync';
const ctx = createContext(loadConfig('dbbackup.config.json'));
const run = await backupJob(ctx, ctx.cfg.jobs[0]);       // { status, id, bytes, destinations, ... }
```
