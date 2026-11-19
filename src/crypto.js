// Streaming authenticated encryption for backup files.
//
// File format "DBBK" v1 (all integers big-endian):
//   magic "DBBK" (4) | version 1 (1) | mode (1) | keyId (8) | salt (16) |
//   noncePrefix (7) | chunkSize u32 (4) | extLen u16 (2) | ext (extLen)
//   then frames: AES-256-GCM(chunk) || tag(16)
//
// - Every file gets its own key: HKDF-SHA256(master, salt, info) so nonces never repeat across files.
// - Nonce = noncePrefix(7) | counter u32 (4) | lastFlag (1). The final frame carries lastFlag=1, so a
//   file cut at a frame boundary fails authentication (truncation-proof, "STREAM" construction).
// - The whole header is the AAD of every frame, so header edits (chunk size, key id...) are detected.
//
// Modes:
//   1 = key        : 32-byte symmetric master key (BACKUP_ENCRYPTION_KEY)
//   2 = passphrase : scrypt(passphrase, salt) -> master key
//   3 = recipient  : X25519 public key. The backup host can only ENCRYPT; restoring needs the private
//                    key, which can live offline. ext = ephemeral public key (raw 32 bytes).

import crypto from 'node:crypto';
import fs from 'node:fs';
import { Transform } from 'node:stream';

export const MAGIC = Buffer.from('DBBK');
export const VERSION = 1;
export const MODES = { key: 1, passphrase: 2, recipient: 3 };
const MODE_NAMES = Object.fromEntries(Object.entries(MODES).map(([k, v]) => [v, k]));
const TAG = 16;
const FIXED_HEADER = 4 + 1 + 1 + 8 + 16 + 7 + 4 + 2;
export const DEFAULT_CHUNK = 1024 * 1024;
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export class DecryptError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DecryptError';
  }
}

// ---------- key material ----------

/** Parse a 32-byte key given as base64, base64url, hex or "base64:..." / "hex:...". */
export function parseSymmetricKey(value) {
  if (Buffer.isBuffer(value)) {
    if (value.length !== 32) throw new Error('Encryption key must be 32 bytes');
    return value;
  }
  const s = String(value ?? '').trim();
  if (!s) throw new Error('Encryption key is empty (set BACKUP_ENCRYPTION_KEY, run "dbbackup keygen")');
  let buf;
  if (s.startsWith('hex:')) buf = Buffer.from(s.slice(4), 'hex');
  else if (s.startsWith('base64:')) buf = Buffer.from(s.slice(7), 'base64');
  else if (/^[0-9a-fA-F]{64}$/.test(s)) buf = Buffer.from(s, 'hex');
  else buf = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (buf.length !== 32) {
    throw new Error(`Encryption key must decode to 32 bytes (got ${buf.length}). Generate one with "dbbackup keygen".`);
  }
  return buf;
}

export function keyIdOf(material) {
  return crypto.createHash('sha256').update('dbbk-keyid').update(material).digest().subarray(0, 8);
}

export function generateSymmetricKey() {
  return 'base64:' + crypto.randomBytes(32).toString('base64');
}

export function generateRecipientKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

/** Accept PEM text, a path to a PEM file, or base64 DER. */
function loadPem(value, kind) {
  let s = String(value ?? '').trim();
  if (!s) throw new Error(`Missing ${kind} key`);
  if (!s.includes('-----BEGIN') && fs.existsSync(s)) s = fs.readFileSync(s, 'utf8');
  s = s.replace(/\\n/g, '\n');
  if (kind === 'public') {
    return s.includes('-----BEGIN')
      ? crypto.createPublicKey(s)
      : crypto.createPublicKey({ key: Buffer.from(s, 'base64'), format: 'der', type: 'spki' });
  }
  return s.includes('-----BEGIN')
    ? crypto.createPrivateKey(s)
    : crypto.createPrivateKey({ key: Buffer.from(s, 'base64'), format: 'der', type: 'pkcs8' });
}

function rawX25519(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  if (publicKey.asymmetricKeyType !== 'x25519') throw new Error('Recipient key must be an X25519 key ("dbbackup keygen --recipient")');
  return der.subarray(der.length - 32);
}

function x25519FromRaw(raw) {
  return crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

/**
 * Build a keyring from config.encryption.
 * { mode, key, oldKeys, passphrase, publicKey, privateKey }
 * Returns { mode, canEncrypt, describe(), encryptParams(), decryptMaster(header) }
 */
export function createKeyring(enc = {}) {
  const mode = enc.mode || 'key';
  if (!MODES[mode]) throw new Error(`Unknown encryption mode "${mode}" (key | passphrase | recipient)`);

  const symmetric = [];
  if (mode === 'key') {
    if (enc.key) symmetric.push(parseSymmetricKey(enc.key));
    for (const k of splitList(enc.oldKeys)) symmetric.push(parseSymmetricKey(k));
  } else {
    // allow restoring older key-mode backups after switching mode
    for (const k of splitList(enc.oldKeys)) symmetric.push(parseSymmetricKey(k));
  }
  const byId = new Map(symmetric.map((k) => [keyIdOf(k).toString('hex'), k]));

  let recipientPub = null;
  let recipientPriv = null;
  if (enc.publicKey) recipientPub = loadPem(enc.publicKey, 'public');
  if (enc.privateKey) {
    recipientPriv = loadPem(enc.privateKey, 'private');
    if (!recipientPub) recipientPub = crypto.createPublicKey(recipientPriv);
  }

  const passphrase = enc.passphrase ? String(enc.passphrase) : '';

  return {
    mode,
    get canEncrypt() {
      if (mode === 'key') return symmetric.length > 0 && Boolean(enc.key);
      if (mode === 'passphrase') return passphrase.length > 0;
      return Boolean(recipientPub);
    },
    describe() {
      if (mode === 'key') return `key ${enc.key ? keyIdOf(symmetric[0]).toString('hex') : '(missing)'}${byId.size > 1 ? ` + ${byId.size - 1} old key(s)` : ''}`;
      if (mode === 'passphrase') return 'passphrase (scrypt)';
      return `recipient ${recipientPub ? keyIdOf(rawX25519(recipientPub)).toString('hex') : '(missing public key)'}${recipientPriv ? ' (private key loaded)' : ' (encrypt-only)'}`;
    },
    async encryptParams() {
      const salt = crypto.randomBytes(16);
      if (mode === 'key') {
        if (!enc.key) throw new Error('No encryption key configured (BACKUP_ENCRYPTION_KEY)');
        const master = symmetric[0];
        return { mode: MODES.key, keyId: keyIdOf(master), salt, master, ext: Buffer.alloc(0) };
      }
      if (mode === 'passphrase') {
        if (!passphrase) throw new Error('No passphrase configured (BACKUP_PASSPHRASE)');
        const master = await scrypt(passphrase, salt);
        return { mode: MODES.passphrase, keyId: Buffer.alloc(8), salt, master, ext: Buffer.alloc(0) };
      }
      if (!recipientPub) throw new Error('No recipient public key configured (BACKUP_PUBLIC_KEY)');
      const eph = crypto.generateKeyPairSync('x25519');
      const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
      const recipientRaw = rawX25519(recipientPub);
      const ephRaw = rawX25519(eph.publicKey);
      const master = Buffer.concat([shared, ephRaw, recipientRaw]);
      return { mode: MODES.recipient, keyId: keyIdOf(recipientRaw), salt, master, ext: ephRaw };
    },
    async decryptMaster(header) {
      if (header.mode === MODES.key) {
        const k = byId.get(header.keyId.toString('hex'));
        if (!k) throw new DecryptError(`No key with id ${header.keyId.toString('hex')} in keyring (set BACKUP_ENCRYPTION_KEY or add it to BACKUP_OLD_KEYS)`);
        return k;
      }
      if (header.mode === MODES.passphrase) {
        if (!passphrase) throw new DecryptError('Backup was encrypted with a passphrase; set BACKUP_PASSPHRASE');
        return scrypt(passphrase, header.salt);
      }
      if (header.mode === MODES.recipient) {
        if (!recipientPriv) throw new DecryptError('Backup was encrypted for a recipient key; set BACKUP_PRIVATE_KEY (PEM or path) to restore');
        const recipientRaw = rawX25519(crypto.createPublicKey(recipientPriv));
        if (!keyIdOf(recipientRaw).equals(header.keyId)) {
          throw new DecryptError(`Backup is for recipient ${header.keyId.toString('hex')}, loaded private key is ${keyIdOf(recipientRaw).toString('hex')}`);
        }
        const shared = crypto.diffieHellman({ privateKey: recipientPriv, publicKey: x25519FromRaw(header.ext) });
        return Buffer.concat([shared, header.ext, recipientRaw]);
      }
      throw new DecryptError(`Unknown encryption mode ${header.mode}`);
    },
  };
}

function splitList(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter(Boolean);
  return String(v).split(/[,\s]+/).filter(Boolean);
}

function scrypt(pass, salt) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(pass, salt, 32, SCRYPT, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

function fileKey(master, salt, headerMode) {
  return Buffer.from(crypto.hkdfSync('sha256', master, salt, Buffer.from(`dbbk v1 file key mode ${headerMode}`), 32));
}

// ---------- header ----------

export function encodeHeader({ mode, keyId, salt, noncePrefix, chunkSize, ext }) {
  const h = Buffer.alloc(FIXED_HEADER + ext.length);
  let o = 0;
  MAGIC.copy(h, o); o += 4;
  h[o++] = VERSION;
  h[o++] = mode;
  keyId.copy(h, o); o += 8;
  salt.copy(h, o); o += 16;
  noncePrefix.copy(h, o); o += 7;
  h.writeUInt32BE(chunkSize, o); o += 4;
  h.writeUInt16BE(ext.length, o); o += 2;
  ext.copy(h, o);
  return h;
}

/** Returns { header, bytes } or null if more data is needed. Throws DecryptError on bad header. */
export function decodeHeader(buf) {
  if (buf.length < FIXED_HEADER) return null;
  if (!buf.subarray(0, 4).equals(MAGIC)) throw new DecryptError('Not a dbbackup encrypted file (bad magic)');
  if (buf[4] !== VERSION) throw new DecryptError(`Unsupported file version ${buf[4]}`);
  const extLen = buf.readUInt16BE(FIXED_HEADER - 2);
  const total = FIXED_HEADER + extLen;
  if (buf.length < total) return null;
  const chunkSize = buf.readUInt32BE(37);
  if (chunkSize < 1 || chunkSize > 64 * 1024 * 1024) throw new DecryptError('Invalid chunk size in header');
  const raw = Buffer.from(buf.subarray(0, total));
  return {
    bytes: total,
    header: {
      raw,
      mode: buf[5],
      modeName: MODE_NAMES[buf[5]] || 'unknown',
      keyId: raw.subarray(6, 14),
      salt: raw.subarray(14, 30),
      noncePrefix: raw.subarray(30, 37),
      chunkSize,
      ext: raw.subarray(FIXED_HEADER, total),
    },
  };
}

function nonce(prefix, counter, last) {
  const n = Buffer.alloc(12);
  prefix.copy(n, 0);
  n.writeUInt32BE(counter, 7);
  n[11] = last ? 1 : 0;
  return n;
}

// ---------- streams ----------

/** Creates an encrypting Transform. `params` from keyring.encryptParams(). */
export function createEncryptStream(params, { chunkSize = DEFAULT_CHUNK } = {}) {
  const noncePrefix = crypto.randomBytes(7);
  const header = encodeHeader({ ...params, noncePrefix, chunkSize });
  const key = fileKey(params.master, params.salt, params.mode);
  let counter = 0;
  let pending = [];
  let pendingLen = 0;

  const seal = (plain, last) => {
    if (counter === 0xffffffff) throw new Error('File too large for chunk counter');
    const c = crypto.createCipheriv('aes-256-gcm', key, nonce(noncePrefix, counter++, last));
    c.setAAD(header);
    const out = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    return out;
  };

  let headerSent = false;
  return new Transform({
    transform(chunk, _enc, cb) {
      try {
        if (!headerSent) { this.push(header); headerSent = true; }
        pending.push(chunk);
        pendingLen += chunk.length;
        // only seal a full chunk once we know more data follows it (strictly greater)
        if (pendingLen > chunkSize) {
          let buf = Buffer.concat(pending, pendingLen);
          while (buf.length > chunkSize) {
            this.push(seal(buf.subarray(0, chunkSize), false));
            buf = buf.subarray(chunkSize);
          }
          pending = [buf];
          pendingLen = buf.length;
        }
        cb();
      } catch (e) { cb(e); }
    },
    flush(cb) {
      try {
        if (!headerSent) { this.push(header); headerSent = true; }
        this.push(seal(Buffer.concat(pending, pendingLen), true));
        pending = [];
        cb();
      } catch (e) { cb(e); }
    },
  });
}

/** Creates a decrypting Transform. Emits 'header' once the header is parsed. */
export function createDecryptStream(keyring) {
  let buf = Buffer.alloc(0);
  let header = null;
  let key = null;
  let frame = 0;
  let counter = 0;
  let sawLast = false;

  const open = (sealed, last) => {
    if (sealed.length < TAG) throw new DecryptError('Truncated frame');
    const d = crypto.createDecipheriv('aes-256-gcm', key, nonce(header.noncePrefix, counter++, last));
    d.setAAD(header.raw);
    d.setAuthTag(sealed.subarray(sealed.length - TAG));
    try {
      return Buffer.concat([d.update(sealed.subarray(0, sealed.length - TAG)), d.final()]);
    } catch {
      throw new DecryptError(last
        ? 'Authentication failed on final block: file is truncated, corrupted, tampered, or the key is wrong'
        : `Authentication failed at block ${counter - 1}: file is corrupted, tampered, or the key is wrong`);
    }
  };

  const t = new Transform({
    transform(chunk, _enc, cb) {
      (async () => {
        buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
        if (!header) {
          const parsed = decodeHeader(buf);
          if (!parsed) return;
          header = parsed.header;
          buf = buf.subarray(parsed.bytes);
          const master = await keyring.decryptMaster(header);
          key = fileKey(master, header.salt, header.mode);
          frame = header.chunkSize + TAG;
          t.emit('header', header);
        }
        while (buf.length > frame) {
          this.push(open(buf.subarray(0, frame), false));
          buf = buf.subarray(frame);
        }
      })().then(() => cb(), cb);
    },
    flush(cb) {
      try {
        if (!header) throw new DecryptError('File is empty or truncated (no header)');
        if (sawLast) return cb();
        this.push(open(buf, true));
        sawLast = true;
        cb();
      } catch (e) { cb(e); }
    },
  });
  return t;
}

/** Read only the header of an encrypted file (for "list" / "doctor"). */
export async function readFileHeader(path) {
  const fh = await fs.promises.open(path, 'r');
  try {
    const b = Buffer.alloc(FIXED_HEADER + 64);
    const { bytesRead } = await fh.read(b, 0, b.length, 0);
    const parsed = decodeHeader(b.subarray(0, bytesRead));
    if (!parsed) throw new DecryptError('Truncated header');
    return parsed.header;
  } finally {
    await fh.close();
  }
}
