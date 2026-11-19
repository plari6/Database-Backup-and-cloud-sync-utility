import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Readable, Writable } from 'node:stream';
import {
  createKeyring, createEncryptStream, createDecryptStream, generateSymmetricKey,
  generateRecipientKeyPair, parseSymmetricKey, DecryptError,
} from '../src/crypto.js';

async function encrypt(keyring, data, chunkSize) {
  const out = [];
  const params = await keyring.encryptParams();
  // feed in odd-sized pieces to exercise buffering
  const pieces = [];
  for (let i = 0; i < data.length; i += 7777) pieces.push(data.subarray(i, i + 7777));
  await pipeline(Readable.from(pieces.length ? pieces : [Buffer.alloc(0)]), createEncryptStream(params, { chunkSize }), new Writable({ write(c, _e, cb) { out.push(c); cb(); } }));
  return Buffer.concat(out);
}

async function decrypt(keyring, data) {
  const out = [];
  const pieces = [];
  for (let i = 0; i < data.length; i += 5003) pieces.push(data.subarray(i, i + 5003));
  await pipeline(Readable.from(pieces), createDecryptStream(keyring), new Writable({ write(c, _e, cb) { out.push(c); cb(); } }));
  return Buffer.concat(out);
}

const key = () => createKeyring({ mode: 'key', key: generateSymmetricKey() });

test('round trip at every size around chunk boundaries', async () => {
  const kr = key();
  const chunk = 4096;
  for (const n of [0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk, 3 * chunk + 17, 100_000]) {
    const data = crypto.randomBytes(n);
    const enc = await encrypt(kr, data, chunk);
    assert.equal(enc.subarray(0, 4).toString(), 'DBBK');
    assert.deepEqual(await decrypt(kr, enc), data, `size ${n}`);
  }
});

test('ciphertext reveals nothing and differs every time', async () => {
  const kr = key();
  const data = Buffer.from('customer@example.com '.repeat(1000));
  const a = await encrypt(kr, data);
  const b = await encrypt(kr, data);
  assert.ok(!a.includes('customer@example.com'));
  assert.notDeepEqual(a, b);
});

test('truncation at a frame boundary is detected', async () => {
  const kr = key();
  const chunk = 1024;
  const enc = await encrypt(kr, crypto.randomBytes(chunk * 4), chunk);
  const headerLen = 4 + 1 + 1 + 8 + 16 + 7 + 4 + 2;
  const frame = chunk + 16;
  for (const frames of [1, 2, 3]) {
    const cut = enc.subarray(0, headerLen + frames * frame);
    await assert.rejects(decrypt(kr, cut), DecryptError, `cut after ${frames} frames`);
  }
});

test('any flipped bit (body or header) is detected', async () => {
  const kr = key();
  const enc = await encrypt(kr, crypto.randomBytes(10_000), 2048);
  for (const pos of [5, 20, 40, 60, 3000, enc.length - 1]) {
    const bad = Buffer.from(enc);
    bad[pos] ^= 0x01;
    await assert.rejects(decrypt(kr, bad), (e) => e instanceof DecryptError || /magic|version|mode|chunk/i.test(e.message), `byte ${pos}`);
  }
});

test('wrong key gives a clear error; key rotation keeps old backups readable', async () => {
  const oldKey = generateSymmetricKey();
  const enc = await encrypt(createKeyring({ key: oldKey }), Buffer.from('old data'));
  await assert.rejects(decrypt(key(), enc), /No key with id/);
  const rotated = createKeyring({ key: generateSymmetricKey(), oldKeys: `${generateSymmetricKey()},${oldKey}` });
  assert.equal((await decrypt(rotated, enc)).toString(), 'old data');
});

test('passphrase mode', async () => {
  const kr = createKeyring({ mode: 'passphrase', passphrase: 'correct horse battery staple' });
  const enc = await encrypt(kr, Buffer.from('hello'));
  assert.equal((await decrypt(kr, enc)).toString(), 'hello');
  await assert.rejects(decrypt(createKeyring({ mode: 'passphrase', passphrase: 'wrong' }), enc), DecryptError);
});

test('recipient mode: public key encrypts, only the private key decrypts', async () => {
  const pair = generateRecipientKeyPair();
  const server = createKeyring({ mode: 'recipient', publicKey: pair.publicKeyPem });
  assert.ok(server.canEncrypt);
  const enc = await encrypt(server, Buffer.from('secret rows'));
  await assert.rejects(decrypt(server, enc), /BACKUP_PRIVATE_KEY/);
  const other = generateRecipientKeyPair();
  await assert.rejects(decrypt(createKeyring({ mode: 'recipient', privateKey: other.privateKeyPem }), enc), /recipient/);
  const restoreHost = createKeyring({ mode: 'recipient', privateKey: pair.privateKeyPem.replace(/\n/g, '\\n') });
  assert.equal((await decrypt(restoreHost, enc)).toString(), 'secret rows');
});

test('key parsing accepts base64, base64url, hex and rejects wrong sizes', () => {
  const raw = crypto.randomBytes(32);
  assert.deepEqual(parseSymmetricKey('base64:' + raw.toString('base64')), raw);
  assert.deepEqual(parseSymmetricKey(raw.toString('base64url')), raw);
  assert.deepEqual(parseSymmetricKey(raw.toString('hex')), raw);
  assert.throws(() => parseSymmetricKey('base64:' + crypto.randomBytes(16).toString('base64')), /32 bytes/);
  assert.throws(() => parseSymmetricKey(''), /empty/);
});

test('garbage input is rejected as not a backup file', async () => {
  await assert.rejects(decrypt(key(), Buffer.from('PGDMP this is a plain dump, not encrypted at all.....')), /bad magic/);
  await assert.rejects(decrypt(key(), Buffer.alloc(0)), /empty or truncated/);
});
