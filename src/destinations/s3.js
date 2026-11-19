import fs from 'node:fs';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  DeleteObjectsCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { log } from '../log.js';

const MB = 1024 * 1024;

/**
 * S3 or any S3-compatible store (Cloudflare R2, Backblaze B2, Wasabi, DigitalOcean Spaces, MinIO).
 * dest: { bucket, region, prefix, endpoint, forcePathStyle, accessKeyId, secretAccessKey,
 *         storageClass, sse: 'AES256' | 'aws:kms', kmsKeyId, objectLock: { mode, days },
 *         multipartThresholdMB, partSizeMB, queueSize }
 */
export function s3Destination(dest, { client } = {}) {
  const isAws = !dest.endpoint;
  const s3 = client || new S3Client({
    region: dest.region || process.env.AWS_REGION || 'us-east-1',
    endpoint: dest.endpoint || undefined,
    forcePathStyle: Boolean(dest.forcePathStyle),
    credentials: dest.accessKeyId ? {
      accessKeyId: dest.accessKeyId,
      secretAccessKey: dest.secretAccessKey,
      sessionToken: dest.sessionToken || undefined,
    } : undefined,
    // S3-compatible stores often reject the SDK's default CRC trailers; we send our own checksums
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    maxAttempts: 4,
    // the SDK cannot replay a file stream after a 5xx and would print to console; our own retry()
    // re-opens the file and logs the failure, so SDK chatter goes to debug level
    logger: {
      trace() {}, debug() {}, info() {},
      warn: (...m) => log.debug(`s3 sdk: ${m.join(' ')}`),
      error: (...m) => log.debug(`s3 sdk: ${m.join(' ')}`),
    },
  });
  const prefix = dest.prefix ? `${dest.prefix}/` : '';
  const full = (key) => prefix + key;
  const strip = (key) => (key.startsWith(prefix) ? key.slice(prefix.length) : key);
  const threshold = (dest.multipartThresholdMB || 64) * MB;

  const writeParams = (key, opts) => {
    const p = {
      Bucket: dest.bucket,
      Key: full(key),
      ContentType: opts.contentType || 'application/octet-stream',
      Metadata: opts.metadata || {},
    };
    if (dest.storageClass && !opts.standardClass) p.StorageClass = dest.storageClass;
    if (dest.sse) p.ServerSideEncryption = dest.sse;
    if (dest.sse === 'aws:kms' && dest.kmsKeyId) p.SSEKMSKeyId = dest.kmsKeyId;
    if (dest.objectLock?.mode && dest.objectLock?.days) {
      p.ObjectLockMode = dest.objectLock.mode; // GOVERNANCE | COMPLIANCE
      p.ObjectLockRetainUntilDate = new Date(Date.now() + dest.objectLock.days * 86400_000);
    }
    return p;
  };

  return {
    name: dest.name,
    type: 's3',
    client: s3,
    describe: () => `s3://${dest.bucket}/${prefix}${dest.endpoint ? ` @ ${dest.endpoint}` : ''}${dest.storageClass ? ` [${dest.storageClass}]` : ''}`,

    /** Upload a local file. opts: { size, sha256 (hex), md5 (hex), metadata, contentType } */
    async putFile(key, file, opts = {}) {
      const size = opts.size ?? fs.statSync(file).size;
      const params = writeParams(key, opts);
      if (size <= threshold) {
        params.Body = fs.createReadStream(file);
        params.ContentLength = size;
        if (isAws && opts.sha256) params.ChecksumSHA256 = Buffer.from(opts.sha256, 'hex').toString('base64');
        else if (opts.md5) params.ContentMD5 = Buffer.from(opts.md5, 'hex').toString('base64');
        await s3.send(new PutObjectCommand(params));
      } else {
        // multipart: parts are uploaded in parallel and retried individually
        const partSize = Math.max((dest.partSizeMB || 16) * MB, Math.ceil(size / 9000));
        params.Body = fs.createReadStream(file, { highWaterMark: MB });
        if (isAws) params.ChecksumAlgorithm = 'SHA256';
        const up = new Upload({ client: s3, params, partSize, queueSize: dest.queueSize || 4, leavePartsOnError: false });
        await up.done();
      }
      // confirm the object is really there with the expected size
      const head = await s3.send(new HeadObjectCommand({ Bucket: dest.bucket, Key: full(key) }));
      if (Number(head.ContentLength) !== size) {
        throw new Error(`Upload size mismatch for ${key}: local ${size}, remote ${head.ContentLength}`);
      }
      return { location: `s3://${dest.bucket}/${full(key)}`, etag: head.ETag };
    },

    async putJson(key, obj) {
      const body = Buffer.from(JSON.stringify(obj, null, 2));
      const crypto = await import('node:crypto');
      const params = writeParams(key, { contentType: 'application/json', standardClass: true });
      params.Body = body;
      params.ContentMD5 = crypto.createHash('md5').update(body).digest('base64');
      await s3.send(new PutObjectCommand(params));
    },

    async getStream(key) {
      const r = await s3.send(new GetObjectCommand({ Bucket: dest.bucket, Key: full(key) }));
      return r.Body;
    },

    async getJson(key) {
      const r = await s3.send(new GetObjectCommand({ Bucket: dest.bucket, Key: full(key) }));
      return JSON.parse(await r.Body.transformToString());
    },

    async list(sub = '') {
      const out = [];
      let token;
      do {
        const r = await s3.send(new ListObjectsV2Command({ Bucket: dest.bucket, Prefix: full(sub), ContinuationToken: token }));
        for (const o of r.Contents || []) out.push({ key: strip(o.Key), size: Number(o.Size), lastModified: o.LastModified ? new Date(o.LastModified) : null });
        token = r.IsTruncated ? r.NextContinuationToken : undefined;
      } while (token);
      return out;
    },

    async remove(keys) {
      const failed = [];
      for (let i = 0; i < keys.length; i += 1000) {
        const batch = keys.slice(i, i + 1000);
        if (batch.length === 1) {
          await s3.send(new DeleteObjectCommand({ Bucket: dest.bucket, Key: full(batch[0]) }));
          continue;
        }
        const r = await s3.send(new DeleteObjectsCommand({
          Bucket: dest.bucket,
          Delete: { Objects: batch.map((k) => ({ Key: full(k) })), Quiet: true },
        }));
        for (const e of r.Errors || []) failed.push(`${strip(e.Key)}: ${e.Code} ${e.Message || ''}`.trim());
      }
      if (failed.length) throw new Error(`Could not delete ${failed.length} object(s): ${failed.slice(0, 3).join('; ')}`);
    },
  };
}
