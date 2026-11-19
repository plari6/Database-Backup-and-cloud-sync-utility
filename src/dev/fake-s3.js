// Minimal in-memory S3-compatible server (path-style) so the demo and tests drive the REAL AWS SDK
// offline: PutObject (Content-MD5 / SHA256 checked), multipart upload, Get/Head/Delete, ListObjectsV2,
// DeleteObjects. Fault injection: failNext(n) makes the next n writes return 503.
import http from 'node:http';
import crypto from 'node:crypto';

const xmlEsc = (s) => String(s).replace(/[<>&'"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c]));

function decodeAwsChunked(buf) {
  const out = [];
  let i = 0;
  while (i < buf.length) {
    const eol = buf.indexOf('\r\n', i);
    if (eol < 0) break;
    const size = parseInt(buf.subarray(i, eol).toString().split(';')[0], 16);
    i = eol + 2;
    if (!size) break;
    out.push(buf.subarray(i, i + size));
    i += size + 2;
  }
  return Buffer.concat(out);
}

export async function startFakeS3({ port = 0 } = {}) {
  const buckets = new Map(); // bucket -> Map(key -> { body, etag, lastModified, metadata })
  const uploads = new Map(); // uploadId -> { bucket, key, parts: Map }
  let failWrites = 0;
  const stats = { puts: 0, gets: 0, deletes: 0, multipart: 0 };

  const bucketOf = (name) => {
    if (!buckets.has(name)) buckets.set(name, new Map());
    return buckets.get(name);
  };

  const send = (res, status, body = '', headers = {}) => {
    res.writeHead(status, { 'content-type': body ? 'application/xml' : 'text/plain', ...headers });
    res.end(body);
  };
  const error = (res, status, code, message) =>
    send(res, status, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${xmlEsc(message)}</Message></Error>`);

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let body = Buffer.concat(chunks);
    if (/aws-chunked/.test(req.headers['content-encoding'] || '') || req.headers['x-amz-decoded-content-length']) {
      body = decodeAwsChunked(body);
    }

    const url = new URL(req.url, 'http://x');
    const [, bucketName, ...rest] = url.pathname.split('/');
    const key = decodeURIComponent(rest.join('/'));
    const q = url.searchParams;
    const bucket = bucketOf(decodeURIComponent(bucketName));
    const isWrite = req.method === 'PUT' || (req.method === 'POST' && !q.has('delete'));

    if (isWrite && failWrites > 0) {
      failWrites--;
      return error(res, 503, 'SlowDown', 'Injected failure');
    }

    try {
      // ----- bucket level -----
      if (!key) {
        if (req.method === 'HEAD') return send(res, 200);
        if (req.method === 'GET' && q.get('list-type') === '2') {
          const prefix = q.get('prefix') || '';
          const max = Number(q.get('max-keys') || 1000);
          const start = Number(q.get('continuation-token') || 0);
          const keys = [...bucket.keys()].filter((k) => k.startsWith(prefix)).sort();
          const page = keys.slice(start, start + max);
          const truncated = start + max < keys.length;
          const contents = page.map((k) => {
            const o = bucket.get(k);
            return `<Contents><Key>${xmlEsc(k)}</Key><LastModified>${o.lastModified.toISOString()}</LastModified><ETag>"${o.etag}"</ETag><Size>${o.body.length}</Size><StorageClass>STANDARD</StorageClass></Contents>`;
          }).join('');
          return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>${xmlEsc(bucketName)}</Name><Prefix>${xmlEsc(prefix)}</Prefix><KeyCount>${page.length}</KeyCount><MaxKeys>${max}</MaxKeys><IsTruncated>${truncated}</IsTruncated>${truncated ? `<NextContinuationToken>${start + max}</NextContinuationToken>` : ''}${contents}</ListBucketResult>`);
        }
        if (req.method === 'POST' && q.has('delete')) {
          const keys = [...body.toString().matchAll(/<Key>([\s\S]*?)<\/Key>/g)].map((m) => m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'));
          for (const k of keys) bucket.delete(k);
          stats.deletes += keys.length;
          return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?><DeleteResult>${keys.map((k) => `<Deleted><Key>${xmlEsc(k)}</Key></Deleted>`).join('')}</DeleteResult>`);
        }
        return error(res, 400, 'NotImplemented', `${req.method} on bucket`);
      }

      // ----- multipart -----
      if (req.method === 'POST' && q.has('uploads')) {
        const id = crypto.randomUUID();
        uploads.set(id, { bucket, key, parts: new Map(), metadata: metaOf(req) });
        stats.multipart++;
        return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>${xmlEsc(bucketName)}</Bucket><Key>${xmlEsc(key)}</Key><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
      }
      if (req.method === 'PUT' && q.has('uploadId')) {
        const up = uploads.get(q.get('uploadId'));
        if (!up) return error(res, 404, 'NoSuchUpload', 'no upload');
        const etag = crypto.createHash('md5').update(body).digest('hex');
        up.parts.set(Number(q.get('partNumber')), { body, etag });
        return send(res, 200, '', { etag: `"${etag}"` });
      }
      if (req.method === 'POST' && q.has('uploadId')) {
        const up = uploads.get(q.get('uploadId'));
        if (!up) return error(res, 404, 'NoSuchUpload', 'no upload');
        const nums = [...body.toString().matchAll(/<PartNumber>(\d+)<\/PartNumber>/g)].map((m) => Number(m[1]));
        const data = Buffer.concat(nums.map((n) => up.parts.get(n).body));
        const etag = `${crypto.createHash('md5').update(data).digest('hex')}-${nums.length}`;
        up.bucket.set(up.key, { body: data, etag, lastModified: new Date(), metadata: up.metadata });
        uploads.delete(q.get('uploadId'));
        stats.puts++;
        return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult><Bucket>${xmlEsc(bucketName)}</Bucket><Key>${xmlEsc(up.key)}</Key><ETag>"${etag}"</ETag></CompleteMultipartUploadResult>`);
      }
      if (req.method === 'DELETE' && q.has('uploadId')) {
        uploads.delete(q.get('uploadId'));
        return send(res, 204);
      }

      // ----- objects -----
      if (req.method === 'PUT') {
        const md5 = req.headers['content-md5'];
        if (md5 && crypto.createHash('md5').update(body).digest('base64') !== md5) return error(res, 400, 'BadDigest', 'Content-MD5 mismatch');
        const sha = req.headers['x-amz-checksum-sha256'];
        if (sha && crypto.createHash('sha256').update(body).digest('base64') !== sha) return error(res, 400, 'BadDigest', 'SHA256 mismatch');
        const etag = crypto.createHash('md5').update(body).digest('hex');
        bucket.set(key, { body, etag, lastModified: new Date(), metadata: metaOf(req) });
        stats.puts++;
        return send(res, 200, '', { etag: `"${etag}"` });
      }
      const obj = bucket.get(key);
      if (req.method === 'DELETE') {
        bucket.delete(key);
        stats.deletes++;
        return send(res, 204);
      }
      if (!obj) {
        if (req.method === 'HEAD') return send(res, 404);
        return error(res, 404, 'NoSuchKey', 'The specified key does not exist.');
      }
      const headers = {
        'content-length': obj.body.length,
        etag: `"${obj.etag}"`,
        'last-modified': obj.lastModified.toUTCString(),
        'content-type': 'application/octet-stream',
        ...Object.fromEntries(Object.entries(obj.metadata).map(([k, v]) => [`x-amz-meta-${k}`, v])),
      };
      if (req.method === 'HEAD') { res.writeHead(200, headers); return res.end(); }
      if (req.method === 'GET') {
        stats.gets++;
        res.writeHead(200, headers);
        return res.end(obj.body);
      }
      return error(res, 400, 'NotImplemented', req.method);
    } catch (e) {
      return error(res, 500, 'InternalError', e.message);
    }
  });

  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  return {
    endpoint,
    buckets,
    stats,
    failNext(n = 1) { failWrites = n; },
    /** flip one byte in an object (tamper / bit-rot simulation) */
    tamper(bucket, key, offset = 200) {
      const o = bucketOf(bucket).get(key);
      if (!o) throw new Error(`no object ${key}`);
      o.body = Buffer.from(o.body);
      o.body[Math.min(offset, o.body.length - 1)] ^= 0xff;
    },
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}

function metaOf(req) {
  return Object.fromEntries(Object.entries(req.headers).filter(([k]) => k.startsWith('x-amz-meta-')).map(([k, v]) => [k.slice(11), v]));
}
