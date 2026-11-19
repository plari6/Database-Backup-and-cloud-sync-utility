import { s3Destination } from './s3.js';
import { localDestination } from './local.js';

const cache = new Map();

/** Create (and cache) a destination adapter. `overrides` lets tests inject an S3 client. */
export function getDestination(cfg, name, overrides = {}) {
  const d = cfg.destinations[name];
  if (!d) throw new Error(`Unknown destination "${name}"`);
  const cacheKey = `${cfg.file}::${name}`;
  if (!overrides.fresh && cache.has(cacheKey)) return cache.get(cacheKey);
  const adapter = d.type === 's3' ? s3Destination(d, overrides) : localDestination(d);
  cache.set(cacheKey, adapter);
  return adapter;
}

export function clearDestinationCache() {
  cache.clear();
}

/** Object layout: <job>/<yyyy>/<mm>/<job>-<id>.<ext>[.gz|.zst].dbbk + <job>-<id>.manifest.json */
export function objectKeys(job, id, fileExt) {
  const y = id.slice(0, 4);
  const m = id.slice(4, 6);
  const base = `${job}/${y}/${m}/${job}-${id}`;
  return { data: `${base}.${fileExt}.dbbk`, manifest: `${base}.manifest.json` };
}
