import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';

/** Local folder, mounted NAS, external drive or network share (second copy for the 3-2-1 rule). */
export function localDestination(dest) {
  const root = path.join(dest.path, dest.prefix || '');
  const abs = (key) => {
    const p = path.resolve(root, key);
    if (!p.startsWith(path.resolve(root))) throw new Error(`Invalid key ${key}`);
    return p;
  };

  return {
    name: dest.name,
    type: 'local',
    describe: () => `local ${root}`,

    async putFile(key, file, opts = {}) {
      const target = abs(key);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const tmp = `${target}.partial`;
      await pipeline(fs.createReadStream(file), fs.createWriteStream(tmp));
      const size = fs.statSync(tmp).size;
      const expected = opts.size ?? fs.statSync(file).size;
      if (size !== expected) {
        fs.rmSync(tmp, { force: true });
        throw new Error(`Copy size mismatch for ${key}: ${size} != ${expected}`);
      }
      fs.renameSync(tmp, target);
      return { location: target };
    },

    async putJson(key, obj) {
      const target = abs(key);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(`${target}.partial`, JSON.stringify(obj, null, 2));
      fs.renameSync(`${target}.partial`, target);
    },

    async getStream(key) {
      const p = abs(key);
      if (!fs.existsSync(p)) throw Object.assign(new Error(`Not found: ${key}`), { name: 'NoSuchKey' });
      return fs.createReadStream(p);
    },

    async getJson(key) {
      return JSON.parse(fs.readFileSync(abs(key), 'utf8'));
    },

    async list(sub = '') {
      const out = [];
      const base = path.resolve(root);
      const walk = (dir) => {
        if (!fs.existsSync(dir)) return;
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
          const p = path.join(dir, e.name);
          if (e.isDirectory()) walk(p);
          else if (!e.name.endsWith('.partial')) {
            const key = path.relative(base, p).split(path.sep).join('/');
            if (key.startsWith(sub)) {
              const st = fs.statSync(p);
              out.push({ key, size: st.size, lastModified: st.mtime });
            }
          }
        }
      };
      walk(base);
      return out;
    },

    async remove(keys) {
      for (const k of keys) {
        const p = abs(k);
        fs.rmSync(p, { force: true });
        // tidy empty year/month folders
        let dir = path.dirname(p);
        while (dir.startsWith(path.resolve(root)) && dir !== path.resolve(root)) {
          try { fs.rmdirSync(dir); } catch { break; }
          dir = path.dirname(dir);
        }
      }
    },
  };
}
