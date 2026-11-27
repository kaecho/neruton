import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

const esmPkgPath = path.join(rootDir, 'dist', 'esm', 'package.json');
const cjsPkgPath = path.join(rootDir, 'dist', 'cjs', 'package.json');

fs.writeFileSync(esmPkgPath, JSON.stringify({ type: 'module' }, null, 2) + '\n', 'utf8');
fs.writeFileSync(cjsPkgPath, JSON.stringify({ type: 'commonjs' }, null, 2) + '\n', 'utf8');

for (const binPath of [
  path.join(rootDir, 'dist', 'esm', 'bin.js'),
  path.join(rootDir, 'dist', 'cjs', 'bin.js'),
]) {
  if (fs.existsSync(binPath)) {
    const content = fs.readFileSync(binPath, 'utf8');
    if (!content.startsWith('#!/usr/bin/env node\n')) {
      fs.writeFileSync(binPath, '#!/usr/bin/env node\n' + content, 'utf8');
    }
    try {
      fs.chmodSync(binPath, 0o755);
    } catch {
      // Ignore chmod errors on non-POSIX filesystems.
    }
  }
}
