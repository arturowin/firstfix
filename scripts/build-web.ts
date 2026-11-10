import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { build } from 'esbuild';

const root = path.join(import.meta.dirname, '..');
const out = path.join(root, 'dist', 'web');

await mkdir(out, { recursive: true });
await build({
  entryPoints: [path.join(root, 'src', 'web', 'app.ts')],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  minify: true,
  sourcemap: false,
  outfile: path.join(out, 'app.js'),
  logLevel: 'warning',
});
await copyFile(path.join(root, 'src', 'web', 'index.html'), path.join(out, 'index.html'));
console.log(`web: built to ${path.relative(root, out)}`);
