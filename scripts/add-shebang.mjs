import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Resolve dist/ from the repo root, not from this script's directory. This
// lived at the repo root and used __dirname directly; moving it into scripts/
// silently pointed it at scripts/dist/index.js and broke the build.
const repoRoot = path.resolve(__dirname, '..');

const indexPath = path.join(repoRoot, 'dist', 'index.js');
const content = fs.readFileSync(indexPath, 'utf8');

if (!content.startsWith('#!/usr/bin/env node')) {
  fs.writeFileSync(indexPath, '#!/usr/bin/env node\n' + content);
  console.log('Added shebang to dist/index.js');
} else {
  console.log('Shebang already present in dist/index.js');
}
