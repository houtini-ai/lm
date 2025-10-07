#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const distPath = path.join(__dirname, 'dist', 'index-lite.js');

// Read the file
let content = fs.readFileSync(distPath, 'utf8');

// Add shebang if not present
if (!content.startsWith('#!/usr/bin/env node')) {
  content = '#!/usr/bin/env node\n' + content;
  fs.writeFileSync(distPath, content);
  console.log('Shebang added to dist/index-lite.js');
} else {
  console.log('Shebang already present in dist/index-lite.js');
}
