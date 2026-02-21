// Copy the fixed compiled JS to the main file
const fs = require('fs');
const path = require('path');

const source = path.join(__dirname, 'dist', 'index-lite-fixed.js');
const dest = path.join(__dirname, 'dist', 'index-lite.js');

fs.copyFileSync(source, dest);
console.log('Fixed version deployed to index-lite.js');