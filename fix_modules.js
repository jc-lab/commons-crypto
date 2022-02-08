const path = require('path');
const fs = require('fs');
const child_process = require('child_process');

if (process.env['npm_command']) {
  child_process.execSync('npm dedupe', {
    stdio: 'inherit'
  });
}

try {
  // hoisting
  const pkijsNodeModulesDir = path.resolve('./node_modules/pkijs/node_modules');
  if (fs.existsSync(pkijsNodeModulesDir)) {
    fs.rmdirSync(pkijsNodeModulesDir , {
      recursive: true
    });
  }
} catch (e) {
  console.warn(e);
}
