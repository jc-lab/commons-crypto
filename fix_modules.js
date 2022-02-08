const path = require('path');
const fs = require('fs');

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
