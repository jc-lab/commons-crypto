const path = require('path');
const fs = require('fs');

fs.rmdirSync(path.resolve('./node_modules/pkijs/node_modules') , {
    recursive: true
});
