'use strict';
console.log(JSON.stringify({ node: process.versions.node, zstdDecompress: typeof require('node:zlib').zstdDecompress, sqlite: typeof require('node:sqlite').DatabaseSync }));
