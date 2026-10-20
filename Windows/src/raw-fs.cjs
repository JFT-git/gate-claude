'use strict';
// Vendor app.asar must remain a real file. Electron's default fs treats ASAR
// archives as virtual directories, including archives outside this application.
module.exports = process.versions.electron ? require('original-fs') : require('node:fs');
