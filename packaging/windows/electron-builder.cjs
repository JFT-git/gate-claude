'use strict';
const path = require('node:path');

module.exports = {
  appId: 'local.proxyguard.gate-claude',
  productName: 'Claude Proxy Guard',
  extraMetadata: { name: 'Claude Proxy Guard' },
  directories: { output: process.env.GUARD_WINDOWS_ARTIFACT_DIR },
  publish: { provider: 'github', owner: 'JFT-git', repo: 'gate-claude', channel: 'latest' },
  win: { target: [{ target: 'nsis', arch: ['x64'] }] },
  nsis: {
    oneClick: true,
    perMachine: false,
    allowElevation: false,
    allowToChangeInstallationDirectory: false,
    deleteAppDataOnUninstall: false,
    differentialPackage: true,
    createDesktopShortcut: false,
    createStartMenuShortcut: true,
    artifactName: 'ClaudeProxyGuard-Windows-${version}-x64-Setup.${ext}',
    include: path.join(__dirname, 'installer.nsh')
  }
};
