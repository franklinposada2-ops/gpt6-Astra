'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function cursorConfigDir(env = process.env, home = os.homedir()) {
  const configured = String(env.CURSOR_HOME || '').trim();
  if (!configured) return path.join(home, '.cursor');
  return path.resolve(configured);
}

function assertCursorUserDir(target) {
  const resolved = path.resolve(String(target));
  if (path.basename(resolved) !== '.cursor') {
    throw new Error('Cursor 破甲只写入名为 .cursor 的用户目录（例如 %USERPROFILE%\\.cursor），不写安装目录，也不写 AppData\\Cursor');
  }
  if (fs.existsSync(path.join(resolved, 'Cursor.exe')) || fs.existsSync(path.join(resolved, 'resources', 'app'))) {
    throw new Error('这是 Cursor 程序目录，破甲不写这里');
  }
  return resolved;
}

module.exports = { cursorConfigDir, assertCursorUserDir };
