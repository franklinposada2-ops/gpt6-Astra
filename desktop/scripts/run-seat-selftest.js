"use strict";

const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..", "..");
const script = path.join(root, "tools", "seat_selftest.py");
const candidates = process.platform === "win32"
  ? ["python", "py", "python3"]
  : ["python3", "python"];

for (const command of candidates) {
  const result = spawnSync(command, [script], {
    cwd: root,
    stdio: "inherit",
    env: { ...process.env, PYTHONUTF8: "1" },
    windowsHide: process.platform === "win32",
  });
  if (result.error?.code === "ENOENT") continue;
  process.exit(result.status == null ? 1 : result.status);
}

console.error(`找不到 Python 3 运行时。请安装 Python 3.9+ 后重试（尝试过：${candidates.join(", ")}）。`);
process.exit(1);
