"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const CORE_FILES = ["ida_zh_cn.py", "zh_cn.json"];
const REMOVABLE_FILES = ["ida_zh_cn.py", "zh_cn.json", "ida_zh_cn.conf.json", "ida_zh_cn_missing.txt"];

function pluginSourceDir() {
  const candidates = [];
  if (process.resourcesPath) candidates.push(path.join(process.resourcesPath, "ida-zh-cn", "plugin"));
  candidates.push(path.resolve(__dirname, "..", "..", "..", "tools", "ida-zh-cn", "plugin"));
  return candidates.find((dir) => fs.existsSync(path.join(dir, "ida_zh_cn.py"))) || candidates[candidates.length - 1];
}

function assertPluginDir(target) {
  const resolved = path.resolve(String(target || ""));
  if (!resolved || path.basename(resolved).toLowerCase() !== "plugins") {
    throw new Error("只写入名为 plugins 的目录");
  }
  if (resolved === path.parse(resolved).root) throw new Error("拒绝写入磁盘根目录");
  return resolved;
}

function resolveTarget(options = {}) {
  if (options.target) return { target: assertPluginDir(options.target), targetSource: "override" };
  const env = options.env || process.env;
  const home = options.home || os.homedir();
  const platform = options.platform || process.platform;
  // IDAUSR accepts a platform-native search path list. Keep the first entry,
  // matching IDA's own plugin lookup order while preserving Windows drive letters.
  const delimiter = platform === "win32" ? ";" : ":";
  let idausr = String(env.IDAUSR || "").split(delimiter)[0].trim();
  if (idausr === "~") idausr = home;
  if (idausr.startsWith("~/") || idausr.startsWith("~\\")) idausr = path.join(home, idausr.slice(2));
  if (idausr) return { target: assertPluginDir(path.join(idausr, "plugins")), targetSource: "IDAUSR" };
  if (platform === "darwin") {
    return {
      target: assertPluginDir(path.join(home, "Library", "Application Support", "Hex-Rays", "IDA Pro", "plugins")),
      targetSource: "macOS 用户目录",
    };
  }
  if (platform === "linux" || platform === "freebsd" || platform === "openbsd") {
    return {
      target: assertPluginDir(path.join(home, ".idapro", "plugins")),
      targetSource: "Linux 用户目录",
    };
  }
  const appData = String(env.APPDATA || "").trim() || path.join(home, "AppData", "Roaming");
  return {
    target: assertPluginDir(path.join(appData, "Hex-Rays", "IDA Pro", "plugins")),
    targetSource: "APPDATA",
  };
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function fileInfo(dir, name, sourceHash) {
  const file = path.join(dir, name);
  const present = fs.existsSync(file) && fs.statSync(file).isFile();
  if (!present) return { name, present: false, match: false };
  const match = sourceHash ? sha256(fs.readFileSync(file)) === sourceHash : false;
  return { name, present: true, match };
}

function sourceHashes(sourceDir) {
  const hashes = {};
  for (const name of CORE_FILES) {
    const file = path.join(sourceDir, name);
    if (!fs.existsSync(file)) return null;
    hashes[name] = sha256(fs.readFileSync(file));
  }
  return hashes;
}

function status(options = {}) {
  const sourceDir = options.sourceDir || pluginSourceDir();
  const where = resolveTarget(options);
  const hashes = sourceHashes(sourceDir);
  const files = CORE_FILES.map((name) => fileInfo(where.target, name, hashes?.[name]));
  const installed = Boolean(hashes) && files.every((item) => item.match);
  const present = files.some((item) => item.present);
  return {
    ok: true,
    action: "status",
    sourceDir,
    sourceReady: Boolean(hashes),
    ...where,
    targetExists: fs.existsSync(where.target),
    installed,
    present,
    files,
  };
}

function contained(root, name) {
  if (name !== path.basename(name)) throw new Error("插件文件名不能带路径");
  const file = path.join(root, name);
  const relative = path.relative(root, file);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("目标文件越出插件目录");
  return file;
}

function install(options = {}) {
  const sourceDir = options.sourceDir || pluginSourceDir();
  const hashes = sourceHashes(sourceDir);
  if (!hashes) throw new Error("找不到收进仓库的 IDA 汉化插件");
  const where = resolveTarget(options);
  fs.mkdirSync(where.target, { recursive: true });
  const backups = [];
  for (const name of CORE_FILES) {
    const dest = contained(where.target, name);
    if (fs.existsSync(dest)) {
      const current = fs.readFileSync(dest);
      if (sha256(current) !== hashes[name]) {
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        const backup = path.join(where.target, ".ida-zh-cn-backup", stamp, name);
        fs.mkdirSync(path.dirname(backup), { recursive: true });
        fs.writeFileSync(backup, current);
        backups.push(backup);
      }
    }
    fs.copyFileSync(path.join(sourceDir, name), dest);
  }
  return { ...status({ ...options, sourceDir }), action: "install", backups };
}

function uninstall(options = {}) {
  const where = resolveTarget(options);
  const removed = [];
  if (fs.existsSync(where.target)) {
    for (const name of REMOVABLE_FILES) {
      const file = contained(where.target, name);
      if (!fs.existsSync(file)) continue;
      fs.unlinkSync(file);
      removed.push(file);
    }
  }
  return { ...status(options), action: "uninstall", removed };
}

module.exports = {
  CORE_FILES,
  REMOVABLE_FILES,
  pluginSourceDir,
  resolveTarget,
  status,
  install,
  uninstall,
};
