const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { callIdaMcp, probeIdaMcp } = require("./ida-mcp");

const MAX_OUTPUT = 12000;
const MAX_EVENTS = 500;

// The registry is deliberately declarative. A workflow can be rendered, inspected,
// or extended without teaching the renderer how to invoke a command.
const TOOL_REGISTRY = [
  { id: "nmap", label: "Nmap", category: "recon", command: "nmap", probeArgs: ["--version"] },
  { id: "naabu", label: "Naabu", category: "recon", command: "naabu", probeArgs: ["-version"] },
  { id: "httpx", label: "httpx", category: "web", command: "httpx", probeArgs: ["-version"] },
  { id: "nuclei", label: "Nuclei", category: "web", command: "nuclei", probeArgs: ["-version"] },
  { id: "ffuf", label: "ffuf", category: "web", command: "ffuf", probeArgs: ["-V"] },
  { id: "sqlmap", label: "sqlmap", category: "web", command: "sqlmap", probeArgs: ["--version"] },
  { id: "burpsuite", label: "Burp Suite", category: "proxy", command: "burpsuite", probeArgs: ["--version"] },
  { id: "mitmproxy", label: "mitmproxy", category: "proxy", command: "mitmproxy", probeArgs: ["--version"] },
  { id: "tshark", label: "TShark", category: "traffic", command: "tshark", probeArgs: ["--version"] },
  { id: "msfconsole", label: "Metasploit", category: "exploit", command: "msfconsole", probeArgs: ["-v"] },
  { id: "strings", label: "strings", category: "reverse", command: "strings", probeArgs: ["--version"] },
  { id: "ida", label: "IDA / IDA Pro", category: "reverse", command: "ida64", aliases: ["ida", "idat64"], probeArgs: ["-h"] },
  { id: "rizin", label: "Rizin", category: "reverse", command: "rz-bin", aliases: ["rabin2", "radare2"], probeArgs: ["-v"] },
  { id: "frida", label: "Frida", category: "reverse", command: "frida", probeArgs: ["--version"] },
  { id: "jadx", label: "JADX", category: "mobile", command: "jadx", probeArgs: ["--version"] },
  { id: "apktool", label: "Apktool", category: "mobile", command: "apktool", probeArgs: ["--version"] },
  { id: "adb", label: "ADB", category: "mobile", command: "adb", probeArgs: ["version"] },
  { id: "python", label: "Python", category: "runtime", command: process.platform === "win32" ? "python" : "python3", probeArgs: ["--version"] },
  { id: "node", label: "Node.js", category: "runtime", command: "node", probeArgs: ["--version"] },
];

function toolById(id) {
  return TOOL_REGISTRY.find((item) => item.id === id) || null;
}

function commandExists(command) {
  const probe = process.platform === "win32" ? "where.exe" : "which";
  try {
    const result = spawnSync(probe, [command], { encoding: "utf8", windowsHide: true, timeout: 2500 });
    const output = `${result.stdout || ""}`.trim();
    return result.status === 0 && Boolean(output);
  } catch {
    return false;
  }
}

function runProbe(tool) {
  const candidates = [tool.command, ...(tool.aliases || [])];
  for (const command of candidates) {
    if (!commandExists(command)) continue;
    try {
      const result = spawnSync(command, tool.probeArgs || ["--version"], {
        encoding: "utf8",
        windowsHide: true,
        timeout: 6000,
      });
      const detail = `${result.stdout || ""}${result.stderr || ""}`.trim().split(/\r?\n/)[0] || "";
      return { id: tool.id, label: tool.label, category: tool.category, ok: result.status === 0 || Boolean(detail), command, detail: detail.slice(0, 180) };
    } catch (error) {
      return { id: tool.id, label: tool.label, category: tool.category, ok: false, command, error: error.message };
    }
  }
  return { id: tool.id, label: tool.label, category: tool.category, ok: false, command: tool.command, error: "未找到可执行文件" };
}

function healthCheckTools(ids) {
  const selected = Array.isArray(ids) && ids.length
    ? TOOL_REGISTRY.filter((item) => ids.includes(item.id))
    : TOOL_REGISTRY;
  const results = selected.map(runProbe);
  return {
    checkedAt: new Date().toISOString(),
    platform: `${os.platform()}-${os.arch()}`,
    available: results.filter((item) => item.ok).length,
    total: results.length,
    tools: results,
  };
}

function safeText(value, max = MAX_OUTPUT) {
  return String(value || "").slice(0, max);
}

function normalizeInput(input = {}) {
  const source = input && typeof input === "object" ? input : {};
  const target = source.target || source.host || source.sample || source.file || null;
  const rawMode = String(source.mode || source.workflow || source.workflowId || source.template || "infiltration").toLowerCase();
  const mode = {
    web: "infiltration",
    pentest: "infiltration",
    ctf: "infiltration",
    ida: "reverse",
    rev: "reverse",
    apk: "mobile",
  }[rawMode] || rawMode;
  return {
    ...source,
    target: target ? String(target) : null,
    mode,
    home: source.home || null,
    cwd: source.cwd || process.cwd(),
    timeoutMs: Math.min(Math.max(Number(source.timeoutMs || 45000), 1000), 15 * 60 * 1000),
  };
}

function stage(id, label, kind, extra = {}) {
  return { id, label, kind, ...extra };
}

function defaultDefinition(mode) {
  if (["reverse", "rev", "ida", "native"].includes(mode)) {
    return {
      id: "reverse",
      label: "IDA 逆向分析",
      description: "样本确认、IDA MCP 健康检查、函数/字符串线索与证据整理。",
      toolIds: ["strings", "ida", "rizin", "frida"],
      stages: [
        stage("sample", "样本与工作目录", "input", { requires: "target", inputKind: "file" }),
        stage("ida-health", "IDA MCP 在线状态", "ida-health", { optional: true }),
        stage("ida-tools", "读取 IDA 工具能力", "ida-tools", { optional: true }),
        stage("strings", "提取可见字符串", "command", { tool: "strings", args: (ctx) => [ctx.target], optional: true }),
        stage("ida-functions", "读取函数索引", "ida-call", { tool: "get_functions", args: { limit: 200 }, optional: true }),
        stage("ida-xrefs", "追踪关键交叉引用", "ida-call", { tool: "get_xrefs", args: { limit: 200 }, optional: true }),
        stage("evidence", "整理逆向证据", "evidence"),
      ],
    };
  }
  if (["unlock", "crack", "patch", "keygen"].includes(mode)) {
    return {
      id: "unlock",
      label: "校验逻辑与补丁分析",
      description: "从样本、字符串和 IDA 函数线索开始，保留原样本并输出可回滚证据。",
      toolIds: ["strings", "ida", "rizin"],
      stages: [
        stage("sample", "样本与派生目录", "input", { requires: "target", inputKind: "file" }),
        stage("ida-health", "IDA MCP 在线状态", "ida-health", { optional: true }),
        stage("strings", "提取授权相关字符串", "command", { tool: "strings", args: (ctx) => [ctx.target], optional: true }),
        stage("ida-functions", "定位校验函数", "ida-call", { tool: "search", args: { query: "license|serial|check|verify|trial" }, optional: true }),
        stage("ida-decompile", "读取反编译结果", "ida-call", { tool: "decompile", args: { function: "CHECK_FN" }, optional: true }),
        stage("evidence", "输出偏移、补丁与回滚记录", "evidence"),
      ],
    };
  }
  if (["mobile", "apk", "android"].includes(mode)) {
    return {
      id: "mobile",
      label: "移动样本分析",
      description: "APK 基础信息、反编译与设备连接状态。",
      toolIds: ["jadx", "apktool", "adb", "frida"],
      stages: [
        stage("sample", "APK 样本", "input", { requires: "target", inputKind: "file" }),
        stage("apktool", "读取 APK 基础信息", "command", { tool: "apktool", args: (ctx) => ["if", ctx.target], optional: true }),
        stage("jadx", "反编译 Java/Kotlin", "command", { tool: "jadx", args: (ctx) => ["-d", path.join(ctx.artifactDir, "jadx"), ctx.target], optional: true }),
        stage("adb", "设备连接状态", "command", { tool: "adb", args: ["devices"], optional: true }),
        stage("evidence", "整理移动分析证据", "evidence"),
      ],
    };
  }
  if (["api", "graphql", "rest"].includes(mode)) {
    return {
      id: "api",
      label: "API 接口分析",
      description: "端点发现、HTTP 行为指纹、鉴权面线索和可复现证据。",
      toolIds: ["httpx", "ffuf", "nuclei", "sqlmap", "burpsuite"],
      stages: [
        stage("target", "API 目标与范围", "input", { requires: "target", inputKind: "target" }),
        stage("httpx", "HTTP 服务与技术栈", "command", { tool: "httpx", args: (ctx) => ["-u", ctx.target, "-json"], optional: true }),
        stage("ffuf", "端点与参数发现", "command", { tool: "ffuf", args: (ctx) => ["-u", `${ctx.target.replace(/\/$/, "")}/FUZZ`, "-w", ctx.wordlist || "WORDLIST", "-of", "json"], optional: true }),
        stage("nuclei", "API 漏洞模板验证", "command", { tool: "nuclei", args: (ctx) => ["-u", ctx.target, "-jsonl", "-silent"], optional: true }),
        stage("evidence", "汇总接口分析证据", "evidence"),
      ],
    };
  }
  return {
    id: "infiltration",
    label: "渗透测试流水线",
    description: "目标确认、端口/服务发现、HTTP 指纹、漏洞模板验证和证据归档。",
    toolIds: ["nmap", "naabu", "httpx", "nuclei", "ffuf", "sqlmap", "burpsuite"],
    stages: [
      stage("target", "目标与范围确认", "input", { requires: "target", inputKind: "target" }),
      stage("nmap", "端口与服务发现", "command", { tool: "nmap", args: (ctx) => ["-sV", "-Pn", "-T3", ctx.target] }),
      stage("httpx", "HTTP 指纹与存活探测", "command", { tool: "httpx", args: (ctx) => ["-u", ctx.target, "-json"], optional: true }),
      stage("nuclei", "漏洞模板验证", "command", { tool: "nuclei", args: (ctx) => ["-u", ctx.target, "-jsonl", "-silent"], optional: true }),
      stage("ffuf", "目录与参数发现", "command", { tool: "ffuf", args: (ctx) => ["-u", `${ctx.target.replace(/\/$/, "")}/FUZZ`, "-w", ctx.wordlist || "WORDLIST", "-of", "json"], optional: true }),
      stage("evidence", "汇总发现与验证证据", "evidence"),
    ],
  };
}

function customDefinition(input) {
  if (input.mode !== "custom" || !Array.isArray(input.steps) || !input.steps.length) return null;
  const allowedKinds = new Set(["input", "command", "ida-health", "ida-tools", "ida-call", "evidence"]);
  const stages = input.steps.slice(0, 32).map((raw, index) => {
    const item = raw && typeof raw === "object" ? raw : {};
    const kind = allowedKinds.has(item.kind) ? item.kind : "command";
    return stage(String(item.id || `step-${index + 1}`), String(item.label || item.id || `步骤 ${index + 1}`), kind, {
      tool: item.tool ? String(item.tool) : undefined,
      args: Array.isArray(item.args) ? item.args.map(String) : (item.args || undefined),
      optional: Boolean(item.optional),
      requires: item.requires ? String(item.requires) : undefined,
      inputKind: item.inputKind ? String(item.inputKind) : undefined,
    });
  });
  return {
    id: "custom",
    label: String(input.label || "自定义工作流"),
    description: String(input.description || "由 AI 生成并经过工具注册表校验的步骤。"),
    toolIds: [...new Set(stages.map((item) => item.tool).filter(Boolean))],
    stages,
  };
}

function definitionForInput(input) {
  const custom = customDefinition(input);
  if (custom) return custom;
  if (input.mode === "custom") {
    const fallback = defaultDefinition("infiltration");
    return { ...fallback, id: "custom", label: "自定义工作流", description: "未提供步骤时使用通用侦察链，可继续由 AI 追加步骤。" };
  }
  return defaultDefinition(input.mode);
}

function definitions() {
  return ["infiltration", "api", "reverse", "unlock", "mobile"].map((id) => defaultDefinition(id));
}

function resolveArgs(args, ctx) {
  const values = Array.isArray(args) ? args : [];
  return values.map((value) => String(value)
    .replaceAll("${target}", ctx.target || "TARGET")
    .replaceAll("${artifactDir}", ctx.artifactDir || "ARTIFACT_DIR")
    .replaceAll("${wordlist}", ctx.wordlist || "WORDLIST"));
}

function previewArgs(item, input) {
  try {
    const args = typeof item.args === "function" ? item.args(input) : (item.args || []);
    return args.map((arg) => String(arg).replace(/[A-Za-z]:\\[^ ]+|\/[^ ]+/g, "PATH"));
  } catch {
    return [];
  }
}

function planWorkflow(input = {}) {
  const normalized = normalizeInput(input);
  const requested = normalized.mode;
  const definition = definitionForInput(normalized);
  const stages = definition.stages.map((item, index) => ({
    id: item.id,
    index,
    label: item.label,
    kind: item.kind,
    tool: item.tool || null,
    optional: Boolean(item.optional),
    requires: item.requires || null,
    args: item.kind === "command" ? previewArgs(item, normalized) : undefined,
    status: "pending",
  }));
  return {
    id: definition.id,
    label: definition.label,
    description: definition.description,
    mode: normalized.mode,
    target: normalized.target,
    toolIds: definition.toolIds,
    requiresTarget: stages.some((item) => item.requires === "target"),
    ida: stages.some((item) => item.kind.startsWith("ida")),
    stages,
  };
}

function runCommand(command, args, options = {}) {
  const timeoutMs = Number(options.timeoutMs || 45000);
  const signal = options.signal;
  const onLine = options.onLine || (() => {});
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let timer = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener("abort", abort);
      resolve({ command, args, ...result, stdout: safeText(stdout), stderr: safeText(stderr), timedOut });
    };
    const child = spawn(command, args, {
      cwd: options.cwd || process.cwd(),
      env: { ...process.env, ...(options.env || {}) },
      windowsHide: true,
      shell: false,
    });
    const abort = () => {
      try { child.kill(); } catch { /* process already ended */ }
      finish({ code: null, ok: false, cancelled: true, error: "cancelled" });
    };
    if (signal?.aborted) return abort();
    signal?.addEventListener("abort", abort, { once: true });
    child.stdout?.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      stdout += text;
      text.split(/\r?\n/).filter((line) => line.trim()).forEach((line) => onLine({ type: "out", message: line.trim() }));
    });
    child.stderr?.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      stderr += text;
      text.split(/\r?\n/).filter((line) => line.trim()).forEach((line) => onLine({ type: "error", message: line.trim() }));
    });
    child.once("error", (error) => finish({ code: null, ok: false, error: error.message }));
    child.once("close", (code) => finish({ code: code ?? 1, ok: code === 0 }));
    timer = setTimeout(() => {
      timedOut = true;
      try { child.kill(); } catch { /* process already ended */ }
      finish({ code: null, ok: false, error: `timeout after ${timeoutMs}ms` });
    }, timeoutMs);
  });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

class WorkflowEngine {
  constructor(options = {}) {
    this.emit = options.emit || (() => {});
    this.tasks = new Map();
  }

  templates() {
    return definitions().map((item) => ({
      id: item.id,
      label: item.label,
      description: item.description,
      toolIds: item.toolIds,
      stages: item.stages.map((step) => ({ id: step.id, label: step.label, kind: step.kind, tool: step.tool || null, optional: Boolean(step.optional) })),
    }));
  }

  emitEvent(task, type, data = {}) {
    const event = {
      eventId: `${task.id}:${task.events.length + 1}`,
      taskId: task.id,
      type,
      at: new Date().toISOString(),
      phase: task.currentStage?.id || null,
      data,
    };
    task.events.push(event);
    if (task.events.length > MAX_EVENTS) task.events.shift();
    try { this.emit(event); } catch { /* renderer may have closed */ }
    return event;
  }

  summary(task) {
    return {
      id: task.id,
      taskId: task.id,
      status: task.status,
      workflowId: task.workflowId,
      label: task.label,
      target: task.input.target,
      createdAt: task.createdAt,
      startedAt: task.startedAt || null,
      finishedAt: task.finishedAt || null,
      currentStage: task.currentStage ? { ...task.currentStage } : null,
      nextStageIndex: task.nextStageIndex,
      stageCount: task.stages.length,
      stages: task.stages.map((item) => ({
        id: item.id,
        index: item.index,
        label: item.label,
        kind: item.kind,
        tool: item.tool || null,
        optional: Boolean(item.optional),
        status: item.status,
        startedAt: item.startedAt,
        finishedAt: item.finishedAt,
        result: item.result || null,
      })),
      completed: task.stages.filter((item) => item.status === "completed").length,
      failed: task.stages.filter((item) => item.status === "failed").length,
      needsInput: task.needsInput || null,
      error: task.error || null,
    };
  }

  create(input = {}) {
    const normalized = normalizeInput(input);
    const definition = definitionForInput(normalized);
    const task = {
      id: `wf-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      workflowId: definition.id,
      label: definition.label,
      input: normalized,
      status: "queued",
      createdAt: new Date().toISOString(),
      stages: definition.stages.map((item, index) => ({ ...item, index, status: "pending", startedAt: null, finishedAt: null, result: null })),
      nextStageIndex: 0,
      currentStage: null,
      events: [],
      results: [],
      controller: new AbortController(),
      pauseRequested: false,
      needsInput: null,
      error: null,
    };
    this.tasks.set(task.id, task);
    this.emitEvent(task, "task:created", { plan: planWorkflow(normalized) });
    return task;
  }

  start(input = {}) {
    const task = this.create(input);
    task.promise = this.run(task).catch((error) => {
      task.status = "failed";
      task.error = error.message;
      task.finishedAt = new Date().toISOString();
      this.emitEvent(task, "task:failed", { error: error.message });
      return this.summary(task);
    });
    return this.summary(task);
  }

  async run(task) {
    if (!["queued", "paused", "needs-input", "running"].includes(task.status)) return this.summary(task);
    task.status = "running";
    task.startedAt ||= new Date().toISOString();
    this.emitEvent(task, "task:started", { from: task.nextStageIndex });
    for (; task.nextStageIndex < task.stages.length; task.nextStageIndex += 1) {
      if (task.controller.signal.aborted) {
        task.status = "cancelled";
        task.finishedAt = new Date().toISOString();
        this.emitEvent(task, "task:cancelled");
        return this.summary(task);
      }
      if (task.pauseRequested) {
        task.status = "paused";
        this.emitEvent(task, "task:paused", { nextStageIndex: task.nextStageIndex });
        return this.summary(task);
      }
      const item = task.stages[task.nextStageIndex];
      task.currentStage = { id: item.id, index: item.index, label: item.label };
      item.status = "running";
      item.startedAt = new Date().toISOString();
      this.emitEvent(task, "phase:started", { stage: item.id, label: item.label, index: item.index });
      let result = await this.executeStage(task, item);
      if (task.controller.signal.aborted || result.cancelled) {
        item.result = result;
        item.status = "cancelled";
        item.finishedAt = new Date().toISOString();
        task.status = "cancelled";
        task.finishedAt = new Date().toISOString();
        this.emitEvent(task, "phase:cancelled", { stage: item.id, result });
        this.emitEvent(task, "task:cancelled", { stage: item.id });
        return this.summary(task);
      }
      if (!result.ok && item.optional && result.status !== "needs-input") {
        result = { ...result, skipped: true, optional: true, reason: result.reason || result.error || "optional stage unavailable" };
      }
      item.result = result;
      item.finishedAt = new Date().toISOString();
      item.status = result.status === "needs-input" ? "needs-input" : result.ok || result.skipped ? "completed" : "failed";
      task.results.push({ stage: item.id, result });
      this.emitEvent(task, result.ok || result.skipped ? "phase:completed" : result.status === "needs-input" ? "phase:input" : "phase:failed", {
        stage: item.id,
        result,
      });
      if (result.status === "needs-input") {
        task.status = "needs-input";
        task.needsInput = { field: item.requires || "target", stage: item.id, message: result.error };
        this.emitEvent(task, "task:needs-input", task.needsInput);
        return this.summary(task);
      }
      if (!result.ok && !result.skipped && !item.optional) {
        task.status = "failed";
        task.error = result.error || `阶段失败：${item.label}`;
        task.finishedAt = new Date().toISOString();
        this.emitEvent(task, "task:failed", { stage: item.id, error: task.error });
        return this.summary(task);
      }
      task.currentStage = null;
    }
    task.status = "completed";
    task.finishedAt = new Date().toISOString();
    this.emitEvent(task, "task:completed", { results: task.results.length });
    return this.summary(task);
  }

  async executeStage(task, item) {
    const ctx = {
      ...task.input,
      artifactDir: task.input.artifactDir || path.join(os.tmpdir(), "coldbrew-artifacts", task.id),
    };
    fs.mkdirSync(ctx.artifactDir, { recursive: true });
    if (item.kind === "input") {
      if (!ctx.target) return { ok: false, status: "needs-input", error: "请先填写目标或样本路径。" };
      if (item.inputKind === "file" && !fs.existsSync(ctx.target)) {
        return { ok: false, status: "needs-input", error: `样本路径不存在：${ctx.target}` };
      }
      return { ok: true, input: ctx.target };
    }
    if (item.kind === "ida-health") {
      const result = await probeIdaMcp({ home: ctx.home, url: ctx.idaUrl, timeoutMs: Math.min(ctx.timeoutMs, 8000) });
      task.idaSessionId = result.sessionId || task.idaSessionId || null;
      return result;
    }
    if (item.kind === "ida-tools") {
      const status = await probeIdaMcp({ home: ctx.home, url: ctx.idaUrl, timeoutMs: Math.min(ctx.timeoutMs, 8000), sessionId: task.idaSessionId });
      task.idaSessionId = status.sessionId || task.idaSessionId || null;
      return { ...status, ok: status.ok, tools: status.tools || [] };
    }
    if (item.kind === "ida-call") {
      const result = await callIdaMcp(item.tool, typeof item.args === "function" ? item.args(ctx) : item.args, {
        home: ctx.home,
        url: ctx.idaUrl,
        sessionId: task.idaSessionId,
        timeoutMs: Math.min(ctx.timeoutMs, 20000),
      });
      return result;
    }
    if (item.kind === "command") {
      const tool = toolById(item.tool);
      if (!tool) return { ok: false, error: `未注册工具：${item.tool}` };
      if (!commandExists(tool.command) && !(tool.aliases || []).some(commandExists)) {
        return { ok: false, skipped: true, reason: `${tool.label} 未安装`, tool: item.tool };
      }
      const command = commandExists(tool.command) ? tool.command : (tool.aliases || []).find(commandExists);
      const args = typeof item.args === "function" ? item.args(ctx) : resolveArgs(item.args, ctx);
      this.emitEvent(task, "tool:started", { tool: item.tool, command, args });
      const result = await runCommand(command, args, {
        cwd: ctx.cwd,
        timeoutMs: ctx.timeoutMs,
        signal: task.controller.signal,
        onLine: (line) => this.emitEvent(task, "tool:output", { tool: item.tool, ...line }),
      });
      return { ...result, tool: item.tool };
    }
    if (item.kind === "evidence") {
      const dir = ctx.artifactDir;
      fs.mkdirSync(dir, { recursive: true });
      const report = {
        taskId: task.id,
        workflowId: task.workflowId,
        target: ctx.target,
        generatedAt: new Date().toISOString(),
        stages: task.results,
      };
      const reportPath = path.join(dir, "workflow-report.json");
      fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
      return { ok: true, artifactDir: dir, reportPath };
    }
    return { ok: false, error: `未知阶段类型：${item.kind}` };
  }

  get(id) {
    const task = this.tasks.get(id);
    if (!task) return null;
    return { ...this.summary(task), events: clone(task.events), results: clone(task.results) };
  }

  list() {
    return [...this.tasks.values()].map((task) => this.summary(task));
  }

  pause(id) {
    const task = this.tasks.get(id);
    if (!task || !["queued", "running"].includes(task.status)) return task ? this.summary(task) : null;
    task.pauseRequested = true;
    if (task.status === "queued") task.status = "paused";
    this.emitEvent(task, "task:pause-requested");
    return this.summary(task);
  }

  resume(id, patch = {}) {
    const task = this.tasks.get(id);
    if (!task || !["paused", "needs-input"].includes(task.status)) return task ? this.summary(task) : null;
    task.input = normalizeInput({ ...task.input, ...(patch && typeof patch === "object" ? patch : {}) });
    task.pauseRequested = false;
    task.needsInput = null;
    task.status = "queued";
    this.emitEvent(task, "task:resumed", { nextStageIndex: task.nextStageIndex });
    task.promise = this.run(task).catch((error) => {
      task.status = "failed";
      task.error = error.message;
      task.finishedAt = new Date().toISOString();
      this.emitEvent(task, "task:failed", { error: error.message });
      return this.summary(task);
    });
    return this.summary(task);
  }

  cancel(id) {
    const task = this.tasks.get(id);
    if (!task || ["completed", "failed", "cancelled"].includes(task.status)) return task ? this.summary(task) : null;
    task.controller.abort();
    task.status = "cancelled";
    task.finishedAt = new Date().toISOString();
    this.emitEvent(task, "task:cancel-requested");
    return this.summary(task);
  }

  clear(id) {
    if (id) return this.tasks.delete(id);
    this.tasks.clear();
    return true;
  }
}

module.exports = {
  TOOL_REGISTRY,
  WorkflowEngine,
  defaultDefinition,
  definitions,
  healthCheckTools,
  planWorkflow,
  runCommand,
};
