"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RelayAdapter, resolveProviderId } = require("../src/lib/relay-adapter");
const core = require("../src/shared/workbench-core");

test("Codex 席位显示全模型支持", () => {
  assert.equal(core.SEATS.find((seat) => seat.id === "codex").tag, "GPT-6 Astra全模型支持");
});

test("GPT-6.1 Sol 是中转预览的主模型", async () => {
  const adapter = new RelayAdapter();
  const models = await adapter.models();
  assert.deepEqual(models.data.map((item) => item.id), ["gpt-6-astra", "gpt-6.1-sol"]);
  assert.equal(adapter.getProviderPreset("gpt-6.1-sol").label, "GPT-6.1 Sol");
});

test("旧 Sol 配置别名归一化到 GPT-6.1 Sol", async () => {
  assert.equal(resolveProviderId("gpt-5.6-sol"), "gpt-6.1-sol");
  assert.equal(resolveProviderId("gpt6.1sol"), "gpt-6.1-sol");
  const result = await new RelayAdapter().preflight({ providerId: "gpt-5.6-sol" });
  assert.equal(result.ok, true);
  assert.equal(result.provider.model, "gpt-6.1-sol");
});
