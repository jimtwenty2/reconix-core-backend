/* The model picker on the Core API's /llm-providers: the API keeps the providers (keys
   Fernet-encrypted, shown as their last 4 only) and calls the active one itself. The picker's
   providers are the TUI's /provider list, one per API provider_type (presets.ts). An API row
   holds one model, as the TUI's providers do (a cloud one offers its built-in models): choosing
   another model of a saved provider changes that row's model. A model off this computer
   becomes active only after its `configuration` approval is approved: the picker says so and
   never approves it itself. Server only. */
import "server-only";

import { type Preset, presetOf } from "../assistant/models/presets";
import type { AddProvider, Probe, SetActive, UpdateProvider } from "../assistant/models/requests";
import { PROVIDER_ID } from "../assistant/models/schema";
import type { FetchResult, ModelsView, ProbeResult, ProviderView } from "../assistant/models/view";
import { coreJson, CoreError } from "./core";
import { asMain } from "./sessions";

/** GET /llm-providers row (LlmProviderOut). */
export type CoreProvider = {
  llm_provider_id: string;
  provider_type: string;
  display_name: string;
  base_url: string | null;
  api_key_last4: string | null;
  model_name: string;
  is_active: boolean;
  is_local: boolean;
};
type Activation = { llm_provider: CoreProvider; approval: { approval_id: string } | null };
type TestOut = { ok: boolean; model_name: string; latency_ms: number; code: string | null; message: string | null };

const TYPE_OF: Record<Preset["id"], string> = {
  reconix: "RECONIX",
  openai: "OPENAI",
  anthropic: "ANTHROPIC",
  deepseek: "DEEPSEEK",
  ollama: "OLLAMA",
  custom: "OPENAI_API_COMPATIBLE",
};
const PRESET_OF: Record<string, Preset["id"]> = Object.fromEntries(Object.entries(TYPE_OF).map(([id, type]) => [type, id as Preset["id"]]));

export const NEEDS_APPROVAL = "This model runs off this computer, so the Core API needs a person's approval before it uses it. Approve the waiting configuration approval (in the TUI), then choose it again.";

/** The API's provider_type for a picker preset. */
export const providerTypeOf = (preset: string): string => TYPE_OF[presetOf(preset).id];

/** The picker preset for an API row, by its provider_type. */
export const presetFor = (row: Pick<CoreProvider, "provider_type">): Preset => presetOf(PRESET_OF[row.provider_type] ?? "custom");

/** The base_url the API takes: none for Reconix and the cloud services (their own address)
    and for Ollama at its default (the API's RECONIX_OLLAMA_URL); else the address given. */
function baseUrlFor(preset: Preset, baseUrl: string): string | null {
  if (preset.kind === "reconix" || preset.kind === "cloud") return null;
  if (preset.kind === "local" && baseUrl.trim() === preset.baseUrl) return null;
  return baseUrl.trim() || null;
}

/** The rows of one provider: the same type at the same address. Each API row holds one
    model (its own approval and history), so a provider with many models is many rows. */
const groupKey = (row: Pick<CoreProvider, "provider_type" | "base_url">) => `${row.provider_type}|${row.base_url ?? ""}`;

/** The API's rows as providers, each named by its first row (its id is the provider's). */
export function groupRows(rows: CoreProvider[]): CoreProvider[][] {
  const groups = new Map<string, CoreProvider[]>();
  for (const row of rows.filter((r) => PROVIDER_ID.test(r.llm_provider_id))) {
    const key = groupKey(row);
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return [...groups.values()].slice(0, 20);
}

/** A provider as the picker shows it: its saved models first, then the rest it has. */
export function toProviderView(group: CoreProvider[], found: readonly string[] = []): ProviderView {
  const first = group[0];
  const preset = presetFor(first);
  return {
    id: first.llm_provider_id,
    name: first.display_name.slice(0, 60),
    preset: preset.id,
    baseUrl: (first.base_url ?? preset.baseUrl).slice(0, 2_048),
    models: [...new Set([...group.map((r) => r.model_name), ...found])].slice(0, 50),
    keySaved: group.some((r) => r.api_key_last4 !== null),
    local: first.is_local,
  };
}

/** The picker's whole view from the API's rows (`found`: every provider's other models). */
export function toModelsView(rows: CoreProvider[], found: ReadonlyMap<string, readonly string[]> = new Map()): ModelsView {
  const groups = groupRows(rows);
  const activeGroup = groups.find((g) => g.some((r) => r.is_active));
  const active = activeGroup?.find((r) => r.is_active) ?? null;
  return {
    providers: groups.map((g) => toProviderView(g, found.get(g[0].llm_provider_id))),
    active: activeGroup && active ? { providerId: activeGroup[0].llm_provider_id, model: active.model_name } : null,
    summary: active
      ? { configured: true, name: active.model_name, provider: active.display_name.slice(0, 60), local: active.is_local, reason: "" }
      : { configured: false, name: "", provider: "", local: false, reason: "Choose a model in the model picker: the Core API answers with it." },
  };
}

/** The names a model list holds that can chat: valid names, embedding models left out
    (LM Studio and Ollama list theirs too, e.g. text-embedding-nomic-embed-text-v1.5). */
export const chatModels = (names: readonly string[]): string[] => names.filter((m) => /^[\w.:/@+-]{1,128}$/.test(m) && !/embed/i.test(m)).slice(0, 200);

const rowsOf = () => asMain((token) => coreJson<CoreProvider[]>("/llm-providers", { token }));

/** The rows of the provider whose id (its first row's) is `id`; none when it is gone. */
async function groupOf(id: string): Promise<CoreProvider[]> {
  const group = groupRows(await rowsOf()).find((g) => g[0].llm_provider_id === id || g.some((r) => r.llm_provider_id === id));
  if (!group) throw new CoreError(404, "LLM_PROVIDER_NOT_FOUND", "That provider is not saved any more.");
  return group;
}

/** Every model a provider has, as the TUI's providers hold many: a cloud service's built-in
    ones, what an Ollama or a custom server on this computer lists (asked through the Core
    API), or only the saved ones (Reconix, a server off this computer, or one that is down). */
async function modelsOf(row: CoreProvider): Promise<readonly string[]> {
  const preset = presetFor(row);
  if (preset.kind === "cloud") return preset.models;
  if ((preset.kind !== "local" && preset.kind !== "custom") || !row.is_local) return [];
  try {
    const out = await asMain((token) => coreJson<{ models: string[] }>(`/llm-providers/${row.llm_provider_id}/models`, { token }));
    return chatModels(out.models);
  } catch {
    return []; // the server is down: its saved models still show
  }
}

/** The picker's view, with every model of every provider. */
export async function modelsView(): Promise<ModelsView> {
  const rows = await rowsOf();
  const groups = groupRows(rows);
  const found = new Map(await Promise.all(groups.map(async (g) => [g[0].llm_provider_id, await modelsOf(g[0])] as const)));
  return toModelsView(rows, found);
}

/** The active model in words, for the page's first render (no model lists asked). */
export const activeModelSummary = async (): Promise<ModelsView["summary"]> => toModelsView(await rowsOf()).summary;

async function activate(id: string): Promise<void> {
  const activation = await asMain((token) => coreJson<Activation>(`/llm-providers/${id}/activate`, { method: "POST", token }));
  if (activation.approval) throw new CoreError(409, "NEEDS_APPROVAL", NEEDS_APPROVAL);
}

/** One more model of a saved provider: a row of its own, with the provider's key copied by
    the Core API (copy_key_from: never sent again, only at the same address). */
async function addModelTo(first: CoreProvider, model: string): Promise<CoreProvider> {
  return asMain((token) =>
    coreJson<CoreProvider>("/llm-providers", {
      method: "POST",
      token,
      body: {
        provider_type: first.provider_type,
        display_name: first.display_name,
        model_name: model,
        base_url: first.base_url,
        ...(first.api_key_last4 !== null ? { copy_key_from: first.llm_provider_id } : {}),
      },
    }),
  );
}

/** Adds a provider with its first model; `activate` makes it the active one. Reconix is
    built into the Core API (its row comes with it): choosing it only activates it. */
export async function addProvider(body: AddProvider): Promise<ModelsView> {
  const preset = presetOf(body.preset);
  if (preset.kind === "reconix") {
    const reconix = (await rowsOf()).find((r) => r.provider_type === "RECONIX");
    if (!reconix) throw new CoreError(404, "LLM_PROVIDER_NOT_FOUND", "The Core API has no Reconix model.");
    if (body.activate) await activate(reconix.llm_provider_id);
    return modelsView();
  }
  const row = await asMain((token) =>
    coreJson<CoreProvider>("/llm-providers", {
      method: "POST",
      token,
      body: {
        provider_type: providerTypeOf(preset.id),
        display_name: (body.name.trim() || preset.label).slice(0, 100),
        model_name: body.models[body.models.length - 1],
        base_url: baseUrlFor(preset, body.baseUrl),
        ...(body.apiKey ? { api_key: body.apiKey } : {}),
      },
    }),
  );
  if (body.activate) await activate(row.llm_provider_id);
  return modelsView();
}

/** Runs `call` on every row of a provider; the first refusal is thrown once all were tried
    (the API keeps the active row and rows agent runs used as they are). */
async function eachRow(group: CoreProvider[], call: (row: CoreProvider) => Promise<unknown>): Promise<void> {
  let refused: unknown = null;
  for (const row of group) {
    try {
      await call(row);
    } catch (error) {
      refused ??= error;
    }
  }
  if (refused) throw refused;
}

/** Changes a provider: its name, address or key on every row it has. A model list adds the
    models it does not have yet (each a row of its own). The type never changes. */
export async function updateProvider(id: string, body: UpdateProvider): Promise<ModelsView> {
  const group = await groupOf(id);
  const first = group[0];
  if (body.preset && providerTypeOf(body.preset) !== first.provider_type) throw new CoreError(400, "TYPE_FIXED", "A provider's kind can't change: add it again as the other one.");
  const patch: Record<string, unknown> = {};
  if (body.name !== undefined) patch.display_name = body.name.trim().slice(0, 100);
  if (body.baseUrl !== undefined) patch.base_url = baseUrlFor(presetFor(first), body.baseUrl);
  if (body.apiKey) patch.api_key = body.apiKey;
  if (body.removeKey) patch.api_key = null;
  if (Object.keys(patch).length) await eachRow(group, (row) => asMain((token) => coreJson(`/llm-providers/${row.llm_provider_id}`, { method: "PATCH", token, body: patch })));
  const saved = new Set(group.map((r) => r.model_name));
  for (const model of body.models ?? []) if (!saved.has(model)) await addModelTo(first, model);
  return modelsView();
}

/** Removes a provider: every row it has. */
export async function removeProvider(id: string): Promise<ModelsView> {
  const group = await groupOf(id);
  await eachRow(group, (row) => asMain((token) => coreJson(`/llm-providers/${row.llm_provider_id}`, { method: "DELETE", token })));
  return modelsView();
}

/** Makes one of a provider's models the active one: its row, added first when the model is
    one the provider has but no row holds yet. */
export async function setActive({ providerId, model }: SetActive): Promise<ModelsView> {
  const group = await groupOf(providerId);
  const row = group.find((r) => r.model_name === model) ?? (await addModelTo(group[0], model));
  await activate(row.llm_provider_id);
  return modelsView();
}

const UNSAVED = "Reconix tests a model once it is added: the Core API checks it then.";

/** "Test connection": only a saved provider is tested (the API sends one fixed prompt). */
export async function testModel(probe: Probe): Promise<ProbeResult> {
  if (!("providerId" in probe)) return { ok: true, detail: UNSAVED };
  const out = await asMain((token) => coreJson<TestOut>(`/llm-providers/${probe.providerId}/test`, { method: "POST", token }));
  return out.ok ? { ok: true, detail: `It answered in ${out.latency_ms} ms.` } : { ok: false, detail: (out.message ?? out.code ?? "It did not answer.").slice(0, 400) };
}

/** "Fetch models": a saved provider's list from the API; unsaved values have none yet. */
export async function fetchModels(probe: Probe): Promise<FetchResult> {
  if (!("providerId" in probe)) return { listed: false, detail: "Type the model's name: the Core API lists models once the provider is added." };
  const out = await asMain((token) => coreJson<{ models: string[] }>(`/llm-providers/${probe.providerId}/models`, { token }));
  const models = out.models.filter((m) => /^[\w.:/@+-]{1,128}$/.test(m)).slice(0, 200);
  return models.length ? { models } : { listed: false, detail: "The model's server listed no models." };
}

/** What "Test connection" answers: the picker's view, the provider tested (saved now), the
    models to choose from, the result in words, and whether this call saved the provider. */
export type Connected = { view: ModelsView; providerId: string; models: string[]; detail: string; created: boolean };

const PLACEHOLDER_MODEL = "unset"; // a new Ollama or custom row's model until its list is read

/** "Test connection", as the TUI's /provider does it: save the provider first (not active),
    then check it: a cloud service or Reconix with the API's test (one fixed prompt), an
    Ollama or a custom server by listing its models (which needs it to answer). The models
    come back to choose from. A provider this call saved and that fails is removed again. */
export async function connect(body: { preset: string; baseUrl: string; apiKey?: string; providerId?: string; name: string }): Promise<Connected> {
  const preset = presetOf(body.preset);
  let row = body.providerId ? (await rowsOf()).find((r) => r.llm_provider_id === body.providerId) : undefined;
  if (body.providerId && !row) throw new CoreError(404, "LLM_PROVIDER_NOT_FOUND", "That provider is not saved any more.");
  if (!row && preset.kind === "reconix") row = (await rowsOf()).find((r) => r.provider_type === "RECONIX");
  let created = false;
  if (!row) {
    row = await asMain((token) =>
      coreJson<CoreProvider>("/llm-providers", {
        method: "POST",
        token,
        body: {
          provider_type: providerTypeOf(preset.id),
          display_name: (body.name.trim() || preset.label).slice(0, 100),
          model_name: preset.models[0] ?? PLACEHOLDER_MODEL,
          base_url: baseUrlFor(preset, body.baseUrl),
          ...(body.apiKey ? { api_key: body.apiKey } : {}),
        },
      }),
    );
    created = true;
  }
  const id = row.llm_provider_id;
  try {
    let models: string[];
    let detail: string;
    if (preset.kind === "cloud" || preset.kind === "reconix") {
      const out = await asMain((token) => coreJson<TestOut>(`/llm-providers/${id}/test`, { method: "POST", token }));
      if (!out.ok) throw new CoreError(422, out.code ?? "MODEL_UNAVAILABLE", (out.message ?? "It did not answer.").slice(0, 400));
      models = preset.kind === "cloud" ? [...new Set([row.model_name, ...preset.models])] : [row.model_name];
      detail = `Connected: ${row.model_name} answered in ${out.latency_ms} ms.`;
    } else {
      const out = await asMain((token) => coreJson<{ models: string[] }>(`/llm-providers/${id}/models`, { token }));
      models = chatModels(out.models);
      if (!models.length) throw new CoreError(422, "NO_MODELS", "It answered, but lists no models: load or pull one first.");
      if (row.model_name === PLACEHOLDER_MODEL) await asMain((token) => coreJson(`/llm-providers/${id}`, { method: "PATCH", token, body: { model_name: models[0] } }));
      detail = `Connected: ${models.length} model${models.length === 1 ? "" : "s"} found.`;
    }
    return { view: await modelsView(), providerId: id, models, detail, created };
  } catch (error) {
    if (created) await asMain((token) => coreJson(`/llm-providers/${id}`, { method: "DELETE", token })).catch(() => undefined);
    throw error;
  }
}
