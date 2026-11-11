/* How a TUI provider looks in the model picker: its avatar (its initial on a steady colour per
   provider) and its kind in one word (Built in, Cloud, Local, Any server). The list, its
   provider page and the Set the provider tiles all use these, so a provider looks the same
   everywhere. */
import { type Preset, presetOf } from "@/lib/assistant/models/presets";

/** A TUI provider's short name ("Reconix (default)" is "Reconix"). */
export const shortLabel = (preset: Preset) => preset.label.replace(/\s*\(.*\)$/, "").replace(/ OpenAI-compatible$/, "");

/** Its kind in one word. */
export const kindLabel = (preset: Preset) => ({ reconix: "Built in", cloud: "Cloud", local: "Local", custom: "Any server" })[preset.kind];

/** A steady hue per provider. */
const HUES: Record<Preset["id"], number> = { reconix: 195, openai: 160, anthropic: 30, deepseek: 250, ollama: 300, custom: 90 };

export function ProviderAvatar({ preset, size = 28 }: { preset: Preset["id"]; size?: number }) {
  const p = presetOf(preset);
  return (
    <span className="ai-picker-avatar" style={{ "--hue": HUES[p.id], width: size, height: size, fontSize: Math.round(size * 0.42) } as React.CSSProperties} aria-hidden>
      {shortLabel(p).charAt(0)}
    </span>
  );
}
