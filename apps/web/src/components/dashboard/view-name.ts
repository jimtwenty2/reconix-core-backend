/* Pure view-name parsing shared by server components (app/page.tsx) and client URL helpers
   (view-url.ts). Kept free of React hooks and browser APIs so server components can import it. */

// (no "audit", "scope", "log" or "terminal": the Audit log, Scope, Run log and Terminal views were removed; old
// ?view=audit, ?view=scope, ?view=log and ?view=terminal links open the Overview). "knowledge" is the Security knowledge page, opened from
// the AI Assistant's header (no sidebar item).
export const VIEWS = ["overview", "assessments", "findings", "reports", "assistant", "knowledge"] as const;
export type View = (typeof VIEWS)[number];

/** Spellings a person may type for a view: they open that view, not the Overview. */
const VIEW_ALIASES: Record<string, View> = {
  report: "reports",
  finding: "findings",
  assessment: "assessments",
};

export const parseView = (value: string | null | undefined): View => {
  const name = (value ?? "").trim().toLowerCase();
  if ((VIEWS as readonly string[]).includes(name)) return name as View;
  return VIEW_ALIASES[name] ?? "overview";
};
