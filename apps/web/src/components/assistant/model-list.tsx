"use client";

/* The model picker's list, "Model": one group per provider (model-picker-rules.ts
   `modelRows`), so a provider with many models never floods it. A group's heading shows the
   provider, where it runs and how many models it has, and opens or closes the group; only the
   provider that answers next starts open (else the first). An open group lists its models, ✓ on
   the one that answers next, in a box that scrolls on its own; with more than FILTER_AT models
   a filter field comes first. One click, Enter or Space uses a model and closes the picker (the
   ✓ one just closes it). The heading's bin asks inline ("Remove <provider>? Its models … go with
   it."), focused on No; Escape there keeps it. One tab stop for the headings, bins and models
   (use-roving.ts); the filter field is its own. + Model, at the bottom, opens Set the provider.
   The first time it opens the models are on their way ("Loading the models…"); once they are
   there, focus goes to the model that answers next (else the first heading, else + Model), or
   to + Model when it comes back from the form. */
import { useEffect, useRef, useState } from "react";
import { Check, ChevronRight, Loader, Plus, Trash2 } from "lucide-react";

import { IconButton } from "@/components/ui/icon-button";
import { type ModelRow, modelRows, removeQuestion, removeRequest } from "./model-picker-rules";
import { choiceKey, type Models } from "./use-models";
import { useRoving } from "./use-roving";

/** A provider with more models than this gets a filter field. */
export const FILTER_AT = 8;

const rowKey = (key: string) => `row:${key}`;
const headKey = (providerId: string) => `head:${providerId}`;
const binKey = (providerId: string) => `remove:${providerId}`;
const ADD = '[data-focus="add"]';

interface Group {
  providerId: string;
  provider: string;
  where: "local" | "remote";
  rows: ModelRow[];
}

/** The rows, provider by provider, in their order. */
export function groupsOf(rows: readonly ModelRow[]): Group[] {
  const groups: Group[] = [];
  for (const row of rows) {
    const last = groups.at(-1);
    if (last && last.providerId === row.providerId) last.rows.push(row);
    else groups.push({ providerId: row.providerId, provider: row.provider, where: row.where, rows: [row] });
  }
  return groups;
}

/** A group's models that match the filter (any part of the name, any case). */
export const matching = (rows: readonly ModelRow[], filter: string) => {
  const f = filter.trim().toLowerCase();
  return f ? rows.filter((r) => r.model.toLowerCase().includes(f)) : [...rows];
};

interface Props {
  models: Models;
  /** Back from Set the provider: focus goes to + Model. */
  fromForm: boolean;
  onChosen: () => void;
  onAdd: () => void;
}

export function ModelList({ models, fromForm, onChosen, onAdd }: Props) {
  const root = useRef<HTMLDivElement>(null);
  const focused = useRef(false);
  const focusNext = useRef<string | null>(null); // a roving key (or ADD) to focus once drawn
  const [confirm, setConfirm] = useState<string | null>(null); // the provider asked about
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<ReadonlySet<string> | null>(null); // null: not chosen yet
  const [filters, setFilters] = useState<Record<string, string>>({});
  const { view, status, error: loadError } = models.state;
  const rows = view ? modelRows(view) : [];
  const groups = groupsOf(rows);
  const checked = rows.find((r) => r.checked);
  // until the person opens or closes one: the provider that answers next, else the first
  const opened = open ?? new Set(checked ? [checked.providerId] : groups[0] ? [groups[0].providerId] : []);
  const shown = (g: Group) => (opened.has(g.providerId) ? matching(g.rows, filters[g.providerId] ?? "") : []);
  const roving = useRoving(
    groups.flatMap((g) => [headKey(g.providerId), ...(g.providerId !== confirm ? [binKey(g.providerId)] : []), ...shown(g).map((r) => rowKey(r.key))]),
    checked ? rowKey(checked.key) : groups[0] ? headKey(groups[0].providerId) : null,
  );
  const ready = view !== null || status === "error";

  useEffect(() => {
    if (focused.current || !ready) return;
    focused.current = true;
    const at = (selector: string) => root.current?.querySelector<HTMLElement>(selector);
    const el = (fromForm && at(ADD)) || at('[data-rove][tabindex="0"]') || at(ADD) || at("button");
    el?.focus({ preventScroll: true });
  }, [ready, fromForm]);

  // after a confirm closes, focus goes back to its bin (or, removed, to the next heading, else
  // + Model)
  useEffect(() => {
    const key = focusNext.current;
    if (!key) return;
    focusNext.current = null;
    const el = key === ADD ? root.current?.querySelector<HTMLElement>(ADD) : root.current?.querySelector<HTMLElement>(`[data-rove="${key}"]`);
    el?.focus({ preventScroll: true });
  });

  const toggle = (providerId: string) => {
    const next = new Set(opened);
    if (next.has(providerId)) next.delete(providerId);
    else next.add(providerId);
    setOpen(next);
  };
  const pick = async (row: ModelRow) => {
    if (models.pending) return;
    if (row.checked) return onChosen();
    setError(null);
    const problem = await models.choose(row.providerId, row.model);
    if (problem) setError(problem);
    else onChosen();
  };
  const keep = (providerId: string) => {
    setConfirm(null);
    setError(null);
    focusNext.current = binKey(providerId);
  };
  const remove = async (g: Group) => {
    const request = view && removeRequest(view, g);
    if (!request) return keep(g.providerId);
    setError(null);
    const problem = await models.remove(g.providerId, request);
    if (problem) return setError(problem);
    const after = groups.find((x) => x.providerId !== g.providerId);
    focusNext.current = after ? headKey(after.providerId) : ADD;
    setConfirm(null);
  };

  if (!view) {
    return (
      <div ref={root} className="ai-picker-body">
        {status === "error" ? (
          <div className="ai-menu-state" role="alert">
            <p>Couldn&apos;t load the models: {loadError}</p>
            <button type="button" onClick={models.load} className="ai-btn ai-btn-small ai-btn-outline mt-2">
              Try again
            </button>
          </div>
        ) : (
          <p className="ai-menu-state" role="status">
            <Loader className="mr-1.5 inline size-3.5 animate-spin" aria-hidden /> Loading the models…
          </p>
        )}
      </div>
    );
  }

  return (
    <div ref={root} className="ai-picker-form">
      <div className="ai-picker-body" aria-busy={models.pending !== null}>
        {status === "error" && (
          <p className="ai-error-text ai-picker-error" role="alert">
            {loadError}
          </p>
        )}
        {groups.length > 0 ? (
          <ul aria-label="Your models" onKeyDown={roving.onKeyDown} className="ai-picker-list">
            {groups.map((g) => {
              const isOpen = opened.has(g.providerId);
              const list = shown(g);
              const listId = `models-${g.providerId}`;
              const count = `${g.rows.length} model${g.rows.length === 1 ? "" : "s"}`;
              const q = removeQuestion(view, g);
              return (
                <li key={g.providerId}>
                  {g.providerId === confirm ? (
                    <div
                      role="group"
                      aria-label={q.title}
                      className="ai-menu-confirm"
                      onKeyDown={(e) => {
                        if (e.key !== "Escape") return;
                        e.preventDefault(); // keeps it; the picker stays open
                        e.stopPropagation();
                        keep(g.providerId);
                      }}
                    >
                      <p className="text-foreground">
                        Remove <span className="font-medium">{g.provider}</span>? {q.detail}
                      </p>
                      {error && (
                        <p className="ai-error-text mt-1" role="alert">
                          {error}
                        </p>
                      )}
                      {/* No on the right, under the bin: a double-click on the bin keeps it */}
                      <div className="mt-2 flex justify-end gap-1.5">
                        <button type="button" onClick={() => void remove(g)} disabled={models.pending !== null} className="ai-btn ai-btn-small ai-btn-danger-solid">
                          {models.pending === `remove:${g.providerId}` && <Loader className="size-3.5 animate-spin" aria-hidden />}
                          Remove
                        </button>
                        <button type="button" autoFocus onClick={() => keep(g.providerId)} className="ai-btn ai-btn-small ai-btn-outline">
                          No
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="ai-picker-row">
                      <button
                        type="button"
                        aria-expanded={isOpen}
                        aria-controls={listId}
                        onClick={() => toggle(g.providerId)}
                        title={isOpen ? `Hide ${g.provider}'s models` : `Show ${g.provider}'s models`}
                        className="ai-picker-head"
                        {...roving.item(headKey(g.providerId))}
                      >
                        <span className="ai-picker-chevron" aria-hidden>
                          <ChevronRight className={`size-3.5 transition-transform ${isOpen ? "rotate-90" : ""}`} strokeWidth={2.5} />
                        </span>
                        <span className="ai-picker-text">
                          <span className="ai-picker-head-name">{g.provider}</span>
                          <span className="ai-picker-meta">
                            {g.where} · {count}
                            {!isOpen && g.rows.some((r) => r.checked) ? " · in use" : ""}
                          </span>
                        </span>
                      </button>
                      <IconButton
                        label={`Remove ${g.provider}`}
                        onClick={() => {
                          setError(null);
                          setConfirm(g.providerId);
                        }}
                        className="ai-picker-remove size-7 hover:text-danger [&_svg]:size-3.5"
                        {...roving.item(binKey(g.providerId))}
                      >
                        <Trash2 aria-hidden />
                      </IconButton>
                    </div>
                  )}
                  {isOpen && (
                    <div id={listId} className="pl-5">
                      {g.rows.length > FILTER_AT && (
                        <input
                          type="search"
                          value={filters[g.providerId] ?? ""}
                          onChange={(e) => setFilters((f) => ({ ...f, [g.providerId]: e.target.value }))}
                          placeholder={`Filter ${count}…`}
                          aria-label={`Filter ${g.provider}'s models`}
                          spellCheck={false}
                          autoComplete="off"
                          className="ai-input ai-mono my-1 h-7 text-xs"
                        />
                      )}
                      <ul aria-label={`${g.provider}'s models`} className="max-h-56 overflow-y-auto">
                        {list.map((row) => (
                          <li key={row.key} className="ai-picker-row">
                            <button
                              type="button"
                              aria-current={row.checked ? "true" : undefined}
                              title={row.checked ? "Answers your next question" : `Use ${row.model}`}
                              onClick={() => void pick(row)}
                              className="ai-picker-model"
                              {...roving.item(rowKey(row.key))}
                            >
                              <span className="ai-picker-check" aria-hidden>
                                {models.pending === choiceKey(row.providerId, row.model) ? <Loader className="size-3 animate-spin" /> : row.checked ? <Check className="size-3" strokeWidth={3} /> : null}
                              </span>
                              <span className="ai-picker-text">
                                <span className="ai-picker-model-name">{row.model}</span>
                              </span>
                            </button>
                          </li>
                        ))}
                        {list.length === 0 && <li className="ai-picker-empty px-2 py-1">No model matches.</li>}
                      </ul>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="ai-picker-empty">No model yet.</p>
        )}
        {error && confirm === null && (
          <p className="ai-error-text ai-picker-error" role="alert">
            {error}
          </p>
        )}
      </div>
      <div className="ai-picker-foot">
        <button type="button" data-focus="add" aria-label="+ Model" onClick={onAdd} className="ai-btn ai-picker-add">
          <Plus className="size-3.5" aria-hidden />
          Add a provider or model
        </button>
      </div>
    </div>
  );
}
