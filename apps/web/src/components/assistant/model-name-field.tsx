"use client";

/* The Model field of the model picker's "Set the provider": a native select of the provider's
   models, found by the form's Test connection (a cloud service's built-in ones once its key
   works, Reconix's, or what an Ollama or a custom server on this computer lists). No name is
   typed. The form shows it only once there are models to choose from. */

import { type ModelList, NO_MODEL_YET } from "./model-picker-rules";
import { NOT_A_LOGIN } from "./model-key-field";
import { MODEL_NAME_MAX } from "./model-name-rules";

/** What the form knows of the provider's models. `sig`: the values the list was fetched for. */
export type ListState = { status: "none" } | { status: "loading" } | ({ status: "ready"; sig: string } & ModelList);

interface Props {
  id: string;
  list: ListState;
  choice: string;
  onChoice: (value: string) => void;
}

export function ModelNameField({ id, list, choice, onChoice }: Props) {
  const select = `${id}-select`;
  const note = `${id}-note`;
  const fetching = list.status === "loading";
  const listed = list.status === "ready" ? list.models : [];
  const manual = list.status === "ready" && listed.length === 0;
  const shownNote = list.status === "ready" ? list.note : null;

  return (
    <div className="ai-field">
      <label htmlFor={select} className="ai-label">
        Model
      </label>
      <div className="ai-picker-inline">
        {manual ? (
          <input
            id={select}
            type="text"
            value={choice}
            onChange={(e) => onChoice(e.target.value)}
            maxLength={Math.min(MODEL_NAME_MAX, 100)}
            spellCheck={false}
            {...NOT_A_LOGIN}
            placeholder="e.g. llama-3.3-70b-versatile"
            aria-describedby={shownNote ? note : undefined}
            className="ai-input ai-mono"
          />
        ) : (
          <select
            id={select}
            value={choice}
            onChange={(e) => onChoice(e.target.value)}
            aria-describedby={shownNote ? note : undefined}
            aria-busy={fetching || undefined}
            className="ai-select ai-mono"
          >
            {list.status !== "ready" && (
              <option value={NO_MODEL_YET} disabled>
                {fetching ? "Listing the models…" : "Test connection to list the models"}
              </option>
            )}
            {listed.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        )}
      </div>
      {shownNote && (
        <p id={note} className="ai-hint">
          {shownNote}
        </p>
      )}
    </div>
  );
}
