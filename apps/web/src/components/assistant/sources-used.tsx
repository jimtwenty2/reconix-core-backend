/* The muted line under an answer listing the knowledge it cites ("Sources: [CVE-2021-44228]
   Apache Log4j2 …"): the server's `sources` frame, kept with the streaming reply. Ref ids and
   titles are plain React text; only a url that starts with http(s) becomes a link, so no other
   scheme can ever be clicked. */
import { ScrollText } from "lucide-react";

import type { SourceRef } from "@/lib/assistant/protocol";

export function SourcesUsed({ sources }: { sources?: SourceRef[] }) {
  if (!sources?.length) return null;
  return (
    <p className="ai-knowledge">
      <ScrollText className="size-3.5 shrink-0" aria-hidden />
      <span className="ai-sources">
        <span>Sources:</span>
        {sources.map((s, i) => (
          <span key={i}>
            {s.title ? `[${s.ref_id}] ` : ""}
            {/^https?:\/\//.test(s.url) ? (
              <a href={s.url} target="_blank" rel="noreferrer noopener">
                {s.title || s.ref_id}
              </a>
            ) : (
              s.title || s.ref_id
            )}
          </span>
        ))}
      </span>
    </p>
  );
}
