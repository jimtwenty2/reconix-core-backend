"use client";

/* One Core API assessment's reports, newest first, then the combined ones covering it: each
   version's build status, its review sign-off and its files. A file is fetched through the
   dashboard (/api/core-reports/<id>/download, which holds the API session) and saved only when
   it arrived whole; a refusal is said as the API said it, never saved. A version that isn't
   READY and signed off says why instead of offering its files. Read-only: making a report and
   asking for its review stay in the TUI. */
import { Download } from "lucide-react";
import { useState } from "react";

import { DashCard } from "@/components/dashboard/dash-card";
import { fetchWithin, fileNameOf, saveBlob, useOneRequest } from "@/components/dashboard/use-file-download";
import { Button } from "@/components/ui/button";
import { EmptyNote } from "@/components/ui/empty-note";
import { StatusBadge } from "@/components/ui/status-badge";
import type { ReportRow } from "@/lib/api/adapt";
import { DOCS } from "@/lib/docs-nav";

const TIMEOUT_MS = 60_000;
type FileState = { kind: "idle" } | { kind: "busy" | "done" | "failed"; text: string };

export function ApiReportList({ reports }: { reports: ReportRow[] }) {
  const { begin } = useOneRequest();
  const [state, setState] = useState<FileState>({ kind: "idle" });

  const download = async (r: ReportRow, format: string) => {
    const ticket = begin();
    const what = `version ${r.version} as ${format}`;
    setState({ kind: "busy", text: `Downloading ${what} from the Core API…` });
    try {
      const res = await fetchWithin(`/api/core-reports/${encodeURIComponent(r.id)}/download?format=${format}`, TIMEOUT_MS, ticket.signal, "*/*");
      if (!ticket.mine()) return;
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { code?: string; message?: string } | null;
        const msg = body?.message ? (body.code ? `${body.message} (${body.code})` : body.message) : `The dashboard answered ${res.status}.`;
        if (ticket.mine()) setState({ kind: "failed", text: msg });
        return;
      }
      const blob = await res.blob();
      if (!ticket.mine()) return;
      const name = fileNameOf(res.headers.get("content-disposition")) ?? `report-v${r.version}.${format.toLowerCase()}`;
      saveBlob(blob, name);
      setState({ kind: "done", text: `Saved ${name}.` });
    } catch (error) {
      if (!ticket.mine()) return;
      const timedOut = error instanceof DOMException && error.name === "TimeoutError";
      setState({ kind: "failed", text: timedOut ? "The download took too long." : "The dashboard could not be reached." });
    } finally {
      ticket.done();
    }
  };

  return (
    <DashCard id="report-versions" title="Reports" docsHref={DOCS.panelReports} meta={`${reports.length} ${reports.length === 1 ? "version" : "versions"}`} className="is-wide">
      {reports.length === 0 ? (
        <EmptyNote>No report for this assessment yet. Make one in the TUI; it shows here once the Core API holds it.</EmptyNote>
      ) : (
        <ul className="flex flex-col divide-y divide-border" aria-label="Report versions">
          {reports.map((r) => (
            <li key={r.id} className="dash-report-version flex flex-col gap-1.5 py-2.5">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className="font-mono text-[13px] text-foreground">v{r.version}</span>
                <StatusBadge meaning={r.status} />
                <StatusBadge meaning={r.review} />
                {r.covers > 1 && <span className="text-xs text-muted-foreground">Combined · {r.covers} assessments</span>}
                <span className="ml-auto font-mono text-[11px] text-muted-foreground">{r.made}</span>
              </div>
              {r.summary && <p className="line-clamp-3 text-xs text-muted-foreground">{r.summary}</p>}
              {r.locked ? (
                <p className="text-xs text-muted-foreground">{r.locked}</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {r.formats.map((format) => (
                    <Button key={format} type="button" variant="outline" size="sm" onClick={() => void download(r, format)} aria-label={`Download version ${r.version} as ${format}`}>
                      <Download aria-hidden className="size-3.5" />
                      {format}
                    </Button>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {state.kind !== "idle" && (
        <p role={state.kind === "failed" ? "alert" : "status"} className="dash-report-file mt-2 text-xs text-muted-foreground">
          {state.text}
        </p>
      )}
    </DashCard>
  );
}
