/* The Local Assessment Viewer at `/`, rendered per request from the local Core API; nothing
   comes from saved files. The Overview, the top bar and the Run log read every assessment as a
   run (lib/api/library.ts loadApiLibrary): with no `?uid=` the Overview totals every one
   (derive-overall.ts); `?uid=` (the switcher's) opens one (derive.ts). The Assessments,
   Findings and Report views read it too (components/dashboard/api-assessments.tsx,
   api-findings.tsx, api-reports.tsx), the last two for the assessment `?assessment=<uuid>`
   names. `?view=` is the open view, read by the client Viewer. There are no roles: signed in
   (src/proxy.ts and requireSignedIn check), every view renders. When the Core API can't be
   read, each view says what it said. The AI Assistant learns what it is about, which model
   answers (lib/assistant/models/resolve.ts) and what to suggest, from the same assessments
   (lib/assistant/prompts.ts). */
import { Suspense } from "react";

import type { AssistantInfo } from "@/components/assistant/types";
import { deriveDashboard } from "@/components/dashboard/derive";
import { deriveOverall } from "@/components/dashboard/derive-overall";
import { runLogData } from "@/components/dashboard/derive-run-log";
import { ApiAssessments, AssessmentsLoading } from "@/components/dashboard/api-assessments";
import { ApiFindings, FindingsLoading } from "@/components/dashboard/api-findings";
import { ApiReports, ReportsLoading } from "@/components/dashboard/api-reports";
import { CoreEmptyView } from "@/components/dashboard/core-empty-view";
import { OverviewView } from "@/components/dashboard/overview-view";
import { RunLogView } from "@/components/dashboard/run-log-view";
import { TopBar } from "@/components/dashboard/top-bar";
import { Viewer } from "@/components/dashboard/viewer";
import { KnowledgeView } from "@/components/knowledge/knowledge-view";
import { CoreError } from "@/lib/api/core";
import { isAssessmentId } from "@/lib/api/findings";
import { loadApiLibrary } from "@/lib/api/library";
import { activeModelSummary } from "@/lib/api/models";
import { runRef, scopedViews, scopeOf } from "@/lib/assistant/insights";
import { welcomePrompts } from "@/lib/assistant/prompts";
import { requireSignedIn } from "@/lib/auth/guard";
import { assessmentView, libraryItem } from "@/lib/data/adapt";
import { clock } from "@/lib/data/format";
import { type Library, UID } from "@/lib/data/store";

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

/** Every Core API assessment as a run, or what the API said when it can't be read. */
async function readLibrary(): Promise<{ library: Library; error: string | null }> {
  try {
    return { library: await loadApiLibrary(), error: null };
  } catch (e) {
    const error = e instanceof CoreError ? `${e.message} (${e.code})` : "The Core API's assessments could not be read.";
    return { library: { dir: "Core API", readAt: Date.now(), assessments: [], problems: [] }, error };
  }
}

export default async function Home({ searchParams }: Props) {
  await requireSignedIn(); // a second lock behind src/proxy.ts
  // its summary only (no API key comes back); without the Core API the assistant says so
  const modelSummary = activeModelSummary().catch((error: unknown) => ({
    configured: false,
    name: "",
    provider: "",
    local: false,
    reason: error instanceof Error ? error.message.slice(0, 600) : "The Core API is not running.",
  }));
  const [params, { library, error }, model] = await Promise.all([searchParams, readLibrary(), modelSummary]);
  const wanted = typeof params.uid === "string" && UID.test(params.uid) ? params.uid : null;
  const views = library.assessments.map(assessmentView);
  // Findings and reports name the Core API's own id (`?assessment=<uuid>`), not `?uid=`.
  const apiAssessment = isAssessmentId(params.assessment) ? params.assessment : null;
  const chosen = views.find((v) => v.uid === wanted) ?? null;
  const dash = chosen ? deriveDashboard(chosen) : null;
  const overall = !chosen && views.length ? deriveOverall(views) : null;
  const items = library.assessments.map(libraryItem);
  const dir = library.dir;
  const assistant: AssistantInfo = {
    scope: scopeOf(chosen),
    runs: scopedViews(views, null).map((v) => ({ ...runRef(v), status: v.status })),
    prompts: welcomePrompts(scopedViews(views, chosen?.uid ?? null)),
    retentionDays: 0, // the Core API keeps conversations until they are closed
    model,
  };
  const empty = <CoreEmptyView error={error} problems={library.problems} compact />;
  /* A stale or hand-typed ?uid= used to fall straight through to the all-runs view, with nothing
     to say the run asked for was not there (QA-LOCAL-WEB-REPORT, QAL-003). */
  const missing = wanted && !chosen && views.length > 0;

  return (
    <Viewer
      topBar={
        <TopBar
          dash={dash}
          overall={overall}
          items={items}
          dir={dir}
          renderedAt={clock(library.readAt)}
          skipped={library.problems}
        />
      }
      notice={
        missing ? (
          <p role="status" className="dash-missing-run">
            The Core API has no such assessment — showing all of them.
          </p>
        ) : null
      }
      overview={
        dash ? (
          <OverviewView cards={dash.cards} />
        ) : overall ? (
          <OverviewView cards={overall.cards} />
        ) : (
          <CoreEmptyView error={error} problems={library.problems} />
        )
      }
      assessments={
        <Suspense fallback={<AssessmentsLoading />}>
          <ApiAssessments />
        </Suspense>
      }
      findings={
        // streamed: the other views never wait on the API (a view switch is client-side only, so
        // every pane is rendered with the page)
        <Suspense fallback={<FindingsLoading />}>
          <ApiFindings assessmentId={apiAssessment} savedRun={apiAssessment ? null : wanted} />
        </Suspense>
      }
      log={views.length ? <RunLogView key={chosen?.uid ?? "all"} data={chosen ? runLogData(chosen) : null} /> : empty}
      reports={
        <Suspense fallback={<ReportsLoading />}>
          <ApiReports assessmentId={apiAssessment} />
        </Suspense>
      }
      knowledge={<KnowledgeView />}
      assistant={assistant}
    />
  );
}
