/* The Local Assessment Viewer at `/`, rendered per request from the assessments the Reconix
   TUI saved (src/lib/data/store.ts). With no `?uid=` the Overview totals every saved run
   (derive-overall.ts); `?uid=` opens one run (derive.ts). The Findings and Report views read
   the Core API instead (components/dashboard/api-findings.tsx, api-reports.tsx), for the
   assessment `?assessment=<uuid>` names. `?view=` is
   the open view, read by the client Viewer. There are no roles: signed in (src/proxy.ts and
   loadLibrary check), every view renders. The AI Assistant learns what it is about, which model answers
   (lib/assistant/models/resolve.ts) and what to suggest, from the data in scope
   (lib/assistant/prompts.ts). */
import { Suspense } from "react";

import type { AssistantInfo } from "@/components/assistant/types";
import { deriveDashboard } from "@/components/dashboard/derive";
import { deriveOverall } from "@/components/dashboard/derive-overall";
import { assessmentsCards, runRow } from "@/components/dashboard/derive-report";
import { runLogData } from "@/components/dashboard/derive-run-log";
import { ApiFindings, FindingsLoading } from "@/components/dashboard/api-findings";
import { ApiReports, ReportsLoading } from "@/components/dashboard/api-reports";
import { AssessmentsView } from "@/components/dashboard/assessments-view";
import { EmptyView } from "@/components/dashboard/empty-view";
import { OverviewView } from "@/components/dashboard/overview-view";
import { RunLogView } from "@/components/dashboard/run-log-view";
import { TopBar } from "@/components/dashboard/top-bar";
import { Viewer } from "@/components/dashboard/viewer";
import { KnowledgeView } from "@/components/knowledge/knowledge-view";
import { isAssessmentId } from "@/lib/api/findings";
import { loadApiLibrary } from "@/lib/api/library";
import { activeModelSummary } from "@/lib/api/models";
import { runRef, scopedViews, scopeOf } from "@/lib/assistant/insights";
import { welcomePrompts } from "@/lib/assistant/prompts";
import { assessmentView, libraryItem } from "@/lib/data/adapt";
import { clock } from "@/lib/data/format";
import { loadLibrary, shownDir, UID } from "@/lib/data/store";

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function Home({ searchParams }: Props) {
  const [params, library] = await Promise.all([searchParams, loadLibrary()]);
  const wanted = typeof params.uid === "string" && UID.test(params.uid) ? params.uid : null;
  const views = library.assessments.map(assessmentView);
  // Findings come from the Core API, for its own assessment (`?assessment=<uuid>`), not `?uid=`.
  const apiAssessment = isAssessmentId(params.assessment) ? params.assessment : null;
  const chosen = views.find((v) => v.uid === wanted) ?? null;
  const dash = chosen ? deriveDashboard(chosen) : null;
  const overall = !chosen && views.length ? deriveOverall(views) : null;
  const items = library.assessments.map(libraryItem);
  const dir = shownDir(library.dir);
  // its summary only (no API key comes back); without the Core API the assistant says so
  const model = await activeModelSummary().catch((error: unknown) => ({
    configured: false,
    name: "",
    provider: "",
    local: false,
    reason: error instanceof Error ? error.message.slice(0, 600) : "The Core API is not running.",
  }));
  // the AI Assistant shows the Core API's real assessments, never the saved demo files
  const apiViews = (await loadApiLibrary().catch(() => ({ assessments: [] }))).assessments.map(assessmentView);
  const apiChosen = apiViews.find((v) => v.uid === wanted) ?? null;
  const assistant: AssistantInfo = {
    scope: scopeOf(apiChosen),
    runs: scopedViews(apiViews, null).map((v) => ({ ...runRef(v), status: v.status })),
    prompts: welcomePrompts(scopedViews(apiViews, apiChosen?.uid ?? null)),
    retentionDays: 0, // the Core API keeps conversations until they are closed
    model,
  };
  const empty = <EmptyView dir={dir} problems={library.problems} compact />;
  /* A stale or hand-typed ?uid= used to fall straight through to the all-runs view, with nothing
     to say the run asked for was not there (QA-LOCAL-WEB-REPORT, QAL-003). */
  const missing = wanted && !chosen && views.length > 0;
  const runs = views.map(runRow);

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
            That assessment isn&apos;t in this folder — showing all runs.
          </p>
        ) : null
      }
      overview={
        dash ? (
          <OverviewView cards={dash.cards} />
        ) : overall ? (
          <OverviewView cards={overall.cards} />
        ) : (
          <EmptyView dir={dir} problems={library.problems} />
        )
      }
      assessments={runs.length ? <AssessmentsView data={assessmentsCards(runs)} /> : empty}
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
