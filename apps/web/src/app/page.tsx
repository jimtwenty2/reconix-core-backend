/* The Local Assessment Viewer at `/`: with the Core API running, Overview, Assessments,
   Findings, Run log and Reports read real assessments from the Core API (lib/api/library.ts).
   When the Core API is unreachable or in mock mode (RECONIX_MOCK=1), it falls back to the
   assessments saved on disk (lib/data/store.ts).
   With no run chosen the Overview totals every run (derive-overall.ts); choosing one opens that run
   (derive.ts). `?view=` is the open view, read by the client Viewer. There are no roles: signed in
   (src/proxy.ts), every view renders. The AI Assistant learns what it is about, which model answers
   and what to suggest, from the assessments in scope. */
import { Suspense } from "react";

import type { AssistantInfo } from "@/components/assistant/types";
import { deriveDashboard } from "@/components/dashboard/derive";
import { deriveOverall } from "@/components/dashboard/derive-overall";
import { runRow } from "@/components/dashboard/derive-report";
import { runLogData } from "@/components/dashboard/derive-run-log";
import { ApiFindings, FindingsLoading } from "@/components/dashboard/api-findings";
import { ApiReports, ReportsLoading } from "@/components/dashboard/api-reports";
import { EmptyView } from "@/components/dashboard/empty-view";
import { LiveAssessments } from "@/components/dashboard/live-assessments";
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
import { type Library, loadLibrary, shownDir, UID } from "@/lib/data/store";
import { liveRefreshMs } from "@/lib/live-refresh";

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function Home({ searchParams }: Props) {
  const params = await searchParams;
  const wanted = typeof params.uid === "string" && UID.test(params.uid) ? params.uid : null;
  const apiAssessment = isAssessmentId(params.assessment) ? params.assessment : null;

  let library: Library;
  if (process.env.RECONIX_MOCK === "1") {
    library = await loadLibrary();
  } else {
    try {
      library = await loadApiLibrary();
    } catch {
      library = await loadLibrary();
    }
  }

  const views = library.assessments.map(assessmentView);
  const chosen =
    views.find(
      (v) =>
        (wanted && v.uid === wanted) ||
        (apiAssessment && (v.coreId === apiAssessment || v.uid === apiAssessment)),
    ) ?? null;

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

  const assistant: AssistantInfo = {
    scope: scopeOf(chosen),
    runs: scopedViews(views, null).map((v) => ({ ...runRef(v), status: v.status })),
    prompts: welcomePrompts(scopedViews(views, chosen?.uid ?? null)),
    retentionDays: 0, // the Core API keeps conversations until they are closed
    model,
  };

  const empty = <EmptyView dir={dir} problems={library.problems} compact />;
  const missing = Boolean((wanted || apiAssessment) && !chosen && views.length > 0);
  const runs = views.map(runRow);
  const every = liveRefreshMs();

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
      assessments={
        runs.length ? (
          <LiveAssessments initial={runs} everyMs={every > 0 ? Math.min(every, 5000) : 0} />
        ) : (
          empty
        )
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
