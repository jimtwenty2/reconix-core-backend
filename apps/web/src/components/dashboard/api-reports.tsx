/* The Report view, from the Core API (server component), for the assessment the shared picker
   names (`?assessment=<uuid>`, the Findings view's too): its summary strip (GET .../overview)
   and its report versions with their files (GET .../reports). With none picked, the Core API's
   assessments as a table, each opening its own report. Read-only, and no fallback: when the
   API is down or refuses, the view says what it said. */
import Link from "next/link";

import { ApiReportList } from "@/components/dashboard/api-report-list";
import { ApiAssessmentPicker } from "@/components/dashboard/api-assessment-picker";
import { ApiErrorNote, Shell } from "@/components/dashboard/api-findings";
import { DashCard } from "@/components/dashboard/dash-card";
import { plural } from "@/components/dashboard/derive-shared";
import { StatStrip } from "@/components/dashboard/stat-strip";
import { DocsLink, ViewHeader } from "@/components/dashboard/view-header";
import { EmptyNote } from "@/components/ui/empty-note";
import { overviewStats, pickerItems, reportRow } from "@/lib/api/adapt";
import { CoreApiError } from "@/lib/api/client";
import { type ApiAssessment, listAssessments } from "@/lib/api/findings";
import { listReports, readOverview } from "@/lib/api/reports";
import { DOCS } from "@/lib/docs-nav";

const header = (tag: string | undefined, about: string) => (
  <ViewHeader title="Report" tag={tag} about={about}>
    <DocsLink href={DOCS.exporting}>Report format</DocsLink>
  </ViewHeader>
);

/** Shown while the API answers (page.tsx streams the view behind it). */
export const ReportsLoading = () => (
  <Shell>
    <EmptyNote status>Reading reports from the Core API…</EmptyNote>
  </Shell>
);

export async function ApiReports({ assessmentId }: { assessmentId: string | null }) {
  let assessments: ApiAssessment[];
  try {
    assessments = await listAssessments();
  } catch (e) {
    if (!(e instanceof CoreApiError)) throw e;
    return (
      <Shell>
        {header(undefined, "Reports from the Core API.")}
        <ApiErrorNote e={e} />
      </Shell>
    );
  }
  const picker = <ApiAssessmentPicker items={pickerItems(assessments)} current={assessmentId} view="reports" />;

  if (assessmentId === null)
    return (
      <div className="dash-view dash-sheet" data-mode="all">
        {header(`All (${assessments.length})`, "Pick an assessment to see its reports and download their files.")}
        <div className="mt-3">{picker}</div>
        <AssessmentTable assessments={assessments} />
      </div>
    );

  const chosen = assessments.find((a) => a.assessment_id === assessmentId);
  let failed: CoreApiError | null = null;
  let data: [Awaited<ReturnType<typeof readOverview>>, Awaited<ReturnType<typeof listReports>>] | null = null;
  if (chosen) {
    try {
      data = await Promise.all([readOverview(assessmentId), listReports(assessmentId)]);
    } catch (e) {
      if (!(e instanceof CoreApiError)) throw e;
      failed = e;
    }
  }
  if (!chosen || failed?.code === "ASSESSMENT_NOT_FOUND" || !data)
    return (
      <Shell>
        {header(undefined, "Reports from the Core API.")}
        <div className="mt-3">{picker}</div>
        {failed && failed.code !== "ASSESSMENT_NOT_FOUND" ? <ApiErrorNote e={failed} /> : <EmptyNote status>The Core API has no assessment with that id. Pick another one.</EmptyNote>}
      </Shell>
    );

  const [overview, reports] = data;
  const a = overview.assessment;
  const tag = [a.engagement_code, overview.targets[0]].filter(Boolean).join(" · ");
  return (
    <div className="dash-view dash-sheet" data-mode="run">
      {header(tag, `${a.name} · ${plural(reports.length, "report version")} from the Core API.`)}
      <div className="mt-3">{picker}</div>
      <StatStrip stats={overviewStats(overview)} label="Report summary" />
      <div className="dash-panels">
        <ApiReportList reports={reports.map(reportRow)} />
      </div>
    </div>
  );
}

function AssessmentTable({ assessments }: { assessments: ApiAssessment[] }) {
  return (
    <div className="dash-panels">
      <DashCard id="report-assessments" title="Assessments" docsHref={DOCS.exporting} meta={plural(assessments.length, "assessment")} className="is-wide">
        {assessments.length === 0 ? (
          <EmptyNote>The Core API holds no assessment yet. Start one in the TUI.</EmptyNote>
        ) : (
          <div className="dash-table-scroll">
            <table aria-label="Core API assessments" className="dash-table">
              <thead>
                <tr>
                  <th scope="col">Assessment</th>
                  <th scope="col">Status</th>
                  <th scope="col">Targets</th>
                  <th scope="col">Findings</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((a) => (
                  <tr key={a.assessment_id}>
                    <th scope="row" className="font-normal">
                      <Link href={`/?view=reports&assessment=${encodeURIComponent(a.assessment_id)}`} className="ui-link">
                        {a.name || a.assessment_id.slice(0, 8)}
                      </Link>
                    </th>
                    <td className="font-mono text-xs">{a.assessment_status}</td>
                    <td className="font-mono text-xs [overflow-wrap:anywhere]">{a.targets.join(", ") || "—"}</td>
                    <td className="tabnums">{a.finding_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DashCard>
    </div>
  );
}
