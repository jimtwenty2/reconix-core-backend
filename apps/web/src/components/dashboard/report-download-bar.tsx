"use client";

/* Header export control for the Report view: one `Export` button that opens the export dialog
   with format selection and live preview before downloading. */
import { useState } from "react";
import { Download } from "lucide-react";

import { ReportExportDialog, type ReportExportPreview } from "@/components/dashboard/report-export-dialog";
import { Button } from "@/components/ui/button";
import type { ReportFormat } from "@/lib/api/reports";

export function ReportDownloadBar({
  report,
  lockedHint,
  preview,
}: {
  report: { id: string; version: number; formats: ReportFormat[] } | null;
  lockedHint?: string | null;
  preview: ReportExportPreview;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button type="button" variant="outline" size="xs" onClick={() => setOpen(true)} aria-label="Export">
        <Download className="size-3.5" aria-hidden />
        Export
      </Button>
      <ReportExportDialog open={open} onClose={() => setOpen(false)} report={report} lockedHint={lockedHint} preview={preview} />
    </>
  );
}
