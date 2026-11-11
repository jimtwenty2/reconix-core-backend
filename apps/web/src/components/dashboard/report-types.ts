/* What the Assessments view draws (AssessmentsCards, derive-report.ts): every saved run as a
   row. Types only. */
import type { LibraryItem, Severity } from "@/lib/data/view-types";

/** A saved run in the runs table (a LibraryItem, so the run search reads it). */
export interface ReportRunRow extends LibraryItem {
  findings: number; // false positives left out
  worst: Severity | null;
  steps: { done: number; total: number };
}

/** What the Assessments view draws: its header and every saved run as a row. */
export interface AssessmentsCards {
  tag: string; // "All 27 runs"
  about: string;
  rows: ReportRunRow[]; // newest first
}
