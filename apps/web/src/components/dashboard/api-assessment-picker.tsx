"use client";

/* Which Core API assessment the Findings view lists: "All assessments" or one. Choosing one
   opens `/?view=findings&assessment=<uuid>` (the server reads it again; the old filters and
   the selected finding belong to the old list, so they are dropped). */
import { useRouter } from "next/navigation";

import { CHIP } from "@/components/dashboard/assessment-switcher";

export function ApiAssessmentPicker({ items, current }: { items: { id: string; label: string }[]; current: string | null }) {
  const router = useRouter();
  return (
    <label className="mb-3 flex items-center gap-2 text-xs">
      <span className="text-muted-foreground">Assessment</span>
      <select
        className={CHIP}
        value={current ?? ""}
        onChange={(e) => router.push(e.target.value ? `/?view=findings&assessment=${encodeURIComponent(e.target.value)}` : "/?view=findings")}
      >
        <option value="">All assessments</option>
        {current && !items.some((i) => i.id === current) && <option value={current}>Unknown assessment</option>}
        {items.map((i) => (
          <option key={i.id} value={i.id}>
            {i.label}
          </option>
        ))}
      </select>
    </label>
  );
}
