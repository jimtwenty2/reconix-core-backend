/* One Core API report file (signed in): `?format=PDF|DOCX|JSON` of a READY, signed-off report,
   fetched by the server with its own session (the token never reaches the browser) and passed
   on as a download. A refusal is the API's own `{code, message}` with its status, and `detail`
   for the dashboard's file fetch (use-file-download.ts), never a fallback file. */
import { NextResponse } from "next/server";

import { signedIn } from "@/lib/auth/guard";
import { CoreApiError } from "@/lib/api/client";
import { downloadReport, isReportFormat } from "@/lib/api/reports";

const NO_STORE = { "Cache-Control": "no-store" };
const EXT = { PDF: "pdf", DOCX: "docx", JSON: "json" } as const;
/** The media type is ours, by format: never the API's, which could ask a browser to render it. */
const MEDIA = { PDF: "application/pdf", DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", JSON: "application/json" } as const;

const refuse = (code: string, message: string, status: number) =>
  NextResponse.json({ code, message, detail: message }, { status, headers: NO_STORE });

/** The API's file name, kept only if it is plain (letters, digits, `.`, `_`, `-`). */
const fileName = (disposition: string | null, fallback: string) => {
  const name = disposition?.match(/filename="?([^";]+)"?/)?.[1] ?? "";
  return /^[A-Za-z0-9._-]{1,120}$/.test(name) ? name : fallback;
};

export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }) {
  if (!(await signedIn())) return refuse("NOT_SIGNED_IN", "Sign in first.", 401);
  const format = new URL(request.url).searchParams.get("format") ?? "";
  if (!isReportFormat(format)) return refuse("BAD_REQUEST", "Unknown report format.", 400);
  const { id } = await ctx.params;
  try {
    const file = await downloadReport(id, format);
    return new NextResponse(file.bytes, {
      headers: {
        "Content-Type": MEDIA[format],
        "Content-Disposition": `attachment; filename="${fileName(file.disposition, `report.${EXT[format]}`)}"`,
        ...NO_STORE,
      },
    });
  } catch (e) {
    if (!(e instanceof CoreApiError)) throw e;
    // the API's own refusal keeps its status; ours (down, a bad answer on a 200) is a 502
    return refuse(e.code, e.message, e.status >= 400 ? e.status : e.code === "BAD_REQUEST" ? 400 : 502);
  }
}
