/* The model picker's "Test connection", on the Core API (signed in; src/proxy.ts checks the
   session too): POST { name, preset, baseUrl, apiKey?, providerId? }. A new provider is saved
   first (not active), then checked, and its models come back (lib/api/models.ts `connect`);
   one that fails is removed again. Needs the page's own Origin; at most a few at a time. */
import { NextResponse } from "next/server";

import { connect } from "@/lib/api/models";
import { coreFailure } from "@/lib/api/respond";
import { fail, NO_STORE, refuse } from "@/lib/assistant/access";
import { ConnectSchema } from "@/lib/assistant/models/requests";
import { readBody } from "@/lib/assistant/models/respond";
import { createLimiter } from "@/lib/assistant/rate";

const limiter = createLimiter(30, 2);

export async function POST(request: Request) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  const body = await readBody(request, ConnectSchema, "Send { name, preset, baseUrl, apiKey?, providerId? } only.");
  if (!body.ok) return body.response;
  const release = limiter.take();
  if (!release) return fail("Too many at once. Wait a moment and try again.", 429);
  try {
    return NextResponse.json(await connect(body.value), { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The Core API could not reach the provider.");
  } finally {
    release();
  }
}
