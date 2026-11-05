/* The model picker's "Test connection": POST /llm-providers/{id}/test (one fixed prompt, no Reconix data), on the Core API (signed in; src/proxy.ts checks the session too).
   POST { providerId, model? } asks about a saved provider; unsaved values from the form
   ({ baseUrl, ... }) are checked by the API once the provider is added. Needs the page's own
   Origin; at most a few at a time. */
import { NextResponse } from "next/server";

import { testModel } from "@/lib/api/models";
import { coreFailure } from "@/lib/api/respond";
import { fail, NO_STORE, refuse } from "@/lib/assistant/access";
import { ProbeSchema } from "@/lib/assistant/models/requests";
import { readBody } from "@/lib/assistant/models/respond";
import { createLimiter } from "@/lib/assistant/rate";

const limiter = createLimiter(30, 2);

export async function POST(request: Request) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  const body = await readBody(request, ProbeSchema, "Send { providerId, model? } or { baseUrl, model, apiKey? } only.");
  if (!body.ok) return body.response;
  const release = limiter.take();
  if (!release) return fail("Too many at once. Wait a moment and try again.", 429);
  try {
    return NextResponse.json(await testModel(body.value), { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The Core API could not reach the model.");
  } finally {
    release();
  }
}
