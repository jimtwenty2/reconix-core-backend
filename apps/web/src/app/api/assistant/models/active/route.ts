/* The model that answers the AI Assistant's next question, on the Core API (signed in;
   src/proxy.ts checks the session too). PUT { providerId, model } activates that provider
   (POST /llm-providers/{id}/activate). A model off this computer waits for its configuration
   approval: the answer is 409 and says so; nothing is approved here. Needs the page's own
   Origin. Answers with the model picker's whole view (never a key). */
import { NextResponse } from "next/server";

import { setActive } from "@/lib/api/models";
import { coreFailure } from "@/lib/api/respond";
import { NO_STORE, refuse } from "@/lib/assistant/access";
import { SetActiveSchema } from "@/lib/assistant/models/requests";
import { readBody } from "@/lib/assistant/models/respond";

export async function PUT(request: Request) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  const body = await readBody(request, SetActiveSchema, "Send { providerId, model } only: a saved provider's id and one of its models.");
  if (!body.ok) return body.response;
  try {
    return NextResponse.json(await setActive(body.value), { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The model could not be chosen.");
  }
}
