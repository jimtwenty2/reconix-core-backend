/* The AI Assistant's models (signed in; src/proxy.ts checks the session too), kept by the Core
   API (lib/api/models.ts on /llm-providers). GET: the providers without their keys (only
   whether one is saved), the active choice, a summary of the model that answers next and the
   presets in the model picker's order. POST adds a provider ({ name, preset, baseUrl, models,
   apiKey?, activate? }); it needs the page's own Origin. The key goes to the API once, over
   this computer's loopback, and never comes back. */
import { NextResponse } from "next/server";

import { addProvider, modelsView } from "@/lib/api/models";
import { coreFailure } from "@/lib/api/respond";
import { NO_STORE, refuse } from "@/lib/assistant/access";
import { PRESETS } from "@/lib/assistant/models/presets";
import { AddProviderSchema } from "@/lib/assistant/models/requests";
import { readBody } from "@/lib/assistant/models/respond";

export async function GET(request: Request) {
  const refused = await refuse(request, { change: false });
  if (refused) return refused;
  const fast = new URL(request.url).searchParams.get("fast") === "1";
  try {
    return NextResponse.json({ ...(await modelsView({ probe: !fast })), presets: PRESETS }, { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The models could not be read.");
  }
}

export async function POST(request: Request) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  const body = await readBody(request, AddProviderSchema, "Send { name, preset, baseUrl, models, apiKey?, activate? } only.");
  if (!body.ok) return body.response;
  try {
    return NextResponse.json(await addProvider(body.value), { status: 201, headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The provider could not be added.");
  }
}
