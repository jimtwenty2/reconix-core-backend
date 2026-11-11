/* One provider of the AI Assistant's models, on the Core API (signed in; src/proxy.ts checks
   the session too). PATCH changes it ({ name?, preset?, baseUrl?, models?, apiKey?,
   removeKey? }); DELETE removes it. Both need the page's own Origin; the id must be a provider
   id (a random UUID) before anything is sent. Answers carry the model picker's whole view,
   never a key. */
import { NextResponse } from "next/server";

import { removeProvider, updateProvider } from "@/lib/api/models";
import { coreFailure } from "@/lib/api/respond";
import { fail, NO_STORE, refuse } from "@/lib/assistant/access";
import { UpdateProviderSchema } from "@/lib/assistant/models/requests";
import { readBody } from "@/lib/assistant/models/respond";
import { isProviderId } from "@/lib/assistant/models/schema";

type Context = { params: Promise<{ id: string }> };

async function idOf(ctx: Context): Promise<string | null> {
  const { id } = await ctx.params;
  return isProviderId(id) ? id : null;
}

export async function PATCH(request: Request, ctx: Context) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  const id = await idOf(ctx);
  if (!id) return fail("That is not a provider id.", 400);
  const body = await readBody(request, UpdateProviderSchema, "Send { name?, preset?, baseUrl?, models?, apiKey? or removeKey? } only.");
  if (!body.ok) return body.response;
  try {
    return NextResponse.json(await updateProvider(id, body.value), { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The provider could not be changed.");
  }
}

export async function DELETE(request: Request, ctx: Context) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  const id = await idOf(ctx);
  if (!id) return fail("That is not a provider id.", 400);
  try {
    return NextResponse.json(await removeProvider(id), { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The provider could not be removed.");
  }
}
