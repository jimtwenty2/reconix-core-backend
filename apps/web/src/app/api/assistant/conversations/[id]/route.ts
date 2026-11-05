/* One conversation (signed in; src/proxy.ts checks the session too), from the Core API: GET
   reads it with every message; DELETE closes its session (the API keeps the messages; the
   list stops showing it). The API keeps no titles, so PATCH (rename) is refused. Changes need
   the page's own Origin; the id must be a conversation id (a random UUID) before anything is
   read. */
import { NextResponse } from "next/server";

import { closeConversation, readConversation } from "@/lib/api/assistant";
import { coreFailure } from "@/lib/api/respond";
import { fail, NO_STORE, refuse } from "@/lib/assistant/access";
import { isConversationId } from "@/lib/assistant/protocol";

type Context = { params: Promise<{ id: string }> };

const BAD_ID = "That is not a conversation id.";
const GONE = "That conversation is not saved any more.";

export async function GET(request: Request, ctx: Context) {
  const refused = await refuse(request, { change: false });
  if (refused) return refused;
  const { id } = await ctx.params;
  if (!isConversationId(id)) return fail(BAD_ID, 400);
  try {
    const conversation = await readConversation(id);
    if (!conversation) return fail(GONE, 404);
    return NextResponse.json({ conversation }, { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The conversation could not be read.");
  }
}

export async function PATCH(request: Request) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  return fail("Conversations are named by their first question; the Core API keeps no other name.", 405);
}

export async function DELETE(request: Request, ctx: Context) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  const { id } = await ctx.params;
  if (!isConversationId(id)) return fail(BAD_ID, 400);
  try {
    if (!(await readConversation(id))) return fail(GONE, 404);
    await closeConversation(id);
    return NextResponse.json({ deleted: 1 }, { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The conversation could not be closed.");
  }
}
