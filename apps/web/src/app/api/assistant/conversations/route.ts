/* The AI Assistant's conversations (signed in; src/proxy.ts checks the session too), read from
   the Core API (lib/api/assistant.ts: one conversation is one open web session): GET lists
   them, newest use first; DELETE closes every one this dashboard started, and needs the
   page's own Origin. */
import { NextResponse } from "next/server";

import { closeAll, listConversations } from "@/lib/api/assistant";
import { coreFailure } from "@/lib/api/respond";
import { NO_STORE, refuse } from "@/lib/assistant/access";

export async function GET(request: Request) {
  const refused = await refuse(request, { change: false });
  if (refused) return refused;
  try {
    // the API keeps them until they are closed
    return NextResponse.json({ conversations: await listConversations(), retentionDays: 0 }, { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The conversations could not be read.");
  }
}

export async function DELETE(request: Request) {
  const refused = await refuse(request, { change: true });
  if (refused) return refused;
  try {
    return NextResponse.json({ deleted: await closeAll() }, { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The conversations could not be closed.");
  }
}
