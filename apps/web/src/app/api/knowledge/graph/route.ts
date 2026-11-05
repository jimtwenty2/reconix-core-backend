/* The Security knowledge graph (signed in; src/proxy.ts checks the session too): every document
   and the references and topics it talks about (lib/api/knowledge.ts `graphData`). Names and
   counts only, never a passage. */
import { NextResponse } from "next/server";

import { NO_STORE } from "@/lib/assistant/access";
import { graphData } from "@/lib/api/knowledge";
import { coreFailure } from "@/lib/api/respond";
import { refuseKnowledge } from "@/lib/knowledge/access";

export async function GET(request: Request) {
  const refused = await refuseKnowledge(request, false);
  if (refused) return refused;
  try {
    return NextResponse.json(await graphData(), { headers: NO_STORE });
  } catch (error) {
    return coreFailure(error, "The knowledge graph could not be read.");
  }
}
