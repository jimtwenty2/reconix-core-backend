/* The model API keys the server holds itself (server only), so a question that repeats one is
   masked by its value (redact.ts `maskValues`) before it is saved, searched or sent: the shapes in
   redact.ts miss a short or unusual key. Read through store.ts `readSaved`
   (opened in memory for this one masking, never returned to a route or logged). A key that can't
   be opened is skipped: what is saved for it is the sealed form, which shows nothing. The TUI's
   store/known_secrets.py does the same for its saved keys and the target login. */
import "server-only";

import { maskValues } from "../redact";
import { readSaved } from "./store";

/** Every saved provider's API key, opened ([] when nothing is saved or the file can't be read:
    the route has checked the chosen model already, and an unreadable file holds no key to mask). */
export async function savedKeys(): Promise<string[]> {
  let saved;
  try {
    saved = await readSaved();
  } catch {
    return [];
  }
  const keys: string[] = [];
  for (const provider of saved.file.providers) {
    try {
      const key = saved.apiKeyOf(provider);
      if (key) keys.push(key);
    } catch {
      // sealed with a key that is gone: nothing readable to mask
    }
  }
  return keys;
}

/** `text` with every saved model API key masked by its value. */
export async function maskSavedKeys(text: string): Promise<string> {
  return maskValues(text, await savedKeys());
}
