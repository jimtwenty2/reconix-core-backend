// Copy the mock model's prepared answers from the TUI (the one source) into the web.
//   node scripts/sync-mock-replies.mjs           write src/lib/assistant/models/mock-replies.json
//   node scripts/sync-mock-replies.mjs --check   exit 1 when the copy differs
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(web, "../tui/reconix/llm/mock_replies.json");
const target = resolve(web, "src/lib/assistant/models/mock-replies.json");

const text = readFileSync(source, "utf8");
JSON.parse(text); // a broken file is never copied
if (process.argv.includes("--check")) {
  let current = "";
  try {
    current = readFileSync(target, "utf8");
  } catch {
    // missing: out of date
  }
  if (current !== text) {
    console.error("mock-replies.json is out of date: run node scripts/sync-mock-replies.mjs");
    process.exit(1);
  }
  console.log("mock-replies.json is up to date");
} else {
  writeFileSync(target, text);
  console.log("wrote src/lib/assistant/models/mock-replies.json");
}
