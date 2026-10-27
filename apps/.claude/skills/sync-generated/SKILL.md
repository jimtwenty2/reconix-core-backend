---
name: sync-generated
description: Regenerate the files the TUI writes into the web (design tokens, the docs' command reference, sample data, knowledge vectors) after changing their source. Use after editing theme.py, commands/builtin.py, store/snapshot.py or the store's sample runs, or when a stale-file test fails.
---

# Regenerate the shared files

These files in `web/` are made by scripts in `tui/scripts/`. Never edit them by hand: the
`guard-paths` hook refuses it.

| Changed | Run (in `tui/`, `.venv` active) | Writes |
|---|---|---|
| `reconix/theme.py` (`WEB_TOKENS`) | `python scripts/export_tokens.py` | `web/src/styles/tokens.css` |
| `reconix/commands/builtin.py` (`COMMANDS`) | `python scripts/export_commands.py` | `web/src/content/docs/commands.json` |
| `store/snapshot.py`, templates, demo runs | `python scripts/make_sample_data.py` | `web/sample-data/*.json` |
| `store/knowledge/rank.py` (tokens, BM25) | `python scripts/make_knowledge_vectors.py` | `web/tests/knowledge-vectors.json` |

## After `snapshot.py` changes
The web validates saved files with `web/src/lib/data/schema.ts`: change it in the same commit,
regenerate the sample data, then run both suites.

## Check
```bash
cd tui && python scripts/export_commands.py --check && pytest -q tests/test_export_commands.py \
  tests/test_knowledge_vectors.py tests/test_redact_vectors.py
cd ../web && npm run check:data && npm test
```

Commit the source change and the regenerated files together.
