---
name: theme-tokens
description: Rules for adding or changing colors and design tokens for the Reconix TUI and local web, keeping tui/reconix/theme.py, the TUI stylesheet and the web's generated tokens.css in sync. Use whenever touching colors, severity/status/risk styles or badges.
---

# Theme tokens

`tui/reconix/theme.py` is the **only** place a color is defined.

| Where | Used for | Fed by |
|---|---|---|
| `theme.py` constants | Rich styles in TUI widgets (`theme.CYAN`) | itself |
| `tui/reconix/reconix.tcss` `$variables` | Textual styling | `theme.CSS_TOKENS` |
| `web/src/styles/tokens.css` | the web's CSS variables | `theme.WEB_TOKENS` via `scripts/export_tokens.py` |

## Rules
1. **Never hard-code a hex value** in a screen, widget, TCSS file or web component. The
   `post-edit-check` hook flags hex in `.tcss`.
2. Add a token in `theme.py` only: a constant, plus an entry in `CSS_TOKENS` (TUI) and/or
   `WEB_TOKENS` (web).
3. For the web, regenerate (never edit `tokens.css`; the `guard-paths` hook refuses it):
   ```bash
   cd tui && python scripts/export_tokens.py
   ```
4. Severity, status and risk colors go through the maps and helpers in `theme.py`; the web
   mirrors the meanings in `web/src/lib/status.ts` (`StatusBadge` / `SeverityBadge`) and never
   uses colour alone.
5. Keep text readable on the dark background: body text `TEXT`, secondary `MUTED`, hints `DIM`.
   Never use `DIM` for anything the user must read.

## Check
```bash
grep -rnE '#[0-9A-Fa-f]{6}' tui/reconix/screens tui/reconix/widgets tui/reconix/reconix.tcss
grep -rnE '#[0-9A-Fa-f]{6}' web/src --include=*.tsx --include=*.ts | grep -v tokens
```
New code adds no hits.
