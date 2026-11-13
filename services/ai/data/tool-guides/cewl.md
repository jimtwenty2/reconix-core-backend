# cewl

## When to use

Spiders a website and builds a custom wordlist from its content — a targeted list for password
attacks. Use it when the target's own words are the best guesses, then feed the list to john or
hashcat for an offline crack, or to hydra against a network login. For character-set or pattern
lists use crunch.

## Key options

- `url` — the target website URL to spider, for example `http://example.com`. Required.
- `depth` — the link depth to spider (default: 2).
- `min_length` — the minimum word length to include (default: 3).
- `outfile` — an output file path for the wordlist.
- `opts` — additional cewl options, for example `--lowercase`.
- `timeout` — per-call timeout in seconds.

## Output

The extracted words, and the wordlist file when `outfile` is given. Reconix keeps no findings from
cewl: `READERS` in the API's `services/findings.py` has no entry for it, so `parse_run` returns
none and only the masked output stays on the tool run.

## Risk notes

The catalog baseline is `LOW` and cewl is `read_only`, so a run goes ahead without waiting for a
person, while anything above the scope's `max_risk` is blocked. `risk_ops.json` has no cewl entry,
so no option raises a call above that baseline. Cewl does send requests to a live website, so the
scope check is what keeps the spider inside the approved targets. The words it returns are public
content, not credentials, but a crack that uses the list puts a real credential in the cracking
tool's output, and rule S8 masks secrets before anything is saved, logged, shown or sent to the
AI, so a person reads the raw tool run rather than the model.
