# arjun fixtures

Real arjun v2.2.7 stdout captured in the lab Kali container against the lab target only
(`http://juice-shop:3000/rest/products/search`, a short wordlist for speed). ANSI colour and
the progress `\r` redraws are kept as captured; the reader strips them via `findings.text.lines`.
`juice_shop.txt` ends with the authoritative `[+] Parameters found: security, q` summary.
