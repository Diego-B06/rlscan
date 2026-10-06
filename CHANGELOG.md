# Changelog

## 0.2.0

Hardening release, validated against a real local Supabase (Postgres + PostgREST) and a Next.js app.

### Fixed
- **Hang on stalled responses.** The timeout now covers the whole request including the body; a server that sends headers and then stalls can no longer block a scan forever.
- **False criticals on SPAs.** `.env`, `.git/config`, etc. are now validated by *content* and compared against a baseline of a non-existent path, so a catch-all `200 index.html` is no longer reported as exposed.
- **Unreachable sites passed CI.** New exit code `2` when the scan could not run (DNS error, refused connection, timeout, invalid URL), including with `--fail-on-high`.
- Misleading `No se evaluaron cabeceras…` message that was followed by header findings anyway.
- "No tables exposed" reassurance when the OpenAPI spec was simply unavailable; now it warns honestly and points to `--supabase-tables`.
- A wrong/expired anon key silently produced zero findings; now warns.
- A `service_role` key passed as `--supabase-anon-key` was accepted (and produced false positives); now refused with exit `2`.
- Secrets scanner: the 15-script cap hid keys in later bundles, and dynamically imported chunks were never visited. It now follows chunks (depth 3, default cap 80 files, `--max-files`).

### Added
- Detection for new Supabase `sb_secret_` keys, Anthropic/OpenAI keys, Stripe restricted keys, GitHub fine-grained tokens.
- Table findings escalate to critical when readable rows contain sensitive column names (names only; values are never read into output).
- Tables that return an empty list are listed as "cannot verify RLS" (empty and RLS-protected look identical to `anon`).
- `--supabase-tables`, `--max-files`, `--no-color`, `--version`; `NO_COLOR` support; JSON output includes `summary`.
- Automatic `https://` when the scheme is omitted.
- 29 automated tests and CI on Node 18/20/22.

### Changed
- Firebase/Google web API keys are reported as **low** (public by design; check referrer restrictions).
- HSTS is not required over plain `http://`; `frame-ancestors` in CSP satisfies X-Frame-Options.

## 0.1.0
- Initial release.
