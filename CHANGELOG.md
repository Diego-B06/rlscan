# Changelog

## 0.3.0

### Fixed
- **Supabase checks that couldn't run looked like a pass.** If every table probe failed (5xx, invalid JSON, timeout) there was no finding at all; a schema that couldn't be listed or an invalid key was only `medium`, so `--fail-on-high` exited `0`. These are now `error` (exit `2`) when you asked for the check; partially failed tables are listed.
- **`--max-files abc` removed the cap entirely** (`NaN` comparison). It now must be a positive integer. Invalid arguments exit `2` instead of commander's `1`, which meant "findings".
- **Silent partial secret scans.** Hitting the 60 s budget, bundles that failed to download and files truncated at 5 MB are now reported.
- **Sensitive columns missed / over-matched.** Column matching is now by word: `customer_email`, `billingAddress`, `contact_phone` escalate to critical; `telemetry` and `cardinality` no longer do.
- **False positives on `/api/*`** when an API catch-all answers `200` JSON to any path: a second baseline under `/api/` detects it and skips those routes with an info note.
- Supabase `--supabase-url` passed alone (from the CLI) now fails with exit `2` instead of a silent info; the message says which value came from a flag or an env var.
- **A blocked or non-existent site looked like a pass.** A `403` bot challenge (Vercel Firewall / Cloudflare) or a `404 DEPLOYMENT_NOT_FOUND` had its error page's headers evaluated and exited `0`. Any non-2xx main page is now `error` (exit `2`) with an explanation; an explicitly requested Supabase check still runs.
- **Schema listing with publishable keys.** Supabase now answers `401 "Secret API key required"` to anon/publishable keys; rlscan said the key might be wrong. It now explains it and falls back to the tables the site's code queries (`/rest/v1/<table>`, `.from('<table>')`).
- Tables that don't exist (`404`, `PGRST205`) are reported as info "no existen" instead of medium "could not be evaluated".

### Added
- **Supabase auto-detection:** the project URL and public anon/publishable key are read from the site's own bundles and RLS is checked without flags (`--no-supabase-autodetect` to disable). Failures in this mode are `medium`, never `error`.
- **Public source maps:** detected (including `hidden-source-map` uploads) and their original source is scanned for secrets.
- New secret formats: database connection strings with password, Google OAuth client secret (`GOCSPX-`), Resend, Mailgun, Twilio API key SID.
- Supabase Storage: buckets an anonymous caller can list, and buckets whose files it can enumerate (private ones are `high`).
- Supabase RPC functions visible to `anon` are listed (never invoked).
- `SUPABASE_URL` / `SUPABASE_ANON_KEY` environment variables.
- When there are more than 50 tables, those with sensitive names are probed first.

### Changed
- Missing CSP is now **medium** (was high): it made `--fail-on-high` fail on almost every site.
- Firebase is no longer advertised as supported (only Firebase web API keys are reported); Firestore/RTDB rules remain on the roadmap.
- Node.js 20+ required; CI runs on Node 20/22/24.

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
