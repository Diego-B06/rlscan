# rlscan

A free, read-only security scanner for apps on **Vercel + Supabase/Firebase** —
the stack most startups and indie hackers actually ship on, and the one most
SMB-focused security tools (built around Windows endpoints and Microsoft 365)
don't cover at all.

```bash
npx rlscan https://your-app.vercel.app
```

Runs in seconds. No signup, no agent to install, no credentials beyond the
public anon key you already ship to the browser.

## What it checks

- **Missing HTTP security headers** — CSP, HSTS (HTTPS only), X-Frame-Options
  (or CSP `frame-ancestors`), X-Content-Type-Options, Referrer-Policy.
- **Leaked secrets in shipped JS** — AWS keys, Stripe live/restricted keys,
  Supabase `service_role` JWTs and `sb_secret_` keys, GitHub / Slack / SendGrid
  tokens, Anthropic and OpenAI keys, private key blocks. It follows chunks that
  are lazy-loaded (`import()`, Next.js/Vite build output) up to 3 levels deep.
  A `service_role` key in client code is always critical: it bypasses Row Level
  Security entirely.
- **Tables exposed by misconfigured Row Level Security** (optional, needs
  `--supabase-url` + `--supabase-anon-key`) — reads one row per table through
  PostgREST using only the public anon key and flags tables that return rows to
  an anonymous caller. Column *names* are used to raise severity; values are
  never printed.
- **Common deployment mistakes** — `.env`, `.git/config`, `wp-config.php`, debug/admin
  routes. Findings are validated by **content** and compared against a
  non-existent path, so SPAs that answer `200` to everything don't produce false alarms.

## Usage

```bash
# Basic scan — headers, leaked secrets, common exposed routes
npx rlscan https://your-app.vercel.app

# Also check Supabase RLS exposure
npx rlscan https://your-app.vercel.app \
  --supabase-url https://yourproject.supabase.co \
  --supabase-anon-key eyJhbGciOi...

# If your project doesn't expose its schema to anon, name the tables yourself
npx rlscan https://your-app.vercel.app \
  --supabase-url https://yourproject.supabase.co \
  --supabase-anon-key eyJhbGciOi... \
  --supabase-tables profiles,orders,invoices

# JSON output, for scripting
npx rlscan https://your-app.vercel.app --json

# CI mode: exit 1 if anything CRITICAL or HIGH is found
npx rlscan https://your-app.vercel.app --fail-on-high
```

Or install it globally: `npm install -g rlscan`.

Never pass a `service_role` / `sb_secret_` key — `rlscan` refuses it. Use the
anon / publishable key your frontend already ships.

### Options

| Flag | Meaning |
|---|---|
| `--supabase-url`, `--supabase-anon-key` | Enable the RLS check (both required) |
| `--supabase-tables a,b,c` | Probe these tables instead of auto-listing |
| `--max-files <n>` | Max JS files scanned for secrets (default 80) |
| `--no-routes` | Skip the common-routes check |
| `--json` | Machine-readable output (`tool`, `version`, `target`, `summary`, `findings`) |
| `--no-color` | Plain output (also honors `NO_COLOR`; auto-off when piped) |
| `--fail-on-high` | Exit `1` on CRITICAL/HIGH findings |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, nothing blocking (or `--fail-on-high` not set) |
| `1` | `--fail-on-high` and at least one CRITICAL/HIGH finding |
| `2` | The scan could **not** be completed (unreachable site, timeout, invalid URL, rejected key) |

A scan that can't run is never reported as a pass. In CI, treat `2` as a failure.

> Output messages are currently in Spanish. English output is on the roadmap.

## Why this exists

Managed SOC / MDR platforms built for SMBs — Huntress, Blumira, Cynet, and
similar — are genuinely good, and genuinely built around **endpoints**:
laptops, Windows servers, Microsoft 365. A startup running entirely on
Vercel and Supabase has basically none of that. Its real attack surface is
API abuse, bad RLS policies, and secrets baked into a JS bundle — and
nothing in that SMB-security category looks at any of it.

`rlscan` is a narrow, free, open-source wedge into that specific gap.
It's intentionally not a full SOC — it's the thing you run before you ever
need one, to find the obvious stuff first.

## ⚠️ Only scan what you're authorized to test

Every check here is read-only and non-destructive — it reads public HTTP
responses and public JS bundles, and queries Supabase using the same public
anon key your own frontend already exposes to every visitor. It does not
exploit anything, modify data, or require privileged credentials.

That said: **only run this against applications you own or have explicit
permission to test.** Scanning someone else's deployment without
authorization is not something this tool is meant to enable, and you're
responsible for how you use it.

## Limitations

- The RLS check is a heuristic: a table returning rows to an anon caller
  *might* be intentionally public (a blog's posts table). Review every finding.
- With only the anon key, a table protected by RLS and an **empty table without
  RLS** look identical (empty list). `rlscan` lists those tables as "cannot
  verify" — check them in the Supabase dashboard.
- If your project doesn't expose its schema to `anon`, the table list can't be
  built automatically; use `--supabase-tables`.
- The secrets scanner matches known key *formats* in same-origin JS. It won't
  catch unknown formats, secrets in third-party scripts, or chunk URLs that are
  computed at runtime and never appear as a string.
- Table severity uses table/column names, not the data itself.
- This is a free first pass, not a replacement for a real audit.

## Roadmap

- [ ] Firebase Security Rules exposure check (Firestore/RTDB)
- [ ] GitHub Action for running this on every deploy
- [ ] English output / i18n
- [ ] Optional authenticated mode (diff what an anon vs. a logged-in user can see)

## Contributing

Issues and PRs welcome — especially new secret-format patterns and
Firebase support. Keep every check read-only; that's the whole premise of
being safe to run against production.

## About

Built by [BARRSEC](https://barrsec.com.mx), an offensive-security
consultancy in Monterrey, México. If this tool finds something, we also do
deeper manual audits and ongoing monitoring (SOC Maddy) for teams that want
to go further.

## License

MIT
