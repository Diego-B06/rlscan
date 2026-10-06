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

- **Missing HTTP security headers** — CSP, HSTS, X-Frame-Options, and friends.
- **Leaked secrets in shipped JS bundles** — AWS keys, Stripe live keys,
  GitHub tokens, Slack tokens, private key blocks, and Supabase
  `service_role` JWTs that accidentally made it into client code (that key
  bypasses Row Level Security entirely — finding one is a critical finding,
  full stop).
- **Tables exposed by misconfigured Row Level Security** (optional, needs
  `--supabase-url` + `--supabase-anon-key`) — probes each table your
  project exposes via PostgREST using only the public anon key, the same
  one your frontend already uses, and flags tables that return rows to an
  anonymous caller.
- **Common deployment mistakes** — `.env` files, `.git/config`, debug/admin
  routes left reachable in production.

## Usage

```bash
# Basic scan — headers, leaked secrets, common exposed routes
npx rlscan https://your-app.vercel.app

# Also check Supabase RLS exposure
npx rlscan https://your-app.vercel.app \
  --supabase-url https://yourproject.supabase.co \
  --supabase-anon-key eyJhbGciOi...

# JSON output, for scripting
npx rlscan https://your-app.vercel.app --json

# CI mode: exit 1 if anything CRITICAL or HIGH is found
npx rlscan https://your-app.vercel.app --fail-on-high
```

Or install it globally:

```bash
npm install -g rlscan
rlscan https://your-app.vercel.app
```

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
  *might* be intentionally public (a blog's posts table, say). Review every
  finding — don't assume every flagged table is a bug.
- The secrets scanner matches known key *formats* (AWS, Stripe, GitHub,
  Slack, SendGrid, Supabase service-role JWTs, PEM key blocks). It won't
  catch a secret in a format it doesn't recognize.
- It scans up to the first 15 `<script src>` bundles the page loads and
  caps each fetch at 5MB — built to be fast, not exhaustive.
- This is not a replacement for a real audit. It's a free first pass.

## Roadmap

- [ ] Firebase Security Rules exposure check (Firestore/RTDB)
- [ ] GitHub Action for running this on every deploy
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
