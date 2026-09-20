# Go-live checklist

Everything here is built and tested against fakes. This is the list for the first time it meets the real
services. Work top to bottom; each step says what "working" looks like.

## 0. Accounts you need

| For | You need | Required? |
|---|---|---|
| Hosting | Railway (or similar) with Postgres | yes |
| Sign-in | a Clerk application | for accounts |
| Private repos | a GitHub OAuth App | optional |
| Billing | a Whop company, plans, an API key | optional |
| Errors | a Sentry project | recommended |

## 1. Deploy

1. Set the environment variables from `.env.example` (see step 2 for which ones each feature needs).
2. Start command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT` (the `Procfile` has it). Migrations run at startup.
3. Point the platform health check at **`/readyz`**. It is `503` until the database is reachable and migrated.
4. Optional, for scale: set `SCAN_WORKER_MODE=external` and run a second service with `python -m backend.worker`.
   If you forget the worker, scans stay `queued` and `/readyz` turns `503` after 5 minutes.

## 2. Configuration by feature

| Feature | Variables |
|---|---|
| Database | `DATABASE_URL` (Postgres) |
| CORS | `ALLOWED_ORIGINS` = your frontend origin(s) |
| AI text | `GEMINI_API_KEY` |
| Sign-in | `CLERK_JWKS_URL`, `CLERK_ISSUER`, `CLERK_AUTHORIZED_PARTIES` |
| Private repos | `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, `GITHUB_OAUTH_REDIRECT_URI`, `TOKEN_ENCRYPTION_KEY`, `FRONTEND_URL` |
| Billing | `WHOP_WEBHOOK_SECRET`, `WHOP_PLAN_MAP`, `WHOP_API_KEY` |
| Admin | `ADMIN_API_KEY` (24+ random characters) |
| Errors | `SENTRY_DSN` |

Leave `ENFORCE_PLAN_LIMITS` unset (or `0`) until billing is verified in step 5, so nobody is paywalled by accident.

## 3. Run the checker

With the same environment as the server (for example `railway run ...`):

```
python -m backend.setup_check --live --api https://YOUR-API --sentry-test
```

Fix every `FAIL`. It never prints secrets and exits `1` if anything fails, so it can gate a deploy.
`--live` only makes read-only calls (it lists checkouts to test the Whop key; it creates nothing).

## 4. Verify each integration

**Sign-in (Clerk).** With a real session token in `$TOKEN`:
`curl -H "Authorization: Bearer $TOKEN" https://YOUR-API/me` should return your user, `"plan": "free"`.
A wrong or expired token must return `401`, never an anonymous response.

**GitHub private repos.**
1. Create the OAuth App (GitHub → Settings → Developer settings → OAuth Apps). Its callback URL must equal
   `GITHUB_OAUTH_REDIRECT_URI` exactly.
2. `curl -H "Authorization: Bearer $TOKEN" https://YOUR-API/integrations/github/authorize` returns `{"url": ...}`.
   Open it in a browser and approve.
3. `GET /integrations/github` now shows `"connected": true`.
4. Scan one of your private repos. With `ENFORCE_PLAN_LIMITS=1` this needs a Pro plan.
5. Disconnect (`DELETE /integrations/github`) and confirm the grant disappears from your GitHub settings.
   GitHub OAuth Apps can only read private repos with the broad `repo` scope, so tell users that plainly.

**Whop billing.**
1. In Whop, create your plans and note each `plan_...` id. Put them in `WHOP_PLAN_MAP`, for example
   `{"plan_abc":"pro","plan_def":"team"}`. Checkout only works with `plan_` ids.
2. Create an API key that is allowed to create checkout configurations, and set `WHOP_API_KEY`.
3. Create the webhook (Developer → Webhooks → Create webhook): your endpoint
   `https://YOUR-API/webhooks/whop`, API version `v1`, events `membership.activated`, `membership.deactivated`
   and `membership.cancel_at_period_end_changed`. Copy the `ws_...` secret into `WHOP_WEBHOOK_SECRET`.
4. `curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"plan":"pro"}' https://YOUR-API/billing/checkout`
   returns a checkout `url`. Buy the cheapest option yourself (refund it afterwards).
5. Expect: the delivery shows `200` in Whop's webhook log, and `GET /me` now says `"plan": "pro"`.
6. Cancel the membership in Whop: access continues until the paid period ends, then `GET /me` returns `free`.

If a delivery fails with `401`, the secret does not match. If `/me` stays `free` after a `200`, check the delivery
body for `"ignored"`: the reason is in that field (most often the plan id is missing from `WHOP_PLAN_MAP`).
Whop retries for about 71 hours and disables a webhook that keeps failing for 72, so watch the first deliveries.

I could not test this against Whop itself. The signature scheme was taken from Whop's SDK and cross-checked against
the reference library, and checkout metadata is documented to be copied onto the membership, but the first real
purchase is the real test.

**Sentry.** `--sentry-test` sends one message; find it in the project. Then trigger a real failure (scan an
unreachable repo URL you own) and confirm it appears.

**GitHub push webhook (re-scan on push).** Repo → Settings → Webhooks: payload URL
`https://YOUR-API/webhooks/github`, content type `application/json`, secret = `GITHUB_WEBHOOK_SECRET`, "push" events.
Push to the default branch of a repo that was scanned: the scan re-runs.

## 5. Turn billing on

Only after step 4 works end to end: set `ENFORCE_PLAN_LIMITS=1`. Free accounts then get 5 scans a month, no re-scan
on push and no private repos. Grant yourself or testers a complimentary plan with the admin API rather than
editing the database (see the README).

## 6. If something goes wrong

- **Turn a feature off** by unsetting its variables (billing, GitHub connect, admin and sign-in all disable cleanly).
- **Stop paywalling** by setting `ENFORCE_PLAN_LIMITS=0`.
- **A stuck queue**: `/readyz` says so; start a worker or set `SCAN_WORKER_MODE=inline`.
- **Someone abusing scans**: lower `SCAN_RATE_LIMIT_PER_HOUR` or `DAILY_SCAN_CAP`.

## Not covered here

The frontend (sign-in, team pages, GitHub connect, delete buttons, checkout) is a separate task, and the AI agents need
a real `GEMINI_API_KEY` and valid model ids. Invites for people who have not signed up yet, and making the
server-wide `GITHUB_TOKEN` opt-in, are deliberately still pending.
