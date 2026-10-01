# Bolt.new & v0 (Next.js / Vite) Platform Security Reference

Source: Next.js and Vite environment variable documentation.
Last reviewed: 2026-10-01.

## Client vs. Server Secrets in Modern Frontend Frameworks
Bolt.new and v0 generate full-stack applications typically using Next.js (App Router or Pages Router) or Vite + React.

### Environment Variable Leak Prevention:
1. **Public vs Private Prefixes**:
   - `NEXT_PUBLIC_*` (Next.js) and `VITE_*` (Vite) variables are embedded directly into public client JavaScript bundles at build time.
   - Anyone visiting the site can extract these variables from bundle files.
  - Never prefix database passwords, payment-provider secrets, API keys, or private service tokens with `NEXT_PUBLIC_` or `VITE_`.
2. **Server-Only Secrets**:
   - Private secrets must omit public prefixes (e.g. `DATABASE_URL`, `STRIPE_SECRET_KEY`) and must ONLY be referenced in server-side files (Server Components, Route Handlers `app/api/.../route.ts`, or Server Actions `'use server'`).
   - In Next.js, importing `import 'server-only'` ensures client components fail to build if they accidentally import server secrets.

## Server Action & Route Authorization
- In Bolt/v0 apps, Server Actions can be invoked directly via HTTP POST requests without going through frontend UI buttons or client state.
- Always authenticate the user session (`const session = await auth()`) inside the server action or route handler before performing database mutations.

## CORS Configuration in Next.js / Vite
- In Next.js Route Handlers:
  ```typescript
  export async function OPTIONS() {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': process.env.NEXT_PUBLIC_APP_URL || 'https://my-app.vercel.app',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }
  ```
- Do not return wildcard `'*'` headers when handling session cookies or Authorization headers.
