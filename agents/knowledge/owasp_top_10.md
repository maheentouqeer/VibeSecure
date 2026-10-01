# OWASP Core Vulnerability Categories & Standards

## A01:2021 — Broken Access Control
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.
- **Common Flaws**:
  - Missing authorization checks on API routes or server actions.
  - Relying solely on client-side routing guards without validating permissions on database or backend operations.
  - Missing database Row-Level Security (RLS) on multi-tenant architectures.
- **Remediation Standard**:
  - Deny access by default.
  - Implement access control mechanisms once and re-use them throughout the application.
  - Enforce record ownership in the database layer or backend service layer.

## A02:2021 — Cryptographic Failures & Hardcoded Secrets
Hardcoding secrets, API tokens, database connection strings, or private keys directly in source code exposes credentials to anyone who has access to the codebase or build artifacts.
  - Embedding provider secret keys, cloud credentials, or private service tokens
- **Remediation Standard**:
  - Remove all hardcoded tokens from git history and code immediately.
  - Rotate any exposed credentials immediately upon discovery.
  - Store secrets exclusively in platform secret managers (e.g., Supabase Vault, Replit Secrets, AWS Secrets Manager, Vercel Environment Variables).
  - Use runtime environment variables on the server; never prefix private secrets with `NEXT_PUBLIC_` or `VITE_`.

## A05:2021 — Security Misconfiguration (CORS, Exposed Files, Headers)
Security misconfigurations occur when security controls are inaccurately configured or left as default values.
- **Cross-Origin Resource Sharing (CORS)**:
  - Wildcard CORS (`origin: '*'`) allows any malicious website loaded in a user's browser to send requests and read responses from your application's API.
  - Remediation: Specify exact trusted domain origins (`origin: ['https://myapp.com']`) and disallow wildcard origins when credentials/cookies are exchanged.
- **Exposed Sensitive Files**:
  - Serving configuration files (`.env`, `.git`, `.replit`, `schema.sql`) publicly allows reconnaissance and credential harvesting.
  - Remediation: Prevent public web servers from routing requests to sensitive files; verify `.gitignore` covers local environment files.
- **Missing Defensive Headers**:
  - Omitting security headers leaves modern browsers unable to protect visitors against clickjacking and MIME-type confusion attacks.
  - Remediation: Configure `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Strict-Transport-Security`.
