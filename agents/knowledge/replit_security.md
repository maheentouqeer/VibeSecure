# Replit Platform Security & Hardening Reference

Source: Replit Secrets documentation, https://docs.replit.com/replit-workspace/workspace-features/secrets.
Last reviewed: 2026-10-01.

## Secrets Management in Replit
Replit environments run in cloud containers and are frequently shared, forked, or deployed to public URLs.

### Critical Rule: Do Not Store Secrets in Files
- Never hardcode API keys or credentials in source files (`index.js`, `main.py`, `config.json`).
- Never commit `.env` files with secret values in public Repls or git repositories.
- Use Replit Secrets (Tools > Secrets / Environment variables tool):
  - In Node.js: Read from `process.env.SECRET_NAME`.
  - In Python: Read from `os.environ.get("SECRET_NAME")`.
  - Replit automatically encrypts these values and injects them only into your running container environment, preventing them from being visible to viewers or forks.

## Public Static File Serving in Replit
- Files placed in public web directories (e.g. `public/`, `static/`, or the root directory if a static server like `express.static('.')` is used) are served verbatim over HTTP.
- Ensure sensitive configuration files like `.replit`, `replit.nix`, `.env`, and private assets are explicitly excluded from static middleware routes.

## CORS & Endpoint Protection
- By default, deployed Repl web applications on `.replit.app` or custom domains should restrict CORS:
  ```javascript
  app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'https://my-repl-app.replit.app',
    credentials: true
  }));
  ```
- Avoid `cors({ origin: '*' })` on any endpoint handling user data or authenticated operations.
