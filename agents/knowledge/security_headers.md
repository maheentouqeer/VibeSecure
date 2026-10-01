# HTTP Security Headers Reference Standard

Source: OWASP Secure Headers Project, https://owasp.org/www-project-secure-headers/.
Last reviewed: 2026-10-01.

## Essential Defensive Headers

### 1. X-Frame-Options
- **Purpose**: Prevents Clickjacking attacks by forbidding the page from being embedded in an `<iframe>` on malicious sites.
- **Recommended Value**: `DENY` or `SAMEORIGIN`.

### 2. X-Content-Type-Options
- **Purpose**: Prevents MIME-sniffing vulnerabilities where the browser might execute user-uploaded files as scripts or styles.
- **Recommended Value**: `nosniff`.

### 3. Strict-Transport-Security (HSTS)
- **Purpose**: Enforces all future connections to the domain to occur strictly over HTTPS.
- **Recommended Value**: `max-age=31536000; includeSubDomains; preload`.

### 4. Content-Security-Policy (CSP)
- **Purpose**: Restricts the sources of executable scripts, stylesheets, images, and network connections to mitigate XSS and data exfiltration.
- **Recommended Baseline**: `default-src 'self'; script-src 'self'; object-src 'none';`.

## Configuration Examples

### Next.js (`next.config.js`)
```javascript
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ];
  },
};
```
