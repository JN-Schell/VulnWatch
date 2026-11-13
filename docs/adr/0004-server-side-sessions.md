# 0004 — Server-side sessions with CSRF and Origin checks

- **Status:** Accepted
- **Date:** 2026-11-13

## Context

The browser application needs authenticated access to a same-origin API. Tokens stored in browser storage are exposed to cross-site scripting, and stateless JWTs are difficult to revoke immediately. The application also needs role-based authorization and auditable session invalidation.

## Decision

Authenticate with an opaque random session token stored in an HttpOnly, SameSite=Strict cookie scoped to `/api`. Store only a SHA-256 digest of the token in PostgreSQL, with an absolute expiry. Sessions are revoked on logout, account disable, and password reset.

State-changing requests require a per-session CSRF token in `X-CSRF-Token` and an exact trusted `Origin` header. Passwords use Argon2 through `pwdlib`. Authorization is enforced server-side through permission dependencies.

Production cookies are `Secure`; production configuration rejects non-HTTPS trusted origins.

## Consequences

- Sessions can be revoked immediately and are not readable by JavaScript.
- CSRF and Origin checks reduce cross-site request risk without exposing tokens to browser storage.
- The API remains same-origin; third-party browser clients would need a separately designed authentication flow.
- SSO, MFA, device/session inventory, and password self-service are future work and must not be claimed as present.
- Reverse proxies must preserve the original host and scheme configuration for correct origin and cookie behavior.
