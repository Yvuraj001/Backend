# emial code send service
# send reset email magic link
# send delete email verification code
# re-genearte verificatoin token
# Backend Build Roadmap (Express + MongoDB)

Build top to bottom. Each phase depends on the one before it.

## Phase 1 — Foundation (do first, blocks everything else)

- [ ] Project structure (routes/controllers/services/models folders)
- [ ] Env config for dev/staging/prod (`.env.development`, `.env.production`)
- [ ] Error handling middleware (single place that catches all errors)
- [ ] Logging (Winston)
- [ ] Input validation (Zod)

## Phase 2 — Security Core

- [ ] Auth: JWT access token + refresh token flow
- [ ] Role-based access control (user/admin middleware)
- [ ] Password hashing (bcrypt) — you already know this
- [ ] Secrets management (never commit `.env`)
- [ ] CORS config
- [ ] Rate limiting

## Phase 3 — Data Layer

- [ ] MongoDB connection with pooling (important for serverless/Vercel)
- [ ] Mongoose schemas + indexes
- [ ] Input sanitization (NoSQL injection prevention)

## Phase 4 — API Design

- [ ] Consistent REST structure + versioning (`/api/v1/...`)
- [ ] Pagination, filtering, sorting on list routes
- [ ] Standard response format (success/error shape)

## Phase 5 — Integrations

- [ ] File uploads → S3/Cloudinary (not local disk)
- [ ] Webhook handling (Razorpay) with signature verification
- [ ] API key rotation strategy for 3rd-party services

## Phase 6 — Reliability & Ops (do once core app works)

- [ ] Health check endpoint (`/health`)
- [ ] Sentry error monitoring
- [ ] Redis caching (only if you have hot/repeated reads)
- [ ] Automated tests (Jest + Supertest) — cover auth + payment flows first
- [ ] CI/CD (GitHub Actions: lint → test → deploy)

## Skip until you actually need them

- CSRF protection — only if you serve cookie-based sessions to a browser form. If you're doing JWT in headers (mobile/SPA style), it's not required. See explanation in chat.
- Full RPC-style API — REST is enough for most apps.

sk-f4c2d82bce474b5eb2b2a6c70213cd88
