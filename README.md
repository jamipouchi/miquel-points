# miquel-points

React SPA + Hono API deployed on Cloudflare Workers for `points.miquelpuigturon.com`.

## Product behavior

- Public user signup with:
  - `username`
  - `password`
  - `description` (1-2 lines)
- Login is blocked until user is manually verified in D1 (`verified = 1`).
- Session-based auth with HttpOnly cookie (`points_session`).
- Authenticated users can view:
  - current total points (`SUM(delta)`)
  - append-only points history

## Stack

- React + Vite
- Hono (Worker API)
- Cloudflare Workers
- Cloudflare D1

## Local setup

1. Install dependencies:

```bash
npm install
```

2. Create D1 database:

```bash
wrangler d1 create miquel-points
```

3. Update `/Users/miquel/Documents/points/miquel-points/wrangler.json`:

- Replace `database_id` with your real D1 id
- Replace `namespace_id` values for rate limiters

4. Set password pepper secret:

```bash
wrangler secret put PASSWORD_PEPPER
```

5. Apply migrations:

```bash
wrangler d1 migrations apply miquel-points
```

## Development

```bash
npm run dev
```

## Build and deploy

```bash
npm run build
npm run deploy
```

Production route is configured as:

- `points.miquelpuigturon.com/*`

## API

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/points?cursor=<token>&limit=<n>`

## D1 schema

Migration file:

- `/Users/miquel/Documents/points/miquel-points/migrations/0001_initial.sql`

Includes:

- `users`
- `sessions`
- `points` (append-only via update/delete abort triggers)

## Manual operations

Verify a user:

```sql
UPDATE users
SET verified = 1,
    verified_at = CURRENT_TIMESTAMP
WHERE username = ?;
```

Add points entry:

```sql
INSERT INTO points (id, user_id, delta, reason, created_by)
VALUES (?, ?, ?, ?, 'manual');
```
