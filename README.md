# BetSports Backend

Flask API service for the MAXWIN frontend. Production is intended to run against Neon Postgres; local SQLite is available only for explicitly configured development environments.

## Production configuration

Set these environment variables in the backend hosting service before starting the application:

```bash
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DBNAME?sslmode=require
BETSPORTS_REQUIRE_POSTGRES=true
BETSPORTS_ALLOWED_ORIGINS=https://betsports-frontend-netlify.netlify.app
BETSPORTS_ADMIN_EMAIL=your-admin@example.com
BETSPORTS_ADMIN_INITIAL_PASSWORD=use-a-unique-one-time-password
```

`BETSPORTS_ADMIN_INITIAL_PASSWORD` has no unsafe fallback. The service fails fast when the production database or bootstrap administrator credentials are missing. Use a unique one-time value, sign in through the admin console, and change it immediately.

After deployment, verify `/health` reports `"database":"neon-postgres"` and run a read-only check against the intended Neon `production` branch.

## Local run

```bash
cd /home/ubuntu/betsports-backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export BETSPORTS_ADMIN_EMAIL=local-admin@example.com
export BETSPORTS_ADMIN_INITIAL_PASSWORD='local-development-password'
python app.py
```

The API listens on `0.0.0.0:5050` by default. Set `BETSPORTS_PORT` or `BETSPORTS_DB` to override local defaults. For production, set `BETSPORTS_REQUIRE_POSTGRES=true` so accidental SQLite startup is impossible.

## Core API areas

- `/health` and `/api/public/config`
- `/api/auth/register`, `/api/auth/login`, `/api/auth/me`, `/api/auth/logout`
- `/api/public/<sport>/matches/*` and `/api/<sport>/matches/*`
- `/api/bet-slip`, `/api/bets/place`, `/api/booking-codes`
- `/api/favourites`, `/api/promotions`, `/api/casino/games`, `/api/virtual/events`
- `/api/user/profile`, `/api/notifications`, `/api/help`
- `/api/admin/*` for protected administrator operations

This is a demo-safe backend: betting endpoints persist selections and return simulated outcomes; they do not process payments or real money.

Wallet deposits, withdrawals, and administrator approval of wallet requests are disabled by default. They return HTTP 503 with the `payment_gateway_disabled` code until a verified provider is configured and `BETSPORTS_PAYMENTS_ENABLED=true` is explicitly set in the production environment.
