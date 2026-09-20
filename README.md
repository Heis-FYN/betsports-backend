# BetSports Backend

Separate Flask + SQLite API service for the restored BetSports frontend. The service is intentionally independent from `/home/ubuntu/pulseline-sports` so the frontend can be connected to it later without coupling the two codebases.

## Run

```bash
cd /home/ubuntu/betsports-backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

The API listens on `0.0.0.0:5050` by default. Set `BETSPORTS_PORT` or `BETSPORTS_DB` in the process environment to override defaults.

## Core API areas

- `/health` and `/api/public/config`
- `/api/auth/register`, `/api/auth/login`, `/api/auth/me`, `/api/auth/logout`
- `/api/public/<sport>/matches/*` and `/api/<sport>/matches/*`
- `/api/bet-slip`, `/api/bets/place`, `/api/booking-codes`
- `/api/favourites`, `/api/promotions`, `/api/casino/games`, `/api/virtual/events`
- `/api/user/profile`, `/api/notifications`, `/api/help`

This is a demo-safe backend: betting endpoints persist selections and return simulated outcomes; they do not process payments or real money.
