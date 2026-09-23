import hashlib
import json
import os
import secrets
import sqlite3
import threading
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # Local SQLite-only installs do not need the production driver.
    psycopg = None
    dict_row = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("BETSPORTS_DB", BASE_DIR / "betsports.db"))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
PORT = int(os.getenv("BETSPORTS_PORT", "5050"))
HOST = os.getenv("BETSPORTS_HOST", "0.0.0.0")
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("BETSPORTS_ALLOWED_ORIGINS", "https://betsports-frontend-netlify.netlify.app,http://localhost:5173").split(",") if origin.strip()]
REQUIRE_POSTGRES = os.getenv("BETSPORTS_REQUIRE_POSTGRES", "false").strip().lower() in {"1", "true", "yes", "on"}
PAYMENTS_ENABLED = os.getenv("BETSPORTS_PAYMENTS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def payment_gateway_disabled():
    return json_error(
        "Deposits and withdrawals are temporarily unavailable because no payment gateway is active.",
        503,
        "payment_gateway_disabled",
    )


class DatabaseAdapter:
    def __init__(self, connection, postgres=False):
        self.connection = connection
        self.postgres = postgres

    def execute(self, query, params=()):
        if self.postgres:
            query = query.replace("?", "%s")
        return self.connection.execute(query, params)

    def commit(self):
        return self.connection.commit()

    def close(self):
        return self.connection.close()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)

SPORTS = ["football", "basketball", "cricket", "tennis", "rugby", "baseball", "icehockey", "volleyball", "ufc", "mma", "golf", "motorsports", "soccer"]

# Backend-only catalog. Public responses contain only normalized match fields.
ESPN_LEAGUE_CATALOG = {
    "football": ["nfl", "college-football", "cfl", "ufl"],
    "basketball": ["nba", "wnba", "mens-college-basketball", "womens-college-basketball"],
    "baseball": ["mlb", "college-baseball"],
    "icehockey": ["nhl", "mens-college-hockey"],
    "soccer": ["eng.1", "esp.1", "ger.1", "ita.1", "fra.1", "uefa.champions", "uefa.europa", "usa.1", "mex.1"],
    "tennis": ["atp", "wta"],
    "golf": ["pga", "lpga"],
    "motorsports": ["f1"],
    "rugby": ["rugby"],
    "cricket": ["international"],
    "volleyball": ["fivb"],
    "ufc": ["ufc"],
}
ESPN_SPORT_PATH = {"icehockey": "hockey", "motorsports": "racing", "ufc": "mma", "mma": "mma"}
ESPN_CACHE_SECONDS = int(os.getenv("ESPN_CACHE_SECONDS", "300"))
ESPN_TIMEOUT_SECONDS = float(os.getenv("ESPN_TIMEOUT_SECONDS", "8"))
_espn_cache = {}
_espn_cache_lock = threading.Lock()


# Supabase-compatible bridge for the existing static frontend.
# It lets the imported UI use this separate Flask/SQLite service without a hosted Supabase dependency.
def _supabase_user(user):
    if not user:
        return None
    name = (user["name"] or "").strip()
    parts = name.split(" ", 1)
    return {
        "id": str(user["id"]),
        "aud": "authenticated",
        "role": "authenticated",
        "email": user["email"],
        "phone": user["phone"] or "",
        "email_confirmed_at": user["created_at"],
        "created_at": user["created_at"],
        "updated_at": user["created_at"],
        "user_metadata": {"first_name": parts[0] if parts else "", "last_name": parts[1] if len(parts) > 1 else "", "phone": user["phone"] or ""},
        "app_metadata": {"provider": "email", "providers": ["email"], "role": (user["role"] or "USER").lower()},
    }

def _supabase_session(user):
    token = secrets.token_urlsafe(32)
    db().execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user["id"], utc_now()))
    db().commit()
    return {"access_token": token, "refresh_token": token, "token_type": "bearer", "expires_in": 31536000, "expires_at": int(datetime.now(timezone.utc).timestamp()) + 31536000, "user": _supabase_user(user)}

def _auth_user_from_request():
    return current_user()

@app.post("/auth/v1/signup")
def supabase_signup():
    body = request.get_json(silent=True) or {}
    options = body.get("options") or {}
    metadata = options.get("data") or {}
    email = str(body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    if not email or len(password) < 6:
        return jsonify({"error": "invalid_credentials", "error_description": "A valid email and password of at least 6 characters are required."}), 400
    existing = db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify({"code": "user_already_exists", "msg": "User already registered"}), 422
    name = " ".join(filter(None, [str(metadata.get("first_name") or "").strip(), str(metadata.get("last_name") or "").strip()])) or email.split("@", 1)[0]
    connection = db()
    connection.execute("INSERT INTO users (name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)", (name, email, metadata.get("phone"), generate_password_hash(password), utc_now()))
    connection.commit()
    user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return jsonify(_supabase_session(user)), 200

@app.post("/auth/v1/token")
def supabase_token():
    body = request.get_json(silent=True) or {}
    grant = body.get("grant_type")
    if grant == "refresh_token":
        token = body.get("refresh_token") or ""
        user = db().execute("SELECT u.* FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.token = ?", (token,)).fetchone()
        if user:
            return jsonify(_supabase_session(user))
    email = str(body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    user = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid_grant", "error_description": "Invalid login credentials"}), 400
    return jsonify(_supabase_session(user))

@app.get("/auth/v1/user")
def supabase_user():
    user = _auth_user_from_request()
    if not user:
        return jsonify({"error": "invalid_token", "error_description": "User not found"}), 401
    return jsonify(_supabase_user(user))

@app.post("/auth/v1/logout")
def supabase_logout():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    if token:
        db().execute("DELETE FROM sessions WHERE token = ?", (token,))
        db().commit()
    return ("", 204)

def _frontend_profile(user):
    profile = _supabase_user(user)
    metadata = profile["user_metadata"]
    return {"id": str(user["id"]), "email": user["email"], "first_name": metadata.get("first_name", ""), "last_name": metadata.get("last_name", ""), "phone": user["phone"] or "", "role": user["role"] or "USER", "country": "GH", "currency": "GHS", "balance": float(user["balance"] or 0), "kyc_status": "verified", "created_at": user["created_at"], "updated_at": user["created_at"]}

def _rest_rows(table):
    user = _auth_user_from_request()
    if table == "profiles":
        return [_frontend_profile(user)] if user else []
    if table == "matches":
        rows = []
        for sport in SPORTS:
            for state in ("live", "upcoming"):
                for match in matches_for(sport, state):
                    rows.append({"id": match["id"], "sport": sport, "league": match["league"], "home_team": match["homeTeam"]["name"], "away_team": match["awayTeam"]["name"], "home_team_id": match["homeTeam"]["id"], "away_team_id": match["awayTeam"]["id"], "status": match["status"], "is_live": match["isLive"], "start_time": match["startTime"], "home_odds": match["odds"]["home"], "draw_odds": match["odds"]["draw"], "away_odds": match["odds"]["away"], "home_score": match["score"]["home"], "away_score": match["score"]["away"]})
        return rows
    if table == "promotions":
        return [{"id": "welcome-200", "title": "Welcome bonus", "description": "Up to 200% extra on your first qualifying slip", "active": True}, {"id": "weekly-500", "title": "Weekly accumulator", "description": "Boosted returns on selected accumulators", "active": True}]
    if table in {"settings", "banners", "leagues", "teams", "markets", "market_selections", "bet_selections", "transactions", "wallet_transactions", "withdrawal_requests", "support_tickets", "flutterwave_accounts", "sub_admin_invites", "sub_admin_payouts", "admin_platform_metrics_summary"}:
        return []
    if table == "bets" and user:
        rows = db().execute("SELECT * FROM bets WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
        return [dict(row) for row in rows]
    if table == "booking_codes" and user:
        rows = db().execute("SELECT booking_code AS code, booking_code, total_odds, stake, status, created_at FROM bets WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
        return [dict(row) for row in rows]
    return []

def _apply_rest_filters(rows):
    for key, values in request.args.items(multi=True):
        if key in {"select", "order", "limit", "offset"}:
            continue
        if "=" in values:
            op, value = values.split("=", 1)
            if op == "eq": rows = [r for r in rows if str(r.get(key, "")) == value]
            elif op == "neq": rows = [r for r in rows if str(r.get(key, "")) != value]
            elif op == "in": rows = [r for r in rows if str(r.get(key, "")) in value.strip("()").split(",")]
    order = request.args.get("order")
    if order:
        key, _, direction = order.partition(".")
        rows = sorted(rows, key=lambda r: str(r.get(key, "")), reverse=direction == "desc")
    try:
        offset = int(request.args.get("offset", 0)); limit = request.args.get("limit")
        rows = rows[offset: offset + int(limit) if limit else None]
    except ValueError:
        pass
    return rows

@app.route("/rest/v1/<table>", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
def supabase_rest(table):
    rows = _apply_rest_filters(_rest_rows(table))
    if request.method == "GET":
        if request.headers.get("Accept") == "application/vnd.pgrst.object+json" or request.args.get("select") and request.args.get("limit") == "1":
            return (jsonify(rows[0]) if rows else jsonify({"code": "PGRST116", "message": "JSON object requested, multiple (or no) rows returned"})), (200 if rows else 406)
        response = jsonify(rows)
        response.headers["Content-Range"] = f"0-{max(len(rows)-1, 0)}/*"
        return response
    # Public frontend writes are mapped to the first-party API where possible.
    if table == "profiles" and request.method in {"PATCH", "PUT"} and current_user():
        body = request.get_json(silent=True) or {}
        db().execute("UPDATE users SET name = ?, phone = ? WHERE id = ?", (body.get("full_name") or body.get("name") or current_user()["name"], body.get("phone", current_user()["phone"]), current_user()["id"]))
        db().commit()
        return jsonify([_frontend_profile(current_user())])
    return jsonify([]), 201 if request.method in {"POST", "PUT", "PATCH"} else 204


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def db():
    if "db" not in g:
        if DATABASE_URL:
            if psycopg is None:
                raise RuntimeError("DATABASE_URL is configured but psycopg is not installed")
            g.db = DatabaseAdapter(psycopg.connect(DATABASE_URL, row_factory=dict_row), postgres=True)
        else:
            connection = sqlite3.connect(DB_PATH)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            g.db = DatabaseAdapter(connection)
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    if REQUIRE_POSTGRES and not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is required when BETSPORTS_REQUIRE_POSTGRES is enabled")
    admin_email_raw = os.getenv("BETSPORTS_ADMIN_EMAIL", "").strip()
    admin_password = os.getenv("BETSPORTS_ADMIN_INITIAL_PASSWORD", "")
    if not admin_email_raw or not admin_password:
        raise RuntimeError("BETSPORTS_ADMIN_EMAIL and BETSPORTS_ADMIN_INITIAL_PASSWORD must be configured")
    admin_email = admin_email_raw.lower()
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("DATABASE_URL is configured but psycopg is not installed")
        connection = DatabaseAdapter(psycopg.connect(DATABASE_URL, row_factory=dict_row), postgres=True)
        admin = connection.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
        if admin is None:
            connection.execute("INSERT INTO users (name, email, password_hash, role, force_password_change, created_at) VALUES (?, ?, ?, 'SUPER_ADMIN', TRUE, ?)", ("MaxWin Administrator", admin_email, generate_password_hash(admin_password), utc_now()))
        else:
            connection.execute("UPDATE users SET role = 'SUPER_ADMIN' WHERE email = ?", (admin_email,))
        connection.commit()
        connection.close()
        return
    connection = sqlite3.connect(DB_PATH)
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            balance REAL NOT NULL DEFAULT 0,
            force_password_change INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bet_slips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            match_id TEXT NOT NULL,
            selection TEXT NOT NULL,
            odds REAL NOT NULL,
            stake REAL DEFAULT 0,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, match_id, selection)
        );
        CREATE TABLE IF NOT EXISTS bets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            booking_code TEXT NOT NULL,
            selections_json TEXT NOT NULL,
            total_odds REAL NOT NULL,
            stake REAL NOT NULL,
            possible_win REAL NOT NULL DEFAULT 0,
            payout REAL NOT NULL DEFAULT 0,
            result TEXT NOT NULL DEFAULT 'open',
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS favourites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            item_type TEXT NOT NULL,
            item_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, item_type, item_id)
        );
        CREATE TABLE IF NOT EXISTS matches (
            id TEXT PRIMARY KEY,
            sport TEXT NOT NULL,
            league TEXT NOT NULL,
            home_team TEXT NOT NULL,
            away_team TEXT NOT NULL,
            start_time TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'upcoming',
            home_odds REAL NOT NULL DEFAULT 1.5,
            draw_odds REAL NOT NULL DEFAULT 3.2,
            away_odds REAL NOT NULL DEFAULT 2.15,
            home_score INTEGER NOT NULL DEFAULT 0,
            away_score INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wallet_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_type TEXT NOT NULL CHECK(request_type IN ('deposit','withdrawal')),
            amount REAL NOT NULL CHECK(amount > 0),
            method TEXT NOT NULL DEFAULT 'manual',
            reference TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            note TEXT,
            reviewed_by INTEGER REFERENCES users(id),
            reviewed_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wallet_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_id INTEGER REFERENCES wallet_requests(id),
            amount REAL NOT NULL,
            balance_after REAL NOT NULL,
            entry_type TEXT NOT NULL,
            note TEXT,
            created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL REFERENCES users(id),
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details_json TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    # Backfill columns for databases created by earlier BetSports versions.
    existing_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)").fetchall()}
    for column, definition in (("role", "TEXT NOT NULL DEFAULT 'USER'"), ("balance", "REAL NOT NULL DEFAULT 0"), ("force_password_change", "INTEGER NOT NULL DEFAULT 0")):
        if column not in existing_columns:
            connection.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
    bet_columns = {row[1] for row in connection.execute("PRAGMA table_info(bets)").fetchall()}
    for column, definition in (("possible_win", "REAL NOT NULL DEFAULT 0"), ("payout", "REAL NOT NULL DEFAULT 0"), ("result", "TEXT NOT NULL DEFAULT 'open'")):
        if column not in bet_columns:
            connection.execute(f"ALTER TABLE bets ADD COLUMN {column} {definition}")
    admin = connection.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
    if admin is None:
        connection.execute("INSERT INTO users (name, email, password_hash, role, force_password_change, created_at) VALUES (?, ?, ?, 'SUPER_ADMIN', ?, ?)", ("MaxWin Administrator", admin_email, generate_password_hash(admin_password), True, utc_now()))
    else:
        connection.execute("UPDATE users SET role = 'SUPER_ADMIN' WHERE email = ?", (admin_email,))
    connection.commit()
    connection.close()


def json_error(message, status=400, code="bad_request"):
    return jsonify({"ok": False, "error": {"code": code, "message": message}}), status


def json_ok(data=None, **meta):
    payload = {"ok": True, "data": data}
    payload.update(meta)
    return jsonify(payload)


def row_to_dict(row):
    return dict(row) if row else None


def scalar(row):
    if row is None:
        return None
    return row[0] if not isinstance(row, dict) else next(iter(row.values()))


def current_user():
    token = request_token()
    if not token:
        return None
    return db().execute(
        "SELECT u.* FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.token = ?", (token,)
    ).fetchone()


def request_token():
    auth = request.headers.get("Authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else request.cookies.get("betsports_token")


def auth_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return json_error("Authentication required", 401, "unauthorized")
        g.user = user
        return handler(*args, **kwargs)

    return wrapped


def make_match(sport, index, state="upcoming"):
    names = {
        "football": [("Hercules", "Juventud Torremolinos"), ("Lecco", "Pergolettese"), ("Chelsea", "Arsenal")],
        "basketball": [("Phoenix", "Brooklyn"), ("Lakers", "Suns")],
        "cricket": [("New Zealand", "Australia"), ("India", "England")],
        "tennis": [("A. Shelton", "H. Rune"), ("I. Swiatek", "C. Gauff")],
        "rugby": [("Chiefs", "Blues"), ("Crusaders", "Brumbies")],
    }
    home, away = names.get(sport, [(f"{sport.title()} United", f"{sport.title()} City")])[index % len(names.get(sport, [("Home", "Away")]))]
    match_id = f"{sport}-{index + 1:03d}"
    return {
        "id": match_id,
        "sport": sport,
        "league": "Featured League",
        "homeTeam": {"id": f"{sport}-home-{index}", "name": home, "shortName": home[:3].upper()},
        "awayTeam": {"id": f"{sport}-away-{index}", "name": away, "shortName": away[:3].upper()},
        "startTime": "2026-09-21T20:00:00Z",
        "status": state,
        "score": {"home": 0 if state != "live" else index, "away": 0},
        "odds": {"home": round(1.55 + index * 0.11, 2), "draw": round(3.2 + index * 0.22, 2), "away": round(2.15 + index * 0.13, 2)},
        "isLive": state == "live",
        "featured": index == 0,
    }


def _espn_status(event):
    status = ((event.get("competitions") or [{}])[0].get("status") or event.get("status") or {})
    state = str(status.get("type", {}).get("state") or status.get("state") or "pre").lower()
    if state in {"post", "final", "completed"}: return "finished"
    if state in {"in", "live", "inprogress"}: return "live"
    if state in {"canceled", "cancelled", "suspended", "postponed"}: return "suspended"
    return "upcoming"


def _espn_number(value, fallback):
    try: return float(value)
    except (TypeError, ValueError): return fallback


def _espn_event_to_match(event, sport, league):
    competitions = event.get("competitions") or []
    competition = competitions[0] if competitions else {}
    competitors = competition.get("competitors") or []
    home = next((item for item in competitors if item.get("homeAway") == "home"), competitors[0] if competitors else {})
    away = next((item for item in competitors if item.get("homeAway") == "away"), competitors[1] if len(competitors) > 1 else {})
    home_team = home.get("team") or {}
    away_team = away.get("team") or {}
    event_id = str(event.get("id") or competition.get("id") or "")
    if not event_id or not home_team.get("displayName") or not away_team.get("displayName"):
        return None
    state = _espn_status(event)
    home_score = int(float(home.get("score") or 0)) if str(home.get("score") or "0").replace('.', '', 1).isdigit() else 0
    away_score = int(float(away.get("score") or 0)) if str(away.get("score") or "0").replace('.', '', 1).isdigit() else 0
    odds = {"home": 1.5, "draw": 3.2, "away": 2.15}
    event_odds = competition.get("odds") or []
    if event_odds:
        first = event_odds[0] or {}
        odds["home"] = _espn_number(first.get("homeTeamOdds", {}).get("moneyLine") or first.get("homeMoneyLine"), odds["home"])
        odds["away"] = _espn_number(first.get("awayTeamOdds", {}).get("moneyLine") or first.get("awayMoneyLine"), odds["away"])
    opaque_id = "m-" + hashlib.sha256(f"{sport}:{league}:{event_id}".encode()).hexdigest()[:20]
    return {
        "id": opaque_id, "sport": sport, "league": (event.get("league") or {}).get("name") or league,
        "homeTeam": {"id": str(home_team.get("id") or f"{event_id}-home"), "name": home_team.get("displayName"), "shortName": home_team.get("shortDisplayName") or home_team.get("abbreviation") or home_team.get("displayName", "Home")[:3].upper()},
        "awayTeam": {"id": str(away_team.get("id") or f"{event_id}-away"), "name": away_team.get("displayName"), "shortName": away_team.get("shortDisplayName") or away_team.get("abbreviation") or away_team.get("displayName", "Away")[:3].upper()},
        "startTime": event.get("date") or utc_now(), "status": state,
        "score": {"home": home_score, "away": away_score}, "odds": odds, "isLive": state == "live", "featured": False,
    }


def _fetch_espn_league(sport, league):
    url = f"https://site.api.espn.com/apis/site/v2/sports/{ESPN_SPORT_PATH.get(sport, sport)}/{league}/scoreboard"
    try:
        request = Request(url, headers={"User-Agent": "MaxWin match service/1.0", "Accept": "application/json"})
        with urlopen(request, timeout=ESPN_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return [_espn_event_to_match(event, sport, league) for event in payload.get("events", [])]
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return []


def _upsert_ingested_match(match):
    connection = db()
    existing = connection.execute("SELECT id FROM matches WHERE id = ?", (match["id"],)).fetchone()
    values = (match["sport"], match["league"], match["homeTeam"]["name"], match["awayTeam"]["name"], match["startTime"], match["status"], match["odds"]["home"], match["odds"]["draw"], match["odds"]["away"], match["score"]["home"], match["score"]["away"], utc_now())
    if existing:
        connection.execute("UPDATE matches SET sport = ?, league = ?, home_team = ?, away_team = ?, start_time = ?, status = ?, home_odds = ?, draw_odds = ?, away_odds = ?, home_score = ?, away_score = ?, updated_at = ? WHERE id = ?", (*values, match["id"]))
    else:
        connection.execute("INSERT INTO matches (id, sport, league, home_team, away_team, start_time, status, home_odds, draw_odds, away_odds, home_score, away_score, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (match["id"], *values[:-1], utc_now(), values[-1]))


def sync_espn_sport(sport, force=False):
    now = datetime.now(timezone.utc).timestamp()
    with _espn_cache_lock:
        cached = _espn_cache.get(sport)
        if not force and cached and now - cached < ESPN_CACHE_SECONDS:
            return
        _espn_cache[sport] = now
    leagues = ESPN_LEAGUE_CATALOG.get(sport, [])
    for league in leagues:
        for match in _fetch_espn_league(sport, league):
            if match:
                _upsert_ingested_match(match)
    db().commit()


def matches_for(sport, status="upcoming"):
    normalized = "live" if status in ("live", "in-play") else "upcoming"
    if sport in ESPN_LEAGUE_CATALOG:
        sync_espn_sport(sport)
    stored = db().execute("SELECT * FROM matches WHERE sport = ? AND status = ? ORDER BY start_time ASC LIMIT 300", (sport, normalized)).fetchall()
    if stored:
        return [stored_match_to_public(row) for row in stored]
    return [make_match(sport, i, normalized) for i in range(3)]


def stored_match_to_public(row):
    return {
        "id": row["id"], "sport": row["sport"], "league": row["league"],
        "homeTeam": {"id": f"{row['id']}-home", "name": row["home_team"], "shortName": row["home_team"][:3].upper()},
        "awayTeam": {"id": f"{row['id']}-away", "name": row["away_team"], "shortName": row["away_team"][:3].upper()},
        "startTime": row["start_time"], "status": row["status"],
        "score": {"home": row["home_score"], "away": row["away_score"]},
        "odds": {"home": row["home_odds"], "draw": row["draw_odds"], "away": row["away_odds"]},
        "isLive": row["status"] == "live", "featured": False,
    }


@app.get("/health")
def health():
    db().execute("SELECT 1").fetchone()
    return json_ok({"service": "betsports-backend", "status": "healthy", "time": utc_now(), "database": "neon-postgres" if DATABASE_URL else "sqlite"})


@app.get("/")
def backend_home():
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BetSports Backend</title>
<style>body{margin:0;background:#0b0d0c;color:#eef5f2;font:16px Arial,sans-serif;display:grid;min-height:100vh;place-items:center}.card{width:min(680px,calc(100% - 40px));padding:36px;border:1px solid #1e4b38;border-radius:20px;background:linear-gradient(145deg,#112119,#0f1412);box-shadow:0 24px 80px #0008}h1{margin:0 0 10px;font-size:34px;letter-spacing:-.04em}p{color:#9eb2a7;line-height:1.6}.pill{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;background:#123f2b;color:#4be58e;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.12em}.dot{width:8px;height:8px;border-radius:50%;background:#4be58e;box-shadow:0 0 12px #4be58e}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:24px}.item{padding:14px;border:1px solid #20332a;border-radius:12px;background:#101916;color:#c9d8d0}.item b{display:block;color:#f5c542;margin-bottom:5px;font-size:12px;text-transform:uppercase;letter-spacing:.1em}@media(max-width:560px){.grid{grid-template-columns:1fr}}</style>
</head><body><main class="card"><span class="pill"><span class="dot"></span>Service online</span><h1>BETSPORTS backend</h1><p>Separate Flask + SQLite API service for the restored BetSports frontend. Demo-safe persistence is enabled for authentication, match data, bet slips, booking codes, favourites, promotions, casino, virtual events, and support content.</p><section class="grid"><div class="item"><b>Health</b>/health</div><div class="item"><b>Config</b>/api/public/config</div><div class="item"><b>Sports</b>/api/public/&lt;sport&gt;/matches/live</div><div class="item"><b>Auth</b>/api/auth/register · /login</div></section></main></body></html>"""


@app.get("/api/public/config")
def public_config():
    return json_ok({"brand": "BETSPORTS", "currency": "GHS", "minStake": 200, "sports": SPORTS, "demoMode": not bool(DATABASE_URL), "paymentProvider": "disabled"})


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or body.get("username") or "").strip()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    if not name or not email or len(password) < 6:
        return json_error("Name, email, and a password of at least 6 characters are required")
    try:
        connection = db()
        cursor = connection.execute(
            "INSERT INTO users (name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
            (name, email, body.get("phone"), generate_password_hash(password), utc_now()),
        )
        new_user_id = cursor.fetchone()["id"]
        connection.commit()
    except sqlite3.IntegrityError:
        return json_error("An account with that email already exists", 409, "email_exists")
    user = connection.execute("SELECT * FROM users WHERE id = ?", (new_user_id,)).fetchone()
    return _session_response(user), 201


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or body.get("username") or "").strip().lower()
    user = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], body.get("password") or ""):
        return json_error("Invalid email or password", 401, "invalid_credentials")
    return _session_response(user)


def _session_response(user):
    token = secrets.token_urlsafe(32)
    db().execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user["id"], utc_now()))
    db().commit()
    response = jsonify({"ok": True, "data": {"user": _public_user(user), "token": token}})
    response.set_cookie("betsports_token", token, httponly=True, samesite="Lax")
    return response


def _public_user(user):
    return {"id": user["id"], "name": user["name"], "email": user["email"], "phone": user["phone"], "role": user["role"] if "role" in user.keys() else "USER", "balance": float(user["balance"] or 0) if "balance" in user.keys() else 0, "forcePasswordChange": bool(user["force_password_change"]) if "force_password_change" in user.keys() else False, "createdAt": user["created_at"]}


@app.get("/api/auth/me")
@auth_required
def me():
    return json_ok(_public_user(g.user))


@app.post("/api/auth/logout")
@auth_required
def logout():
    token = request_token()
    db().execute("DELETE FROM sessions WHERE token = ?", (token,))
    db().commit()
    response = jsonify({"ok": True, "data": {"loggedOut": True}})
    response.delete_cookie("betsports_token")
    return response


@app.post("/api/auth/change-password")
@auth_required
def change_password():
    body = request.get_json(silent=True) or {}
    current_password = str(body.get("currentPassword") or body.get("current_password") or "")
    new_password = str(body.get("newPassword") or body.get("new_password") or "")
    if not check_password_hash(g.user["password_hash"], current_password):
        return json_error("Current password is incorrect", 401, "invalid_current_password")
    if len(new_password) < 10:
        return json_error("New password must be at least 10 characters", 400, "weak_password")
    if check_password_hash(g.user["password_hash"], new_password):
        return json_error("New password must be different from the current password", 400, "same_password")
    connection = db()
    connection.execute("UPDATE users SET password_hash = ?, force_password_change = FALSE WHERE id = ?", (generate_password_hash(new_password), g.user["id"]))
    current_token = request_token()
    connection.execute("DELETE FROM sessions WHERE user_id = ? AND token != ?", (g.user["id"], current_token))
    connection.commit()
    return json_ok({"changed": True, "sessionsRevoked": True})


@app.get("/api/user/profile")
@auth_required
def profile():
    return json_ok(_public_user(g.user))


@app.patch("/api/user/profile")
@auth_required
def update_profile():
    body = request.get_json(silent=True) or {}
    name = body.get("name", g.user["name"])
    phone = body.get("phone", g.user["phone"])
    db().execute("UPDATE users SET name = ?, phone = ? WHERE id = ?", (name, phone, g.user["id"]))
    db().commit()
    return json_ok(_public_user(db().execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()))


@app.route("/api/public/<sport>/matches/<path:status>", methods=["GET"])
@app.route("/api/<sport>/matches/<path:status>", methods=["GET"])
def sport_matches(sport, status):
    if sport not in SPORTS:
        return json_error("Unsupported sport", 404, "sport_not_found")
    state = "live" if "live" in status else "upcoming"
    data = matches_for(sport, state)
    return json_ok(data, count=len(data), sport=sport, status=state)


@app.get("/api/public/<sport>/matches/<match_id>")
@app.get("/api/<sport>/matches/<match_id>")
def sport_match_detail(sport, match_id):
    if sport not in SPORTS:
        return json_error("Unsupported sport", 404, "sport_not_found")
    if match_id in {"live", "upcoming", "in-play"}:
        return sport_matches(sport, match_id)
    stored = db().execute("SELECT * FROM matches WHERE id = ? AND sport = ?", (match_id, sport)).fetchone()
    if stored:
        return json_ok(stored_match_to_public(stored))
    return json_ok(make_match(sport, abs(hash(match_id)) % 3, "live" if "live" in match_id else "upcoming"))


@app.get("/api/public/<sport>/standings/<path:rest>")
@app.get("/api/<sport>/standings/<path:rest>")
def standings(sport, rest):
    return json_ok({"sport": sport, "competition": rest, "standings": [{"position": i, "team": f"{sport.title()} {i}", "played": 10 - i, "points": 30 - i * 2} for i in range(1, 6)]})


@app.get("/api/public/<sport>/teams")
@app.get("/api/<sport>/teams")
def teams(sport):
    return json_ok([{"id": f"{sport}-{i}", "name": f"{sport.title()} Team {i}"} for i in range(1, 7)])


@app.get("/api/promotions")
@app.get("/api/public/promotions")
def promotions():
    return json_ok([
        {"id": "welcome-200", "title": "Welcome bonus", "description": "Up to 200% extra on your first qualifying slip", "type": "welcome", "active": True},
        {"id": "weekly-500", "title": "Weekly accumulator", "description": "Boosted returns on selected accumulators", "type": "accumulator", "active": True},
    ])


@app.get("/api/casino/games")
@app.get("/api/public/casino/games")
def casino_games():
    return json_ok([
        {"id": "aviator", "name": "Aviator", "category": "instant", "players": 5757, "multiplier": "96.86x"},
        {"id": "football-star", "name": "Football Star", "category": "virtual", "players": 3412, "multiplier": "42.10x"},
    ])


@app.get("/api/virtual/events")
@app.get("/api/public/virtual/events")
def virtual_events():
    return json_ok([make_match("football", i, "upcoming") for i in range(4)])


@app.get("/api/notifications")
@auth_required
def notifications():
    return json_ok([{ "id": "welcome", "title": "Welcome to BetSports", "message": "Your account is ready.", "read": False }])


@app.get("/api/help")
def help_center():
    return json_ok({"categories": ["Account", "Betting", "Payments", "Responsible play"], "contact": "support@betsports.example", "articles": 12})


@app.route("/api/favourites", methods=["GET", "POST", "DELETE"])
@auth_required
def favourites():
    connection = db()
    if request.method == "GET":
        rows = connection.execute("SELECT * FROM favourites WHERE user_id = ? ORDER BY created_at DESC", (g.user["id"],)).fetchall()
        return json_ok([row_to_dict(row) for row in rows])
    body = request.get_json(silent=True) or {}
    item_type = body.get("itemType", "match")
    item_id = str(body.get("itemId") or body.get("id") or "")
    if not item_id:
        return json_error("itemId is required")
    if request.method == "POST":
        connection.execute("INSERT INTO favourites (user_id, item_type, item_id, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (user_id, item_type, item_id) DO NOTHING", (g.user["id"], item_type, item_id, utc_now()))
    else:
        connection.execute("DELETE FROM favourites WHERE user_id = ? AND item_type = ? AND item_id = ?", (g.user["id"], item_type, item_id))
    connection.commit()
    return json_ok({"itemType": item_type, "itemId": item_id})


@app.route("/api/bet-slip", methods=["GET", "POST", "DELETE"])
@auth_required
def bet_slip():
    connection = db()
    if request.method == "GET":
        rows = connection.execute("SELECT * FROM bet_slips WHERE user_id = ? ORDER BY created_at DESC", (g.user["id"],)).fetchall()
        items = [row_to_dict(row) for row in rows]
        return json_ok({"items": items, "totalOdds": round(_total_odds(items), 2), "stake": round(sum(float(item["stake"] or 0) for item in items), 2)})
    body = request.get_json(silent=True) or {}
    if request.method == "DELETE":
        if body.get("id"):
            connection.execute("DELETE FROM bet_slips WHERE id = ? AND user_id = ?", (body["id"], g.user["id"]))
        else:
            connection.execute("DELETE FROM bet_slips WHERE user_id = ?", (g.user["id"],))
    else:
        match_id = str(body.get("matchId") or body.get("match_id") or "")
        selection = str(body.get("selection") or "")
        odds = float(body.get("odds") or 1)
        if not match_id or not selection:
            return json_error("matchId and selection are required")
        connection.execute("INSERT INTO bet_slips (user_id, match_id, selection, odds, stake, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (user_id, match_id, selection) DO UPDATE SET odds = EXCLUDED.odds, stake = EXCLUDED.stake, created_at = EXCLUDED.created_at", (g.user["id"], match_id, selection, odds, float(body.get("stake") or 0), utc_now()))
    connection.commit()
    return json_ok({"updated": True})


def _total_odds(items):
    total = 1.0
    for item in items:
        total *= max(1.0, float(item.get("odds") or 1))
    return total if items else 0


@app.post("/api/bets/place")
@app.post("/api/bets")
@auth_required
def place_bet():
    body = request.get_json(silent=True) or {}
    selections = body.get("selections") or body.get("items") or []
    stake = float(body.get("stake") or 0)
    if not selections or stake <= 0:
        return json_error("At least one selection and a positive stake are required")
    booking_code = "BS-" + secrets.token_hex(4).upper()
    total_odds = _total_odds(selections)
    connection = db()
    possible_win = round(total_odds * stake, 2)
    connection.execute("INSERT INTO bets (user_id, booking_code, selections_json, total_odds, stake, possible_win, payout, result, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, 'open', ?, ?)", (g.user["id"], booking_code, json.dumps(selections), total_odds, stake, possible_win, "accepted-demo", utc_now()))
    connection.commit()
    return json_ok({"bookingCode": booking_code, "status": "accepted-demo", "totalOdds": round(total_odds, 2), "possibleWin": possible_win}), 201


@app.route("/api/booking-codes", methods=["GET", "POST"])
@auth_required
def booking_codes():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        code = body.get("code") or body.get("bookingCode")
        if not code:
            return json_error("Booking code is required")
        return json_ok({"code": code, "status": "loaded-demo", "selections": []})
    rows = db().execute("SELECT booking_code, total_odds, stake, status, created_at FROM bets WHERE user_id = ? ORDER BY created_at DESC", (g.user["id"],)).fetchall()
    return json_ok([row_to_dict(row) for row in rows])


@app.get("/api/phone-lookup")
def phone_lookup():
    phone = request.args.get("phone", "")
    return json_ok({"phone": phone, "available": True})



def admin_current_user():
    user = current_user()
    if user is None or (user["role"] or "USER").upper() not in {"ADMIN", "SUPER_ADMIN"}:
        return None
    return user


def admin_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        user = admin_current_user()
        if user is None:
            return json_error("Administrator authentication required", 401, "admin_unauthorized")
        g.admin = user
        return handler(*args, **kwargs)
    return wrapped


def super_admin_required(handler):
    @wraps(handler)
    @admin_required
    def wrapped(*args, **kwargs):
        if (g.admin["role"] or "").upper() != "SUPER_ADMIN":
            return json_error("Super administrator authentication required", 403, "super_admin_required")
        return handler(*args, **kwargs)
    return wrapped


def audit(action, entity_type, entity_id=None, details=None):
    connection = db()
    params = (g.admin["id"], action, entity_type, str(entity_id) if entity_id is not None else None, json.dumps(details or {}, default=str), utc_now())
    if connection.postgres:
        connection.execute("INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, details_json, created_at) VALUES (?, ?, ?, ?, ?::jsonb, ?)", params)
    else:
        connection.execute("INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)", params)


def admin_user_dict(row):
    result = row_to_dict(row)
    if result:
        result["force_password_change"] = bool(result.get("force_password_change"))
        result["balance"] = float(result.get("balance") or 0)
    return result


@app.post("/api/admin/auth/login")
def admin_login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    user = db().execute("SELECT * FROM users WHERE email = ? AND upper(role) IN ('ADMIN', 'SUPER_ADMIN')", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return json_error("Invalid administrator credentials", 401, "invalid_admin_credentials")
    token = secrets.token_urlsafe(40)
    db().execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user["id"], utc_now()))
    db().commit()
    return json_ok({"token": token, "admin": admin_user_dict(user), "mustChangePassword": bool(user["force_password_change"])})


@app.post("/api/admin/auth/change-password")
@admin_required
def admin_change_password():
    body = request.get_json(silent=True) or {}
    password = str(body.get("password") or "")
    if len(password) < 10:
        return json_error("Password must be at least 10 characters", 400, "weak_password")
    db().execute("UPDATE users SET password_hash = ?, force_password_change = FALSE WHERE id = ?", (generate_password_hash(password), g.admin["id"]))
    audit("change_password", "admin", g.admin["id"])
    db().commit()
    return json_ok({"changed": True})


@app.get("/api/admin/auth/me")
@admin_required
def admin_me():
    return json_ok({"admin": admin_user_dict(g.admin), "mustChangePassword": bool(g.admin["force_password_change"])})


@app.get("/api/admin/admins")
@super_admin_required
def admin_list_admins():
    rows = db().execute("SELECT id, name, email, phone, role, force_password_change, created_at FROM users WHERE upper(role) IN ('ADMIN', 'SUPER_ADMIN') ORDER BY id ASC").fetchall()
    return json_ok([admin_user_dict(row) for row in rows])


@app.post("/api/admin/admins")
@super_admin_required
def admin_create_admin():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    name = str(body.get("name") or "").strip()
    password = str(body.get("password") or "")
    if not email or "@" not in email:
        return json_error("A valid administrator email is required", 400, "invalid_email")
    if not name:
        return json_error("Administrator name is required", 400, "invalid_name")
    if len(password) < 10:
        return json_error("The temporary password must be at least 10 characters", 400, "weak_password")
    connection = db()
    existing = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return json_error("An account with this email already exists", 409, "email_in_use")
    cursor = connection.execute("INSERT INTO users (name, email, password_hash, role, force_password_change, created_at) VALUES (?, ?, ?, 'ADMIN', ?, ?) RETURNING id", (name, email, generate_password_hash(password), True, utc_now()))
    row = cursor.fetchone()
    admin_id = scalar(row)
    audit("create_admin", "admin", admin_id, {"email": email, "role": "ADMIN"})
    connection.commit()
    created = connection.execute("SELECT id, name, email, phone, role, force_password_change, created_at FROM users WHERE id = ?", (admin_id,)).fetchone()
    return json_ok(admin_user_dict(created)), 201


@app.post("/api/admin/auth/logout")
@admin_required
def admin_logout():
    token = request.headers.get("Authorization", "")[7:]
    db().execute("DELETE FROM sessions WHERE token = ?", (token,))
    db().commit()
    return json_ok({"loggedOut": True})


@app.get("/api/admin/overview")
@admin_required
def admin_overview():
    connection = db()
    counts = {
        "users": scalar(connection.execute("SELECT COUNT(*) FROM users WHERE upper(role) = 'USER'").fetchone()),
        "bets": scalar(connection.execute("SELECT COUNT(*) FROM bets").fetchone()),
        "pendingDeposits": scalar(connection.execute("SELECT COUNT(*) FROM wallet_requests WHERE request_type = 'deposit' AND status = 'pending'").fetchone()),
        "pendingWithdrawals": scalar(connection.execute("SELECT COUNT(*) FROM wallet_requests WHERE request_type = 'withdrawal' AND status = 'pending'").fetchone()),
        "totalStakes": float(scalar(connection.execute("SELECT COALESCE(SUM(stake), 0) FROM bets").fetchone()) or 0),
        "totalBalances": float(scalar(connection.execute("SELECT COALESCE(SUM(balance), 0) FROM users WHERE upper(role) = 'USER'").fetchone()) or 0),
        "totalPayouts": float(scalar(connection.execute("SELECT COALESCE(SUM(payout), 0) FROM bets").fetchone()) or 0),
        "openBets": scalar(connection.execute("SELECT COUNT(*) FROM bets WHERE result = 'open'").fetchone()),
        "wonBets": scalar(connection.execute("SELECT COUNT(*) FROM bets WHERE result = 'won'").fetchone()),
        "lostBets": scalar(connection.execute("SELECT COUNT(*) FROM bets WHERE result = 'lost'").fetchone()),
    }
    return json_ok(counts)


@app.get("/api/admin/users")
@admin_required
def admin_users():
    search = str(request.args.get("search") or "").strip()
    query = "SELECT id, name, email, phone, role, balance, force_password_change, created_at FROM users WHERE upper(role) = 'USER'"
    params = []
    if search:
        query += " AND (lower(name) LIKE ? OR lower(email) LIKE ? OR CAST(id AS TEXT) = ?)"
        params += [f"%{search.lower()}%", f"%{search.lower()}%", search]
    query += " ORDER BY id DESC LIMIT 200"
    return json_ok([admin_user_dict(row) for row in db().execute(query, params).fetchall()])


@app.get("/api/admin/users/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    user = db().execute("SELECT id, name, email, phone, role, balance, force_password_change, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return json_error("User not found", 404, "user_not_found")
    connection = db()
    bets = connection.execute("SELECT id, booking_code, total_odds, stake, status, created_at FROM bets WHERE user_id = ? ORDER BY created_at DESC LIMIT 200", (user_id,)).fetchall()
    ledger = connection.execute("SELECT * FROM wallet_ledger WHERE user_id = ? ORDER BY created_at DESC LIMIT 200", (user_id,)).fetchall()
    return json_ok({"user": admin_user_dict(user), "bets": [row_to_dict(row) for row in bets], "ledger": [row_to_dict(row) for row in ledger]})


@app.patch("/api/admin/users/<int:user_id>/balance")
@admin_required
def admin_adjust_balance(user_id):
    body = request.get_json(silent=True) or {}
    try:
        amount = float(body.get("amount"))
    except (TypeError, ValueError):
        return json_error("A numeric amount is required")
    if amount == 0:
        return json_error("Amount cannot be zero")
    connection = db()
    user = connection.execute("SELECT * FROM users WHERE id = ? AND upper(role) = 'USER'", (user_id,)).fetchone()
    if user is None:
        return json_error("User not found", 404, "user_not_found")
    new_balance = float(user["balance"] or 0) + amount
    if new_balance < 0:
        return json_error("Balance cannot become negative", 400, "insufficient_balance")
    connection.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
    connection.execute("INSERT INTO wallet_ledger (user_id, amount, balance_after, entry_type, note, created_by, created_at) VALUES (?, ?, ?, 'admin_adjustment', ?, ?, ?)", (user_id, amount, new_balance, str(body.get("note") or "Admin balance adjustment"), g.admin["id"], utc_now()))
    audit("adjust_balance", "user", user_id, {"amount": amount, "note": body.get("note")})
    connection.commit()
    return json_ok({"userId": user_id, "balance": new_balance})


@app.get("/api/admin/bets")
@admin_required
def admin_bets():
    rows = db().execute("SELECT b.*, u.name AS user_name, u.email AS user_email FROM bets b JOIN users u ON u.id = b.user_id ORDER BY b.created_at DESC LIMIT 300").fetchall()
    return json_ok([row_to_dict(row) for row in rows])


@app.post("/api/admin/bets/<int:bet_id>/settle")
@admin_required
def admin_settle_bet(bet_id):
    body = request.get_json(silent=True) or {}
    result = str(body.get("result") or "").lower()
    if result not in {"won", "lost", "void"}:
        return json_error("Result must be won, lost, or void")
    connection = db()
    bet = connection.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()
    if bet is None:
        return json_error("Bet not found", 404, "bet_not_found")
    if bet["result"] != "open":
        return json_error("This bet has already been settled", 409, "bet_already_settled")
    payout = float(bet["possible_win"] or 0) if result == "won" else float(bet["stake"] or 0) if result == "void" else 0
    connection.execute("UPDATE bets SET result = ?, payout = ?, status = ? WHERE id = ?", (result, payout, f"settled-{result}", bet_id))
    if payout:
        user = connection.execute("SELECT balance FROM users WHERE id = ?", (bet["user_id"],)).fetchone()
        new_balance = float(user["balance"] or 0) + payout
        connection.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, bet["user_id"]))
        connection.execute("INSERT INTO wallet_ledger (user_id, amount, balance_after, entry_type, note, created_by, created_at) VALUES (?, ?, ?, 'bet_payout', ?, ?, ?)", (bet["user_id"], payout, new_balance, result, g.admin["id"], utc_now()))
    audit("settle_bet", "bet", bet_id, {"result": result, "payout": payout})
    connection.commit()
    return json_ok({"betId": bet_id, "result": result, "payout": payout})


@app.get("/api/admin/requests")
@admin_required
def admin_requests():
    status = request.args.get("status")
    query = "SELECT w.*, u.name AS user_name, u.email AS user_email FROM wallet_requests w JOIN users u ON u.id = w.user_id"
    params = []
    if status:
        query += " WHERE w.status = ?"; params.append(status)
    query += " ORDER BY w.created_at DESC LIMIT 300"
    return json_ok([row_to_dict(row) for row in db().execute(query, params).fetchall()])


@app.post("/api/admin/requests/<int:request_id>/<action>")
@admin_required
def admin_review_request(request_id, action):
    if action not in {"approve", "reject"}:
        return json_error("Unsupported review action", 400)
    if action == "approve" and not PAYMENTS_ENABLED:
        return payment_gateway_disabled()
    connection = db()
    item = connection.execute("SELECT * FROM wallet_requests WHERE id = ?", (request_id,)).fetchone()
    if item is None:
        return json_error("Wallet request not found", 404, "request_not_found")
    if item["status"] != "pending":
        return json_error("This request has already been reviewed", 409, "request_already_reviewed")
    new_status = "approved" if action == "approve" else "rejected"
    reviewed_at = utc_now()
    connection.execute("UPDATE wallet_requests SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?", (new_status, g.admin["id"], reviewed_at, request_id))
    if action == "approve":
        signed_amount = float(item["amount"]) if item["request_type"] == "deposit" else -float(item["amount"])
        user = connection.execute("SELECT balance FROM users WHERE id = ?", (item["user_id"],)).fetchone()
        new_balance = float(user["balance"] or 0) + signed_amount
        if new_balance < 0:
            return json_error("User balance is too low for this withdrawal", 400, "insufficient_balance")
        connection.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, item["user_id"]))
        connection.execute("INSERT INTO wallet_ledger (user_id, request_id, amount, balance_after, entry_type, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (item["user_id"], request_id, signed_amount, new_balance, item["request_type"], item["note"], g.admin["id"], reviewed_at))
    audit(f"{action}_{item['request_type']}", "wallet_request", request_id, {"amount": item["amount"], "provider": "disabled"})
    connection.commit()
    return json_ok({"requestId": request_id, "status": new_status})


@app.post("/api/admin/sync-matches")
@admin_required
def admin_sync_matches():
    sport = str((request.get_json(silent=True) or {}).get("sport") or "").strip().lower()
    targets = [sport] if sport in ESPN_LEAGUE_CATALOG else list(ESPN_LEAGUE_CATALOG)
    for target in targets:
        sync_espn_sport(target, force=True)
    audit("sync_matches", "match_feed", sport or "all", {"sports": targets})
    db().commit()
    return json_ok({"sports": targets, "status": "synced"})


@app.get("/api/admin/matches")
@admin_required
def admin_matches():
    return json_ok([row_to_dict(row) for row in db().execute("SELECT * FROM matches ORDER BY start_time ASC LIMIT 300").fetchall()])


@app.post("/api/admin/matches")
@admin_required
def admin_create_match():
    body = request.get_json(silent=True) or {}
    required = ["sport", "league", "homeTeam", "awayTeam", "startTime"]
    if any(not str(body.get(key) or "").strip() for key in required):
        return json_error("sport, league, homeTeam, awayTeam, and startTime are required")
    match_id = str(body.get("id") or f"admin-{secrets.token_hex(6)}")
    now = utc_now()
    db().execute("INSERT INTO matches (id, sport, league, home_team, away_team, start_time, status, home_odds, draw_odds, away_odds, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (match_id, body["sport"], body["league"], body["homeTeam"], body["awayTeam"], body["startTime"], body.get("status", "upcoming"), float(body.get("homeOdds") or 1.5), float(body.get("drawOdds") or 3.2), float(body.get("awayOdds") or 2.15), now, now))
    audit("create_match", "match", match_id, body)
    db().commit()
    return json_ok({"id": match_id}), 201


@app.patch("/api/admin/matches/<match_id>")
@admin_required
def admin_update_match(match_id):
    match = db().execute("SELECT * FROM matches WHERE id = ?", (match_id,)).fetchone()
    if match is None:
        return json_error("Match not found", 404, "match_not_found")
    body = request.get_json(silent=True) or {}
    fields = {"status": body.get("status", match["status"]), "home_score": int(body.get("homeScore", match["home_score"])), "away_score": int(body.get("awayScore", match["away_score"])), "home_odds": float(body.get("homeOdds", match["home_odds"])), "draw_odds": float(body.get("drawOdds", match["draw_odds"])), "away_odds": float(body.get("awayOdds", match["away_odds"])), "updated_at": utc_now()}
    db().execute("UPDATE matches SET status = ?, home_score = ?, away_score = ?, home_odds = ?, draw_odds = ?, away_odds = ?, updated_at = ? WHERE id = ?", (*fields.values(), match_id))
    audit("update_match", "match", match_id, fields)
    db().commit()
    return json_ok({"updated": True})


@app.get("/api/admin/audit-log")
@admin_required
def admin_audit_log():
    rows = db().execute("SELECT a.*, u.email AS admin_email FROM admin_audit_log a JOIN users u ON u.id = a.admin_id ORDER BY a.created_at DESC LIMIT 300").fetchall()
    return json_ok([row_to_dict(row) for row in rows])


@app.post("/api/wallet/deposits")
@auth_required
def create_deposit_request():
    if not PAYMENTS_ENABLED:
        return payment_gateway_disabled()
    body = request.get_json(silent=True) or {}
    try:
        amount = float(body.get("amount"))
    except (TypeError, ValueError):
        return json_error("A numeric amount is required")
    if amount <= 0:
        return json_error("Amount must be positive")
    cursor = db().execute("INSERT INTO wallet_requests (user_id, request_type, amount, method, reference, note, created_at) VALUES (?, 'deposit', ?, ?, ?, ?, ?) RETURNING id", (g.user["id"], amount, body.get("method") or "manual", body.get("reference"), body.get("note"), utc_now()))
    request_id = cursor.fetchone()["id"]
    db().commit()
    return json_ok({"requestId": request_id, "status": "pending"}), 201


@app.post("/api/wallet/withdrawals")
@auth_required
def create_withdrawal_request():
    if not PAYMENTS_ENABLED:
        return payment_gateway_disabled()
    body = request.get_json(silent=True) or {}
    try:
        amount = float(body.get("amount"))
    except (TypeError, ValueError):
        return json_error("A numeric amount is required")
    if amount <= 0:
        return json_error("Amount must be positive")
    if float(g.user["balance"] or 0) < amount:
        return json_error("Insufficient balance", 400, "insufficient_balance")
    cursor = db().execute("INSERT INTO wallet_requests (user_id, request_type, amount, method, reference, note, created_at) VALUES (?, 'withdrawal', ?, ?, ?, ?, ?) RETURNING id", (g.user["id"], amount, body.get("method") or "manual", body.get("reference"), body.get("note"), utc_now()))
    request_id = cursor.fetchone()["id"]
    db().commit()
    return json_ok({"requestId": request_id, "status": "pending"}), 201


@app.errorhandler(404)
def not_found(_error):
    return json_error("Endpoint not found", 404, "not_found")


@app.errorhandler(405)
def method_not_allowed(_error):
    return json_error("Method not allowed", 405, "method_not_allowed")


init_db()

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
