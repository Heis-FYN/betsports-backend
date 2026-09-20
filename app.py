import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("BETSPORTS_DB", BASE_DIR / "betsports.db"))
PORT = int(os.getenv("BETSPORTS_PORT", "5050"))
HOST = os.getenv("BETSPORTS_HOST", "0.0.0.0")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": os.getenv("BETSPORTS_ALLOWED_ORIGINS", "*")}}, supports_credentials=True)

SPORTS = ["football", "basketball", "cricket", "tennis", "rugby", "baseball", "icehockey", "volleyball", "ufc", "mma", "nfl", "nba"]


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
        "app_metadata": {"provider": "email", "providers": ["email"], "role": "user"},
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
    return {"id": str(user["id"]), "email": user["email"], "first_name": metadata.get("first_name", ""), "last_name": metadata.get("last_name", ""), "phone": user["phone"] or "", "role": "USER", "country": "GH", "currency": "GHS", "balance": 0, "kyc_status": "verified", "created_at": user["created_at"], "updated_at": user["created_at"]}

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
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    connection = sqlite3.connect(DB_PATH)
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            password_hash TEXT NOT NULL,
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
        """
    )
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


def current_user():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else request.cookies.get("betsports_token")
    if not token:
        return None
    return db().execute(
        "SELECT u.* FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.token = ?", (token,)
    ).fetchone()


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


def matches_for(sport, status="upcoming"):
    normalized = "live" if status in ("live", "in-play") else "upcoming"
    return [make_match(sport, i, normalized) for i in range(3)]


@app.get("/health")
def health():
    db().execute("SELECT 1").fetchone()
    return json_ok({"service": "betsports-backend", "status": "healthy", "time": utc_now(), "database": "sqlite"})


@app.get("/")
def backend_home():
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BetSports Backend</title>
<style>body{margin:0;background:#0b0d0c;color:#eef5f2;font:16px Arial,sans-serif;display:grid;min-height:100vh;place-items:center}.card{width:min(680px,calc(100% - 40px));padding:36px;border:1px solid #1e4b38;border-radius:20px;background:linear-gradient(145deg,#112119,#0f1412);box-shadow:0 24px 80px #0008}h1{margin:0 0 10px;font-size:34px;letter-spacing:-.04em}p{color:#9eb2a7;line-height:1.6}.pill{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;background:#123f2b;color:#4be58e;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.12em}.dot{width:8px;height:8px;border-radius:50%;background:#4be58e;box-shadow:0 0 12px #4be58e}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:24px}.item{padding:14px;border:1px solid #20332a;border-radius:12px;background:#101916;color:#c9d8d0}.item b{display:block;color:#f5c542;margin-bottom:5px;font-size:12px;text-transform:uppercase;letter-spacing:.1em}@media(max-width:560px){.grid{grid-template-columns:1fr}}</style>
</head><body><main class="card"><span class="pill"><span class="dot"></span>Service online</span><h1>BETSPORTS backend</h1><p>Separate Flask + SQLite API service for the restored BetSports frontend. Demo-safe persistence is enabled for authentication, match data, bet slips, booking codes, favourites, promotions, casino, virtual events, and support content.</p><section class="grid"><div class="item"><b>Health</b>/health</div><div class="item"><b>Config</b>/api/public/config</div><div class="item"><b>Sports</b>/api/public/&lt;sport&gt;/matches/live</div><div class="item"><b>Auth</b>/api/auth/register · /login</div></section></main></body></html>"""


@app.get("/api/public/config")
def public_config():
    return json_ok({"brand": "BETSPORTS", "currency": "GHS", "minStake": 200, "sports": SPORTS, "demoMode": True})


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
            "INSERT INTO users (name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, email, body.get("phone"), generate_password_hash(password), utc_now()),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        return json_error("An account with that email already exists", 409, "email_exists")
    user = connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
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
    return {"id": user["id"], "name": user["name"], "email": user["email"], "phone": user["phone"], "createdAt": user["created_at"]}


@app.get("/api/auth/me")
@auth_required
def me():
    return json_ok(_public_user(g.user))


@app.post("/api/auth/logout")
@auth_required
def logout():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else request.cookies.get("betsports_token")
    db().execute("DELETE FROM sessions WHERE token = ?", (token,))
    db().commit()
    response = jsonify({"ok": True, "data": {"loggedOut": True}})
    response.delete_cookie("betsports_token")
    return response


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
        connection.execute("INSERT OR IGNORE INTO favourites (user_id, item_type, item_id, created_at) VALUES (?, ?, ?, ?)", (g.user["id"], item_type, item_id, utc_now()))
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
        connection.execute("INSERT OR REPLACE INTO bet_slips (user_id, match_id, selection, odds, stake, created_at) VALUES (?, ?, ?, ?, ?, ?)", (g.user["id"], match_id, selection, odds, float(body.get("stake") or 0), utc_now()))
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
    connection.execute("INSERT INTO bets (user_id, booking_code, selections_json, total_odds, stake, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (g.user["id"], booking_code, __import__("json").dumps(selections), total_odds, stake, "accepted-demo", utc_now()))
    connection.commit()
    return json_ok({"bookingCode": booking_code, "status": "accepted-demo", "totalOdds": round(total_odds, 2), "possibleWin": round(total_odds * stake, 2)}), 201


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


@app.errorhandler(404)
def not_found(_error):
    return json_error("Endpoint not found", 404, "not_found")


@app.errorhandler(405)
def method_not_allowed(_error):
    return json_error("Method not allowed", 405, "method_not_allowed")


init_db()

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
