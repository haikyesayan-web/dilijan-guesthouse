#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import queue
import re
import secrets
import sqlite3
import threading
import time
import uuid
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DATA_DIR = APP_DIR / "data"
DB_PATH = Path(os.environ.get("GH_DB_PATH", DATA_DIR / "guesthouse.sqlite3"))
HOST = os.environ.get("GH_HOST", "127.0.0.1")
PORT = int(os.environ.get("GH_PORT", "8000"))
SESSION_DAYS = int(os.environ.get("GH_SESSION_DAYS", "30"))
COOKIE_SECURE = os.environ.get("GH_COOKIE_SECURE", "0") == "1"

PLATFORMS = {
    "Booking": "#003b95",
    "Airbnb": "#e0245e",
    "list.am": "#e08a00",
    "Instagram": "#8a3ab9",
    "Facebook": "#1877f2",
    "Direct": "#2f6b4f",
}

DB_LOCK = threading.RLock()
SSE_CLIENTS = set()
SSE_LOCK = threading.Lock()


def now_ts():
    return int(time.time())


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=15000")
    return con


def init_db():
    with DB_LOCK:
        con = get_db()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('owner','staff')),
              active INTEGER NOT NULL DEFAULT 1,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bookings (
              id TEXT PRIMARY KEY,
              guest TEXT NOT NULL,
              check_in TEXT NOT NULL,
              check_out TEXT NOT NULL,
              platform TEXT NOT NULL,
              room TEXT,
              guests INTEGER NOT NULL DEFAULT 2,
              price TEXT,
              phone TEXT,
              notes TEXT,
              by_name TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'confirmed' CHECK(status IN ('confirmed','cancelled')),
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bookings_dates ON bookings(check_in, check_out);
            CREATE INDEX IF NOT EXISTS idx_bookings_room ON bookings(room, check_in, check_out);
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            """
        )
        con.commit()
        con.close()


def clean_text(v, max_len=2000):
    if v is None:
        return ""
    return str(v).strip()[:max_len]


def valid_date(s):
    return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", s or ""))


def normalize_booking(data, existing=None):
    existing = existing or {}
    guest = clean_text(data.get("guest"), 200)
    cin = clean_text(data.get("checkIn"), 10)
    cout = clean_text(data.get("checkOut"), 10)
    platform = clean_text(data.get("platform"), 50)
    room = clean_text(data.get("room"), 100)
    price = clean_text(data.get("price"), 120)
    phone = clean_text(data.get("phone"), 120)
    notes = clean_text(data.get("notes"), 3000)
    by = clean_text(data.get("by"), 120)
    try:
        guests = int(data.get("guests", 2))
    except (TypeError, ValueError):
        guests = 2
    guests = min(max(guests, 1), 50)
    errors = []
    if not guest or not cin or not cout or not by:
        errors.append("required")
    if not valid_date(cin) or not valid_date(cout):
        errors.append("date")
    if valid_date(cin) and valid_date(cout) and cout <= cin:
        errors.append("order")
    if platform not in PLATFORMS:
        errors.append("platform")
    return {
        "guest": guest,
        "checkIn": cin,
        "checkOut": cout,
        "platform": platform,
        "room": room,
        "guests": guests,
        "price": price,
        "phone": phone,
        "notes": notes,
        "by": by,
    }, errors


def public_booking(row):
    return {
        "id": row["id"],
        "guest": row["guest"],
        "checkIn": row["check_in"],
        "checkOut": row["check_out"],
        "platform": row["platform"],
        "room": row["room"] or "",
        "guests": row["guests"],
        "price": row["price"] or "",
        "phone": row["phone"] or "",
        "notes": row["notes"] or "",
        "by": row["by_name"],
        "status": row["status"],
        "created": row["created_at"],
        "updated": row["updated_at"],
    }


def public_user(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "username": row["username"],
        "role": row["role"],
        "active": bool(row["active"]),
    }


def random_id():
    return uuid.uuid4().hex


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210000)
    return "pbkdf2_sha256$210000$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def check_password(password, stored):
    try:
        algo, rounds_s, salt_b64, digest_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def cleanup_sessions(con):
    con.execute("DELETE FROM sessions WHERE expires_at < ?", (now_ts(),))


def session_user(handler):
    cookie = SimpleCookie()
    cookie.load(handler.headers.get("Cookie", ""))
    token = cookie.get("gh_session")
    if not token:
        return None
    token = token.value
    with DB_LOCK:
        con = get_db()
        cleanup_sessions(con)
        row = con.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND u.active=1 AND s.expires_at>=?",
            (token, now_ts()),
        ).fetchone()
        con.commit()
        con.close()
    return row


def set_session(handler, user_id):
    token = secrets.token_urlsafe(36)
    expires = now_ts() + SESSION_DAYS * 86400
    with DB_LOCK:
        con = get_db()
        con.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (token, user_id, expires))
        con.commit()
        con.close()
    cookie = f"gh_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS*86400}"
    if COOKIE_SECURE:
        cookie += "; Secure"
    handler.send_header("Set-Cookie", cookie)


def clear_session(handler):
    cookie = SimpleCookie()
    cookie.load(handler.headers.get("Cookie", ""))
    token = cookie.get("gh_session")
    if token:
        with DB_LOCK:
            con = get_db()
            con.execute("DELETE FROM sessions WHERE token=?", (token.value,))
            con.commit()
            con.close()
    handler.send_header("Set-Cookie", "gh_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")


def broadcast(kind="bookings"):
    payload = json.dumps({"type": kind, "at": now_ts()}, ensure_ascii=False)
    dead = []
    with SSE_LOCK:
        clients = list(SSE_CLIENTS)
    for q in clients:
        try:
            q.put_nowait(payload)
        except Exception:
            dead.append(q)
    if dead:
        with SSE_LOCK:
            for q in dead:
                SSE_CLIENTS.discard(q)


def get_bookings():
    with DB_LOCK:
        con = get_db()
        rows = con.execute("SELECT * FROM bookings ORDER BY check_in ASC, created_at ASC").fetchall()
        con.close()
    return [public_booking(r) for r in rows]


def find_overlaps(con, booking, exclude_id=None):
    sql = """
      SELECT * FROM bookings
      WHERE status!='cancelled'
        AND room IS NOT NULL AND TRIM(room)!=''
        AND LOWER(TRIM(room))=LOWER(TRIM(?))
        AND check_in < ?
        AND ? < check_out
    """
    args = [booking["room"], booking["checkOut"], booking["checkIn"]]
    if exclude_id:
        sql += " AND id != ?"
        args.append(exclude_id)
    return con.execute(sql, args).fetchall()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DilijanGuesthouse/1.0"

    def log_message(self, fmt, *args):
        return

    def send_json(self, payload, status=HTTPStatus.OK, extra_headers=None, set_cookie=False):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        if set_cookie:
            pass
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b"{}"
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("bad_json")

    def require_user(self):
        user = session_user(self)
        if not user:
            self.send_json({"error": "auth_required"}, HTTPStatus.UNAUTHORIZED)
            return None
        return user

    def require_owner(self):
        user = self.require_user()
        if user and user["role"] != "owner":
            self.send_json({"error": "owner_required"}, HTTPStatus.FORBIDDEN)
            return None
        return user

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/setup":
            with DB_LOCK:
                con = get_db()
                count = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
                con.close()
            self.send_json({"initialized": count > 0})
            return
        if path == "/api/me":
            user = session_user(self)
            if not user:
                self.send_json({"authenticated": False})
            else:
                self.send_json({"authenticated": True, "user": public_user(user)})
            return
        if path == "/api/bookings":
            user = self.require_user()
            if not user:
                return
            self.send_json({"bookings": get_bookings()})
            return
        if path == "/api/team":
            user = self.require_owner()
            if not user:
                return
            with DB_LOCK:
                con = get_db()
                rows = con.execute("SELECT * FROM users ORDER BY role DESC, name COLLATE NOCASE").fetchall()
                con.close()
            self.send_json({"users": [public_user(r) for r in rows]})
            return
        if path == "/api/events":
            user = self.require_user()
            if not user:
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            q = queue.Queue()
            with SSE_LOCK:
                SSE_CLIENTS.add(q)
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    try:
                        msg = q.get(timeout=25)
                        self.wfile.write(("data: " + msg + "\n\n").encode("utf-8"))
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            finally:
                with SSE_LOCK:
                    SSE_CLIENTS.discard(q)
            return
        # Static app
        file_path = STATIC_DIR / ("index.html" if path in ("/", "") else path.lstrip("/"))
        try:
            file_path = file_path.resolve()
            if STATIC_DIR.resolve() not in file_path.parents and file_path != STATIC_DIR.resolve() / "index.html":
                raise FileNotFoundError
            if not file_path.is_file():
                raise FileNotFoundError
            data = file_path.read_bytes()
            ctype = "text/html; charset=utf-8"
            if file_path.suffix == ".js": ctype = "text/javascript; charset=utf-8"
            elif file_path.suffix == ".css": ctype = "text/css; charset=utf-8"
            elif file_path.suffix == ".json": ctype = "application/json; charset=utf-8"
            elif file_path.suffix == ".svg": ctype = "image/svg+xml"
            elif file_path.suffix == ".png": ctype = "image/png"
            elif file_path.suffix == ".webmanifest": ctype = "application/manifest+json"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            if path == "/" or path == "/index.html":
                self.send_header("Cache-Control", "no-store")
            else:
                self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/setup":
            try:
                body = self.read_json()
            except ValueError:
                self.send_json({"error": "bad_json"}, HTTPStatus.BAD_REQUEST)
                return
            name = clean_text(body.get("name"), 120)
            username = clean_text(body.get("username"), 80)
            password = str(body.get("password") or "")
            if not name or not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username) or len(password) < 8:
                self.send_json({"error": "invalid_setup"}, HTTPStatus.BAD_REQUEST)
                return
            with DB_LOCK:
                con = get_db()
                count = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
                if count:
                    con.close()
                    self.send_json({"error": "already_initialized"}, HTTPStatus.CONFLICT)
                    return
                uid = random_id()
                con.execute(
                    "INSERT INTO users(id,name,username,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,?)",
                    (uid, name, username, hash_password(password), "owner", 1, now_ts()),
                )
                con.commit()
                con.close()
            self.send_response(HTTPStatus.CREATED)
            set_session(self, uid)
            raw = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            broadcast("auth")
            return

        if path == "/api/login":
            try:
                body = self.read_json()
            except ValueError:
                self.send_json({"error": "bad_json"}, HTTPStatus.BAD_REQUEST)
                return
            username = clean_text(body.get("username"), 80)
            password = str(body.get("password") or "")
            with DB_LOCK:
                con = get_db()
                row = con.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1", (username,)).fetchone()
                con.close()
            if not row or not check_password(password, row["password_hash"]):
                self.send_json({"error": "invalid_credentials"}, HTTPStatus.UNAUTHORIZED)
                return
            self.send_response(HTTPStatus.OK)
            set_session(self, row["id"])
            raw = json.dumps({"ok": True, "user": public_user(row)}, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/api/logout":
            self.send_response(HTTPStatus.OK)
            clear_session(self)
            raw = b'{"ok":true}'
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/api/bookings":
            user = self.require_user()
            if not user:
                return
            try:
                body = self.read_json()
            except ValueError:
                self.send_json({"error": "bad_json"}, HTTPStatus.BAD_REQUEST)
                return
            data, errors = normalize_booking(body)
            if errors:
                self.send_json({"error": "validation", "fields": errors}, HTTPStatus.BAD_REQUEST)
                return
            force = bool(body.get("forceOverlap"))
            bid = random_id()
            ts = now_ts()
            with DB_LOCK:
                con = get_db()
                try:
                    overlaps = find_overlaps(con, data)
                    if overlaps and not force:
                        r = overlaps[0]
                        self.send_json({"error": "overlap", "booking": public_booking(r)}, HTTPStatus.CONFLICT)
                        con.close()
                        return
                    con.execute(
                        """INSERT INTO bookings(id,guest,check_in,check_out,platform,room,guests,price,phone,notes,by_name,status,created_at,updated_at,created_by_user_id)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (bid, data["guest"], data["checkIn"], data["checkOut"], data["platform"], data["room"], data["guests"], data["price"], data["phone"], data["notes"], data["by"], "confirmed", ts, ts, user["id"]),
                    )
                    con.commit()
                    row = con.execute("SELECT * FROM bookings WHERE id=?", (bid,)).fetchone()
                finally:
                    con.close()
            broadcast()
            self.send_json({"booking": public_booking(row) if row else None}, HTTPStatus.CREATED)
            return

        if path == "/api/team":
            user = self.require_owner()
            if not user:
                return
            try:
                body = self.read_json()
            except ValueError:
                self.send_json({"error": "bad_json"}, HTTPStatus.BAD_REQUEST)
                return
            name = clean_text(body.get("name"), 120)
            username = clean_text(body.get("username"), 80)
            password = str(body.get("password") or "")
            if not name or not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username) or len(password) < 8:
                self.send_json({"error": "invalid_staff"}, HTTPStatus.BAD_REQUEST)
                return
            uid = random_id()
            with DB_LOCK:
                con = get_db()
                try:
                    con.execute(
                        "INSERT INTO users(id,name,username,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,?)",
                        (uid, name, username, hash_password(password), "staff", 1, now_ts()),
                    )
                    con.commit()
                    row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                except sqlite3.IntegrityError:
                    con.close()
                    self.send_json({"error": "username_taken"}, HTTPStatus.CONFLICT)
                    return
                finally:
                    if con:
                        con.close()
            broadcast("team")
            self.send_json({"user": public_user(row) if row else None}, HTTPStatus.CREATED)
            return

        if path == "/api/team/rotate-password":
            user = self.require_owner()
            if not user:
                return
            try:
                body = self.read_json()
            except ValueError:
                self.send_json({"error": "bad_json"}, HTTPStatus.BAD_REQUEST)
                return
            uid = clean_text(body.get("id"), 100)
            password = str(body.get("password") or "")
            if len(password) < 8:
                self.send_json({"error": "invalid_password"}, HTTPStatus.BAD_REQUEST)
                return
            with DB_LOCK:
                con = get_db()
                cur = con.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), uid))
                con.commit()
                con.close()
            self.send_json({"ok": cur.rowcount == 1})
            return

        self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        path = urlparse(self.path).path
        m = re.fullmatch(r"/api/bookings/([^/]+)", path)
        if m:
            user = self.require_user()
            if not user:
                return
            bid = m.group(1)
            try:
                body = self.read_json()
            except ValueError:
                self.send_json({"error": "bad_json"}, HTTPStatus.BAD_REQUEST)
                return
            with DB_LOCK:
                con = get_db()
                old = con.execute("SELECT * FROM bookings WHERE id=?", (bid,)).fetchone()
                if not old:
                    con.close()
                    self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                    return
                data, errors = normalize_booking(body, existing=old)
                if errors:
                    con.close()
                    self.send_json({"error": "validation", "fields": errors}, HTTPStatus.BAD_REQUEST)
                    return
                force = bool(body.get("forceOverlap"))
                overlaps = find_overlaps(con, data, exclude_id=bid)
                if overlaps and not force:
                    r = overlaps[0]
                    con.close()
                    self.send_json({"error": "overlap", "booking": public_booking(r)}, HTTPStatus.CONFLICT)
                    return
                ts = now_ts()
                con.execute(
                    """UPDATE bookings SET guest=?,check_in=?,check_out=?,platform=?,room=?,guests=?,price=?,phone=?,notes=?,by_name=?,updated_at=? WHERE id=?""",
                    (data["guest"], data["checkIn"], data["checkOut"], data["platform"], data["room"], data["guests"], data["price"], data["phone"], data["notes"], data["by"], ts, bid),
                )
                con.commit()
                row = con.execute("SELECT * FROM bookings WHERE id=?", (bid,)).fetchone()
                con.close()
            broadcast()
            self.send_json({"booking": public_booking(row) if row else None})
            return

        self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_PATCH(self):
        path = urlparse(self.path).path
        m = re.fullmatch(r"/api/bookings/([^/]+)/status", path)
        if m:
            user = self.require_user()
            if not user:
                return
            bid = m.group(1)
            try:
                body = self.read_json()
            except ValueError:
                self.send_json({"error": "bad_json"}, HTTPStatus.BAD_REQUEST)
                return
            new_status = body.get("status")
            if new_status not in ("confirmed", "cancelled"):
                self.send_json({"error": "bad_status"}, HTTPStatus.BAD_REQUEST)
                return
            with DB_LOCK:
                con = get_db()
                old = con.execute("SELECT * FROM bookings WHERE id=?", (bid,)).fetchone()
                if not old:
                    con.close()
                    self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                    return
                con.execute("UPDATE bookings SET status=?,updated_at=? WHERE id=?", (new_status, now_ts(), bid))
                con.commit()
                row = con.execute("SELECT * FROM bookings WHERE id=?", (bid,)).fetchone()
                con.close()
            broadcast()
            self.send_json({"booking": public_booking(row) if row else None})
            return
        self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        path = urlparse(self.path).path
        m = re.fullmatch(r"/api/bookings/([^/]+)", path)
        if m:
            user = self.require_user()
            if not user:
                return
            bid = m.group(1)
            with DB_LOCK:
                con = get_db()
                cur = con.execute("DELETE FROM bookings WHERE id=?", (bid,))
                con.commit()
                con.close()
            if cur.rowcount != 1:
                self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                return
            broadcast()
            self.send_json({"ok": True})
            return
        self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Dilijan Guesthouse app running at http://{HOST}:{PORT}")
    print(f"Database: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
