#!/usr/bin/env python3
"""Невеликий сервер для збереження даних бюджету. Лише стандартна бібліотека Python.

Працює за nginx на 127.0.0.1. Дані лежать у DATA_DIR/data.json, пароль у вигляді хешу в DATA_DIR/config.json.
Встановити пароль:  python3 server.py --set-password
"""
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA_DIR = os.environ.get("DATA_DIR", "/var/lib/czeresniowski")
PORT = int(os.environ.get("PORT", "8765"))
SESSION_DAYS = 30
MAX_BODY = 10 * 1024 * 1024

CONFIG = os.path.join(DATA_DIR, "config.json")
DATA = os.path.join(DATA_DIR, "data.json")
SESSIONS = os.path.join(DATA_DIR, "sessions.json")
BACKUPS = os.path.join(DATA_DIR, "backups")

lock = threading.Lock()
failed = {}  # ip -> (кількість невдалих спроб, час останньої)


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False)
    os.replace(tmp, path)


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 300_000).hex()
    return {"salt": salt, "hash": digest}


def check_password(password):
    cfg = read_json(CONFIG, None)
    if not cfg:
        return False
    return hmac.compare_digest(hash_password(password, cfg["salt"])["hash"], cfg["hash"])


def set_password():
    os.makedirs(DATA_DIR, exist_ok=True)
    while True:
        p1 = getpass.getpass("Новий пароль для сайту: ")
        if len(p1) < 8:
            print("Пароль має бути не коротший за 8 символів")
            continue
        if p1 == getpass.getpass("Повторіть пароль: "):
            break
        print("Паролі не збігаються")
    write_json(CONFIG, hash_password(p1))
    write_json(SESSIONS, {})  # після зміни пароля всі мають увійти знову
    print("Пароль збережено")


def backup(data):
    # одна копія на день, останні 60 днів
    os.makedirs(BACKUPS, exist_ok=True)
    write_json(os.path.join(BACKUPS, time.strftime("data-%Y-%m-%d.json")), data)
    for old in sorted(os.listdir(BACKUPS))[:-60]:
        os.remove(os.path.join(BACKUPS, old))


class Handler(BaseHTTPRequestHandler):
    server_version = "czeresniowski"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_ip(), fmt % args))

    def client_ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def send(self, code, body=None, cookie=None):
        raw = json.dumps(body if body is not None else {}, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def session(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        token = c["sid"].value if "sid" in c else None
        if not token:
            return None
        with lock:
            sessions = read_json(SESSIONS, {})
            exp = sessions.get(token)
        return token if exp and exp > time.time() else None

    def cookie(self, token, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return f"sid={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def same_origin(self):
        # захист від запитів з чужих сайтів: браузер завжди надсилає Origin для POST/PUT
        origin = self.headers.get("Origin")
        return origin is None or origin.split("://", 1)[-1] == self.headers.get("Host")

    def do_GET(self):
        if self.path == "/api/data":
            if not self.session():
                return self.send(401)
            with lock:
                return self.send(200, read_json(DATA, {"rev": 0, "tx": []}))
        self.send(404)

    def do_POST(self):
        if not self.same_origin():
            return self.send(403)
        if self.path == "/api/login":
            ip = self.client_ip()
            count, last = failed.get(ip, (0, 0))
            if count >= 5 and time.time() - last < 60 * min(count - 4, 30):
                return self.send(429, {"error": "Забагато спроб, зачекайте кілька хвилин"})
            try:
                ok = check_password(str(self.body().get("password", "")))
            except ValueError:
                return self.send(400)
            if not ok:
                failed[ip] = (count + 1, time.time())
                return self.send(401, {"error": "Неправильний пароль"})
            failed.pop(ip, None)
            token = secrets.token_urlsafe(32)
            with lock:
                sessions = {t: e for t, e in read_json(SESSIONS, {}).items() if e > time.time()}
                sessions[token] = time.time() + SESSION_DAYS * 86400
                write_json(SESSIONS, sessions)
            return self.send(200, cookie=self.cookie(token, SESSION_DAYS * 86400))
        if self.path == "/api/logout":
            token = self.session()
            if token:
                with lock:
                    sessions = read_json(SESSIONS, {})
                    sessions.pop(token, None)
                    write_json(SESSIONS, sessions)
            return self.send(200, cookie=self.cookie("", 0))
        self.send(404)

    def do_PUT(self):
        if not self.same_origin():
            return self.send(403)
        if self.path != "/api/data":
            return self.send(404)
        if not self.session():
            return self.send(401)
        try:
            body = self.body()
            tx = body["tx"]
            assert isinstance(tx, list)
        except (ValueError, KeyError, AssertionError):
            return self.send(400)
        with lock:
            current = read_json(DATA, {"rev": 0, "tx": []})
            # якщо дані змінили з іншого пристрою, клієнт має спершу їх завантажити
            if body.get("rev") != current["rev"]:
                return self.send(409, current)
            new = {"rev": current["rev"] + 1, "tx": tx}
            write_json(DATA, new)
            backup(new)
        self.send(200, {"rev": new["rev"]})


if __name__ == "__main__":
    if "--set-password" in sys.argv:
        set_password()
        sys.exit()
    if not os.path.exists(CONFIG):
        sys.exit("Пароль не встановлено. Запустіть: python3 server.py --set-password")
    print(f"Сервер слухає 127.0.0.1:{PORT}, дані в {DATA_DIR}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
