"""Підключення до банку через Enable Banking (PSD2). Лише стандартна бібліотека Python і openssl.

Налаштування лежить у DATA_DIR/bank.json, приватний ключ застосунку в DATA_DIR/enablebanking.pem.
Документація API: https://enablebanking.com/docs/api/reference
"""
import base64
import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone

API = os.environ.get("EB_API", "https://api.enablebanking.com")


class BankError(Exception):
    pass


class Bank:
    def __init__(self, data_dir, read_json, write_json):
        self.cfg_path = os.path.join(data_dir, "bank.json")
        self.key_path = os.path.join(data_dir, "enablebanking.pem")
        self.read_json, self.write_json = read_json, write_json

    # ---------- налаштування ----------
    def cfg(self):
        return self.read_json(self.cfg_path, {"app_id": None, "connections": [], "pending": {}})

    def configured(self):
        return bool(self.cfg().get("app_id")) and os.path.exists(self.key_path)

    # ---------- запити до API ----------
    def token(self, app_id):
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
        now = int(time.time())
        header = b64(json.dumps({"typ": "JWT", "alg": "RS256", "kid": app_id}).encode())
        payload = b64(json.dumps({"iss": "enablebanking.com", "aud": "api.enablebanking.com",
                                  "iat": now, "exp": now + 3600}).encode())
        signing_input = header + b"." + payload
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.key_path, "-binary"],
                             input=signing_input, capture_output=True, check=True).stdout
        return (signing_input + b"." + b64(sig)).decode()

    def call(self, method, path, body=None):
        cfg = self.cfg()
        if not self.configured():
            raise BankError("Підключення до банку ще не налаштоване")
        req = urllib.request.Request(API + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer " + self.token(cfg["app_id"]),
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise BankError(f"Enable Banking відповів {e.code}: {e.read()[:300].decode(errors='replace')}")

    # ---------- дії ----------
    def banks(self):
        return [{"name": a["name"], "psu_types": a.get("psu_types", [])}
                for a in self.call("GET", "/aspsps?country=PL").get("aspsps", [])]

    def status(self):
        cfg = self.cfg()
        return {"configured": self.configured(),
                "connections": [{k: c.get(k) for k in ("id", "bank", "account", "psu_type", "valid_until", "accounts", "last_fetch")}
                                for c in cfg["connections"]]}

    def start(self, bank, psu_type, account, redirect_url):
        aspsps = {a["name"]: a for a in self.call("GET", "/aspsps?country=PL").get("aspsps", [])}
        if bank not in aspsps:
            raise BankError("Банк не знайдено")
        seconds = aspsps[bank].get("maximum_consent_validity") or 90 * 86400
        valid_until = datetime.now(timezone.utc) + timedelta(seconds=min(seconds, 180 * 86400) - 60)
        state = secrets.token_urlsafe(16)
        res = self.call("POST", "/auth", {"access": {"valid_until": valid_until.isoformat()},
                                          "aspsp": {"name": bank, "country": "PL"},
                                          "state": state, "redirect_url": redirect_url, "psu_type": psu_type})
        cfg = self.cfg()
        cfg["pending"] = {state: {"bank": bank, "psu_type": psu_type, "account": account, "at": time.time()}}
        self.write_json(self.cfg_path, cfg)
        return res["url"]

    def finish(self, code, state):
        cfg = self.cfg()
        p = cfg.get("pending", {}).pop(state, None)
        if not p or time.time() - p["at"] > 3600:
            raise BankError("Посилання застаріло, почніть підключення знову")
        s = self.call("POST", "/sessions", {"code": code})
        accounts = [{"uid": a["uid"], "name": a.get("name") or (a.get("account_id") or {}).get("iban") or a["uid"]}
                    for a in s.get("accounts", [])]
        # нове підключення того ж банку й типу замінює старе (наприклад, після закінчення згоди)
        cfg["connections"] = [c for c in cfg["connections"] if not (c["bank"] == p["bank"] and c["account"] == p["account"])]
        cfg["connections"].append({"id": s["session_id"], "bank": p["bank"], "psu_type": p["psu_type"],
                                   "account": p["account"], "accounts": accounts,
                                   "valid_until": (s.get("access") or {}).get("valid_until"), "last_fetch": None})
        self.write_json(self.cfg_path, cfg)

    def remove(self, conn_id):
        cfg = self.cfg()
        cfg["connections"] = [c for c in cfg["connections"] if c["id"] != conn_id]
        self.write_json(self.cfg_path, cfg)
        try:
            self.call("DELETE", f"/sessions/{conn_id}")
        except BankError:
            pass

    def fetch(self):
        """Повертає операції з усіх підключень. Повтори відсіює браузер за полем ref."""
        cfg = self.cfg()
        out, errors = [], []
        for c in cfg["connections"]:
            # перший раз беремо 90 днів, далі з запасом у 7 днів від останнього оновлення
            since = date.today() - timedelta(days=90)
            if c.get("last_fetch"):
                since = max(since, date.fromisoformat(c["last_fetch"][:10]) - timedelta(days=7))
            try:
                for a in c["accounts"]:
                    key = None
                    while True:
                        q = {"date_from": since.isoformat()}
                        if key:
                            q["continuation_key"] = key
                        res = self.call("GET", f"/accounts/{a['uid']}/transactions?" + urllib.parse.urlencode(q))
                        out += [t for t in (convert(x, c["account"]) for x in res.get("transactions", [])) if t]
                        key = res.get("continuation_key")
                        if not key:
                            break
                c["last_fetch"] = date.today().isoformat()
            except BankError as e:
                errors.append(f"{c['bank']}: {e}")
        self.write_json(self.cfg_path, cfg)
        return {"transactions": out, "errors": errors}


def convert(t, account):
    if t.get("status") not in (None, "BOOK"):
        return None  # операції в обробці з'являться пізніше, вже проведеними
    amt = t.get("transaction_amount") or {}
    if (amt.get("currency") or "PLN") != "PLN":
        return None
    value = abs(float(amt.get("amount") or 0))
    if not value:
        return None
    sign = -1 if t.get("credit_debit_indicator") == "DBIT" else 1
    party = (t.get("creditor") if sign < 0 else t.get("debtor")) or {}
    info = t.get("remittance_information") or []
    note = " · ".join(x for x in [party.get("name"), *info] if x)
    d = t.get("booking_date") or t.get("transaction_date") or t.get("value_date")
    ref = t.get("entry_reference") or t.get("transaction_id") or f"{d}|{sign * value}|{note}"
    return {"ref": f"{account}:{ref}", "date": d, "amount": sign * value, "note": note, "account": account}
