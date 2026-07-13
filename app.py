import base64
import hashlib
import hmac
import ipaddress
import io
import json
import jwt
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
import urllib.error
from dotenv import load_dotenv

load_dotenv()

# Try to load SQLCipher binding; if DB_ENCRYPTION_KEY is not set, fall back to plain sqlite3.
try:
    import sqlcipher3
except ImportError:
    sqlcipher3 = None

import pyotp
import qrcode
import qrcode.image.svg
from datetime import timedelta
from flask import Flask, request, jsonify, render_template_string, render_template, send_file, g, session
app = Flask(__name__, template_folder='.')


def _is_trusted_proxy(remote_addr):
    """Verifica si remote_addr pertenece a un proxy reverso de confianza."""
    trusted = os.environ.get('TRUSTED_PROXIES', '')
    if not trusted:
        return False
    for network in trusted.split(','):
        network = network.strip()
        if not network:
            continue
        try:
            if '/' in network:
                if ipaddress.ip_address(remote_addr) in ipaddress.ip_network(network, strict=False):
                    return True
            elif remote_addr == network:
                return True
        except ValueError:
            continue
    return False


def _get_raw_client_ip():
    remote = request.remote_addr or "unknown"

    if remote != "unknown" and _is_trusted_proxy(remote):
        if "CF-Connecting-IP" in request.headers:
            return request.headers["CF-Connecting-IP"]

        if "X-Forwarded-For" in request.headers:
            return request.headers["X-Forwarded-For"].split(",")[0].strip()

        if "X-Real-IP" in request.headers:
            return request.headers["X-Real-IP"]

    return remote


def get_ip_prefix(ip, v4_len=24, v6_len=64):
    """Devuelve el prefijo de red de una IP. Si LOG_IP_FULL es true, devuelve la IP completa."""
    if ip in (None, "unknown"):
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return str(ipaddress.ip_network((addr, v4_len), strict=False))
        return str(ipaddress.ip_network((addr, v6_len), strict=False))
    except ValueError:
        return "unknown"


def get_client_ip():
    """Devuelve el identificador de IP usado para lógica de rate limiting, sesión y dificultad.

    Si LOG_IP_FULL es true, usa la IP completa; de lo contrario, usa el prefijo
    de red (/24 para IPv4, /64 para IPv6) para minimizar datos personales.
    """
    raw = _get_raw_client_ip()
    if LOG_IP_FULL:
        return raw
    return get_ip_prefix(raw)

DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), "menta.db"))
DB_ENCRYPTION_KEY = os.environ.get('DB_ENCRYPTION_KEY', '')
DATA_RETENTION_HOURS = int(os.environ.get('DATA_RETENTION_HOURS', 24))
ACCOUNT_INACTIVITY_DAYS = int(os.environ.get('ACCOUNT_INACTIVITY_DAYS', 30))
LOG_IP_FULL = os.environ.get('LOG_IP_FULL', 'false').lower() in ('1', 'true', 'yes', 'on')

CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '')
CORS_MODE = os.environ.get('CORS_MODE', 'strict')  # strict or permissive
PROXY_FAIL_CLOSED = os.environ.get('PROXY_FAIL_CLOSED', 'true').lower() in ('1', 'true', 'yes', 'on')

RL_INIT_PER_TENANT = os.environ.get('RL_INIT_PER_TENANT', '60,3600')
RL_CHALLENGE_PER_TENANT = os.environ.get('RL_CHALLENGE_PER_TENANT', '120,3600')
RL_REDEEM_PER_TENANT = os.environ.get('RL_REDEEM_PER_TENANT', '120,3600')
RL_VERIFY_PER_TENANT = os.environ.get('RL_VERIFY_PER_TENANT', '120,3600')
RL_GLOBAL_INIT = os.environ.get('RL_GLOBAL_INIT', '1000,3600')
RL_GLOBAL_CHALLENGE = os.environ.get('RL_GLOBAL_CHALLENGE', '2000,3600')
RL_GLOBAL_REDEEM = os.environ.get('RL_GLOBAL_REDEEM', '2000,3600')
RL_GLOBAL_VERIFY = os.environ.get('RL_GLOBAL_VERIFY', '2000,3600')

MIN_DIFFICULTY = os.environ.get('MIN_DIFFICULTY', '')
DIFFICULTY_NEW_IP = os.environ.get('DIFFICULTY_NEW_IP', '')

TRIAL_DAYS = int(os.environ.get('TRIAL_DAYS', 45))
DOMAIN_COOLDOWN_DAYS = int(os.environ.get('DOMAIN_COOLDOWN_DAYS', 182))
SUPPORT_INACTIVITY_DAYS = int(os.environ.get('SUPPORT_INACTIVITY_DAYS', 30))
NTFY_BASE_URL = os.environ.get('NTFY_BASE_URL', 'https://ntfy.sh').rstrip('/')
NTFY_ADMIN_TOPIC = os.environ.get('NTFY_ADMIN_TOPIC', '')


def get_db():
    """Open the database. If DB_ENCRYPTION_KEY is set, use SQLCipher via sqlcipher3."""
    use_sqlcipher = DB_ENCRYPTION_KEY and sqlcipher3 is not None
    if use_sqlcipher:
        conn = sqlcipher3.connect(DB_PATH)
        conn.row_factory = sqlcipher3.Row
        # Safe string literal for the PRAGMA key
        key_escaped = DB_ENCRYPTION_KEY.replace("'", "''")
        conn.execute("PRAGMA key='{}'".format(key_escaped))
        try:
            conn.execute("SELECT 1")
        except Exception:
            # If the existing DB is plain, back it up and create a fresh encrypted one.
            if os.path.exists(DB_PATH):
                backup = DB_PATH + '.legacy-' + str(int(time.time()))
                os.rename(DB_PATH, backup)
                print('[DB] Backed up plain database to:', backup)
            conn = sqlcipher3.connect(DB_PATH)
            conn.row_factory = sqlcipher3.Row
            conn.execute("PRAGMA key='{}'".format(key_escaped))
    else:
        if DB_ENCRYPTION_KEY and sqlcipher3 is None:
            print('[WARN] DB_ENCRYPTION_KEY is set but sqlcipher3 is not installed; using plain sqlite3.')
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS challenges (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT '',
                salt TEXT NOT NULL,
                target TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                tenant_id TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rl ON rate_limits(tenant_id, ip, endpoint, timestamp)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits_tenant (
                tenant_id TEXT NOT NULL DEFAULT '',
                endpoint TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rlt ON rate_limits_tenant(tenant_id, endpoint, timestamp)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits_global (
                endpoint TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rlg ON rate_limits_global(endpoint, timestamp)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                account_number TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT '',
                domains TEXT NOT NULL DEFAULT '',
                primary_domain TEXT NOT NULL DEFAULT '',
                plan TEXT NOT NULL DEFAULT 'beginner',
                status TEXT NOT NULL DEFAULT 'trial',
                trial_started_at REAL,
                payment_activated_at REAL,
                ntfy_topic TEXT,
                totp_secret TEXT,
                created_at REAL NOT NULL,
                last_seen_at REAL NOT NULL,
                notes TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts ON accounts(tenant_id, last_seen_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_history (
                domain_root TEXT PRIMARY KEY,
                account_number TEXT NOT NULL,
                first_seen_at REAL NOT NULL,
                last_active_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                release_after REAL,
                paid INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_history ON domain_history(account_number, status, last_active_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                id TEXT PRIMARY KEY,
                account_number TEXT,
                ntfy_topic TEXT,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at REAL NOT NULL,
                last_reply_at REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_support_tickets ON support_tickets(status, created_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS support_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT NOT NULL,
                author TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_support_replies ON support_replies(ticket_id, created_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_2fa (
                id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS totp_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_totp_recovery ON totp_recovery_codes(owner, used)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS solved_challenges (
                tenant_id TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                solve_time REAL NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sc ON solved_challenges(tenant_id, ip, timestamp)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_s ON sessions(tenant_id, expires)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS verified_tokens (
                jti TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT '',
                verified_at REAL NOT NULL,
                expires REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vt ON verified_tokens(tenant_id, expires)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS failed_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                reason TEXT NOT NULL,
                challenge_id TEXT,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fa ON failed_attempts(tenant_id, ip, timestamp)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint TEXT NOT NULL,
                token_type TEXT NOT NULL,
                ip TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_aal ON admin_access_log(endpoint, timestamp)")

init_db()

def _migrate():
    with get_db() as conn:
        # Legacy columns
        cols = {r[1] for r in conn.execute("PRAGMA table_info(challenges)").fetchall()}
        if "created_at" not in cols:
            conn.execute("ALTER TABLE challenges ADD COLUMN created_at REAL NOT NULL DEFAULT 0")
        cols2 = {r[1] for r in conn.execute("PRAGMA table_info(solved_challenges)").fetchall()}
        if "solve_time" not in cols2:
            conn.execute("ALTER TABLE solved_challenges ADD COLUMN solve_time REAL NOT NULL DEFAULT 30")
        # Tenant separation for SaaS
        for table in ["challenges", "rate_limits", "solved_challenges", "sessions", "failed_attempts"]:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
            if "tenant_id" not in cols:
                conn.execute("ALTER TABLE %s ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''" % table)
        # Accounts trial/payment columns
        cols_accounts = {r[1] for r in conn.execute("PRAGMA table_info(accounts)").fetchall()}
        for col in ["primary_domain", "plan", "status", "ntfy_topic", "totp_secret"]:
            if col not in cols_accounts:
                conn.execute("ALTER TABLE accounts ADD COLUMN %s TEXT" % col)
        for col in ["trial_started_at", "payment_activated_at"]:
            if col not in cols_accounts:
                conn.execute("ALTER TABLE accounts ADD COLUMN %s REAL" % col)
        # New tables for domain anti-bypass and support tickets
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_history (
                domain_root TEXT PRIMARY KEY,
                account_number TEXT NOT NULL,
                first_seen_at REAL NOT NULL,
                last_active_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                release_after REAL,
                paid INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_history ON domain_history(account_number, status, last_active_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                id TEXT PRIMARY KEY,
                account_number TEXT,
                ntfy_topic TEXT,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at REAL NOT NULL,
                last_reply_at REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_support_tickets ON support_tickets(status, created_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS support_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT NOT NULL,
                author TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_support_replies ON support_replies(ticket_id, created_at)")
        cols_aal = {r[1] for r in conn.execute("PRAGMA table_info(admin_access_log)").fetchall()}
        if "admin_access_log" not in {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS admin_access_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint TEXT NOT NULL,
                    token_type TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_aal ON admin_access_log(endpoint, timestamp)")
        # 2FA tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_2fa (
                id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS totp_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_totp_recovery ON totp_recovery_codes(owner, used)")
_migrate()

def _cleanup():
    """Removes expired data so the database does not grow indefinitely."""
    try:
        now = time.time()
        retention = max(3600, DATA_RETENTION_HOURS * 3600)
        with get_db() as conn:
            # Tables with explicit expiry columns are purged by that column.
            for table, col, window in [
                ("challenges", "expires", 0),
                ("sessions", "expires", 0),
                ("verified_tokens", "expires", 0),
                ("rate_limits", "timestamp", min(3600, retention)),
                ("rate_limits_tenant", "timestamp", min(3600, retention)),
                ("rate_limits_global", "timestamp", min(3600, retention)),
                ("solved_challenges", "timestamp", min(7200, retention)),
                ("failed_attempts", "timestamp", min(86400, retention)),
                ("accounts", "last_seen_at", ACCOUNT_INACTIVITY_DAYS * 86400),
                ("domain_history", "last_active_at", ACCOUNT_INACTIVITY_DAYS * 86400),
            ]:
                conn.execute("DELETE FROM %s WHERE %s < ?" % (table, col), (now - window,))
            # Support tickets are deleted after SUPPORT_INACTIVITY_DAYS of inactivity
            # (last reply or, if none, ticket creation), then their replies are purged too.
            cutoff = now - (SUPPORT_INACTIVITY_DAYS * 86400)
            conn.execute("DELETE FROM support_tickets WHERE COALESCE(last_reply_at, created_at) < ?", (cutoff,))
            conn.execute("DELETE FROM support_replies WHERE ticket_id NOT IN (SELECT id FROM support_tickets)")
        print("[CLEANUP] Expired data removed")
    except Exception as e:
        print("[CLEANUP ERROR] %s" % e)
_cleanup()

def current_tenant():
    """Identificador de tenant para separación por API key en SaaS."""
    return getattr(g, 'tenant_id', '')


@app.before_request
def set_tenant():
    """Lee el tenant desde el header X-API-Key o, en SaaS, dedúcelo del origen CORS."""
    api_key = request.headers.get('X-API-Key', '')
    if api_key:
        g.tenant_id = api_key
    else:
        origin = request.headers.get('Origin')
        account = get_account_by_origin(origin) if origin else None
        g.tenant_id = account['account_number'] if account else ''


def _get_account_auth():
    """Extrae el número de cuenta de Authorization Bearer o X-API-Key.
    Si el token es un JWT de sesión, lo decodifica y devuelve (account_number, verified).
    Si es un número de cuenta directo, devuelve (account_number, False).
    """
    auth = request.headers.get('Authorization', '')
    token = request.headers.get('X-API-Key', '')
    if auth.startswith('Bearer '):
        token = auth[7:].strip()
    if not token:
        return '', False
    # Try JWT session token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if payload.get('type') == 'account_session':
            return payload.get('account_number', ''), True
    except Exception:
        pass
    # Raw account number (allowed only if account has no 2FA, verified below)
    return token, False


def _issue_account_token(account_number, verified=True, expires=86400):
    """Emite un JWT de sesión para una cuenta."""
    now = time.time()
    return jwt.encode(
        {'type': 'account_session', 'account_number': account_number, 'verified': verified, 'iat': now, 'exp': now + expires},
        SECRET_KEY,
        algorithm='HS256'
    )


def generate_account_number():
    """Genera un número de cuenta de 16 dígitos único."""
    while True:
        number = ''.join(str(secrets.randbelow(10)) for _ in range(16))
        with get_db() as conn:
            exists = conn.execute("SELECT 1 FROM accounts WHERE account_number = ?", (number,)).fetchone()
        if not exists:
            return number


def get_account(tenant_id):
    """Obtiene la cuenta asociada al tenant_id (número de cuenta)."""
    if not tenant_id:
        return None
    try:
        with get_db() as conn:
            return conn.execute("SELECT * FROM accounts WHERE tenant_id = ? OR account_number = ?", (tenant_id, tenant_id)).fetchone()
    except Exception:
        return None


def update_account_last_seen(tenant_id):
    """Actualiza el último visto de una cuenta."""
    if not tenant_id:
        return
    try:
        with get_db() as conn:
            conn.execute("UPDATE accounts SET last_seen_at = ? WHERE tenant_id = ? OR account_number = ?", (time.time(), tenant_id, tenant_id))
    except Exception:
        pass


def normalize_domain(value):
    """Extrae y normaliza el hostname de un origen o dominio."""
    if not value:
        return None
    value = value.strip().lower()
    # Remove leading wildcard prefix
    if value.startswith('*.'):
        value = value[2:]
    if value.startswith('*'):
        value = value[1:]
    # Strip scheme and path
    if '://' in value:
        parsed = urllib.parse.urlparse(value)
        host = parsed.hostname
    else:
        host = value.split('/')[0].split(':')[0]
    if not host:
        return None
    # Remove leading www. to treat it as root
    if host.startswith('www.'):
        host = host[4:]
    # Remove trailing dot
    host = host.rstrip('.')
    if not host or '.' not in host:
        return None
    return host


def _normalize_domains_input(domains):
    """Convierte una lista de dominios a una cadena separada por comas, normalizando saltos de línea."""
    if not domains:
        return ''
    if isinstance(domains, list):
        domains = ','.join(str(d).strip() for d in domains if d)
    domains = domains.replace('\r\n', ',').replace('\n', ',').replace('\r', ',')
    return domains


def _count_valid_domains(domains):
    """Cuenta los dominios validos en una cadena separada por comas."""
    domains = _normalize_domains_input(domains)
    if not domains:
        return 0
    count = 0
    for d in domains.split(','):
        if normalize_domain(d):
            count += 1
    return count


def _check_domain_plan_limit(domains, plan):
    """Devuelve (None) si el plan permite los dominios, o (response, status) si excede."""
    if plan == 'developer':
        return None
    count = _count_valid_domains(domains)
    if count > 1:
        return jsonify({"error": "Beginner plan allows only 1 domain. Upgrade to Developer for unlimited domains."}), 400
    return None


def domain_overlap(a, b):
    """Verifica si dos nombres de dominio se solapan (igual, subdominio o padre)."""
    if not a or not b:
        return False
    a = a.rstrip('.')
    b = b.rstrip('.')
    if a == b:
        return True
    return a.endswith('.' + b) or b.endswith('.' + a)


def get_account_by_origin(origin):
    """Busca la cuenta SaaS activa asociada a un origen CORS usando el historial de dominios."""
    if not origin:
        return None
    host = normalize_domain(origin)
    if not host:
        return None
    try:
        with get_db() as conn:
            # active domains only
            rows = conn.execute(
                "SELECT * FROM domain_history WHERE status = 'active'"
            ).fetchall()
            for row in rows:
                if domain_overlap(host, row['domain_root']):
                    return get_account(row['account_number'])
    except Exception:
        pass
    return None


def _is_same_origin(origin):
    """Verifica si el Origin coincide con el host actual (same-origin)."""
    if not origin:
        return True
    try:
        parsed = urllib.parse.urlparse(origin)
        origin_host = parsed.hostname
        origin_port = parsed.port
        if not origin_host:
            return False
        request_host = request.host.split(':')[0]
        # During local development 127.0.0.1, localhost and any port are equivalent
        loopbacks = ('localhost', '127.0.0.1', '::1')
        if origin_host in loopbacks and request_host in loopbacks:
            return True
        if origin_host == request_host:
            return True
        # If the server is accessed through a non-standard port, compare host ignoring port
        if request.host == origin_host or request.host == (origin_host + ((':' + str(origin_port)) if origin_port else '')):
            return True
        return False
    except Exception:
        return False


def is_origin_allowed(tenant_id, origin):
    """Verifica si el origen está permitido para el tenant usando solapamiento de dominios."""
    if not origin:
        return True  # petición same-origin no envía Origin
    if _is_same_origin(origin):
        return True
    host = normalize_domain(origin)
    if not host:
        return False
    if tenant_id:
        account = get_account(tenant_id)
        if not account:
            return False
        # primary domain always covers subdomains
        if domain_overlap(host, account['primary_domain']):
            return True
        allowed = {d.strip() for d in (account['domains'] or '').split(',') if d.strip()}
        for d in allowed:
            if domain_overlap(host, normalize_domain(d)):
                return True
        return False
    # Modo self-hosted
    if CORS_ORIGINS == '*':
        return True
    if not CORS_ORIGINS:
        return CORS_MODE != 'strict'
    allowed = {d.strip().rstrip('/') for d in CORS_ORIGINS.split(',') if d.strip()}
    return origin in allowed


def check_account_status(tenant_id):
    """Verifica si una cuenta SaaS puede usar los endpoints protegidos."""
    if not tenant_id:
        return {'ok': True}
    account = get_account(tenant_id)
    if not account:
        return {'ok': True}  # self-hosted no requiere cuenta
    now = time.time()
    status = account['status']
    trial_started_raw = account['trial_started_at']
    try:
        trial_started = float(trial_started_raw) if trial_started_raw else 0
    except (ValueError, TypeError):
        trial_started = 0
    trial_expires = trial_started + (TRIAL_DAYS * 86400)
    days_left = int((trial_expires - now) / 86400) if status == 'trial' else 0

    if status == 'active':
        return {'ok': True, 'status': 'active', 'days_left': None}
    if status == 'trial':
        if now < trial_expires:
            return {'ok': True, 'status': 'trial', 'days_left': max(0, days_left)}
        # Trial expired; move to expired and lock domain
        _expire_account(tenant_id)
        return {
            'ok': False,
            'status': 'expired',
            'days_left': 0,
            'error': 'Trial expired. Contact support to activate your account.',
            'support_url': '/support?subject=trial-expired'
        }
    if status == 'pending_claim':
        return {
            'ok': False,
            'status': 'pending_claim',
            'days_left': 0,
            'error': 'Account pending domain verification. Open a support claim.',
            'support_url': '/support?subject=domain-claim'
        }
    if status in ('expired', 'suspended'):
        return {
            'ok': False,
            'status': status,
            'days_left': 0,
            'error': 'Account inactive. Contact support to reactivate.',
            'support_url': '/support?subject=account-reactivate'
        }
    return {'ok': True}


def _expire_account(account_number):
    """Marca una cuenta como expirada y bloquea su dominio durante el periodo de cooldown."""
    try:
        now = time.time()
        release = now + (DOMAIN_COOLDOWN_DAYS * 86400)
        with get_db() as conn:
            conn.execute(
                "UPDATE accounts SET status = 'expired' WHERE account_number = ?",
                (account_number,)
            )
            conn.execute(
                "UPDATE domain_history SET status = 'locked', release_after = ? WHERE account_number = ? AND status = 'active'",
                (release, account_number)
            )
    except Exception:
        pass


def _release_domain(domain_root):
    """Libera un dominio del historial para permitir nuevo registro."""
    try:
        with get_db() as conn:
            conn.execute(
                "UPDATE domain_history SET status = 'released', release_after = NULL WHERE domain_root = ?",
                (domain_root,)
            )
    except Exception:
        pass


def check_domain_conflict(domain_root, account_number=None):
    """Verifica si un dominio ya está registrado."""
    if not domain_root:
        return None
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_history WHERE status IN ('active', 'locked')"
            ).fetchall()
            for row in rows:
                if domain_overlap(domain_root, row['domain_root']):
                    if account_number and row['account_number'] == account_number:
                        continue
                    # if locked, check if it was paid
                    if row['status'] == 'locked':
                        release = row['release_after'] or 0
                        days_inactive = int((time.time() - (release - DOMAIN_COOLDOWN_DAYS * 86400)) / 86400) if release else 0
                        return {
                            'type': 'locked',
                            'domain': row['domain_root'],
                            'account_number': row['account_number'],
                            'paid': bool(row['paid']),
                            'days_inactive': days_inactive,
                            'release_after': release,
                            'days_until_release': int((release - time.time()) / 86400) if release > time.time() else 0
                        }
                    return {
                        'type': 'active',
                        'domain': row['domain_root'],
                        'account_number': row['account_number']
                    }
    except Exception:
        pass
    return None


def _register_domain_for_account(account_number, domain_root, paid=False, status='active'):
    """Registra un dominio en el historial para una cuenta."""
    if not domain_root:
        return
    now = time.time()
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO domain_history (domain_root, account_number, first_seen_at, last_active_at, status, paid) VALUES (?, ?, COALESCE((SELECT first_seen_at FROM domain_history WHERE domain_root = ?), ?), ?, ?, ?)",
                (domain_root, account_number, domain_root, now, now, status, 1 if paid else 0)
            )
    except Exception:
        pass


def _notify_ntfy(topic, message, link=None):
    """Envía una notificación a un topic de ntfy."""
    if not topic:
        return
    try:
        url = NTFY_BASE_URL + '/' + urllib.parse.quote(topic, safe='')
        headers = {'Content-Type': 'text/plain; charset=utf-8'}
        if link:
            headers['Actions'] = 'view, Open, ' + link
        payload = message.encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers=headers, method='POST')
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def _support_link(ticket_id, request=None):
    """Construye el enlace secreto a un ticket."""
    host = ''
    if request:
        host = request.host_url.rstrip('/')
    return host + '/support/' + ticket_id


def check_proxy_misconfiguration():
    """Detecta si hay headers de proxy pero el origen no está en TRUSTED_PROXIES."""
    remote = request.remote_addr or "unknown"
    if remote == "unknown":
        return False
    proxy_headers = ['CF-Connecting-IP', 'X-Real-IP', 'X-Forwarded-For']
    if not any(h in request.headers for h in proxy_headers):
        return False
    return not _is_trusted_proxy(remote)


def _parse_rate_limit(value):
    """Parsea 'count,window_seconds' en una tupla."""
    if not value:
        return None, None
    parts = value.split(',')
    if len(parts) != 2:
        return None, None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None, None


def check_rate_limit_tenant(tenant_id, endpoint, limit_str):
    """Rate limit por tenant (cuenta) para mitigar farms distribuidas."""
    if not tenant_id or not limit_str:
        return True
    max_requests, window = _parse_rate_limit(limit_str)
    if max_requests is None:
        return True
    now = time.time()
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM rate_limits_tenant WHERE tenant_id = ? AND endpoint = ? AND timestamp > ?",
            (tenant_id, endpoint, now - window)
        ).fetchone()[0]
        if count >= max_requests:
            return False
        conn.execute(
            "INSERT INTO rate_limits_tenant (tenant_id, endpoint, timestamp) VALUES (?, ?, ?)",
            (tenant_id, endpoint, now)
        )
    return True


def check_rate_limit_global(endpoint, limit_str):
    """Rate limit global para todo el servicio."""
    max_requests, window = _parse_rate_limit(limit_str)
    if max_requests is None:
        return True
    now = time.time()
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM rate_limits_global WHERE endpoint = ? AND timestamp > ?",
            (endpoint, now - window)
        ).fetchone()[0]
        if count >= max_requests:
            return False
        conn.execute(
            "INSERT INTO rate_limits_global (endpoint, timestamp) VALUES (?, ?)",
            (endpoint, now)
        )
    return True


def _max_difficulty(a, b):
    """Devuelve la dificultad más alta (más ceros)."""
    if not a:
        return b
    if not b:
        return a
    return a if len(a) >= len(b) else b


def _has_recent_solves(ip, tenant_id=''):
    """Indica si la IP/tenant tiene solves recientes."""
    with get_db() as conn:
        return conn.execute(
            "SELECT 1 FROM solved_challenges WHERE tenant_id = ? AND ip = ? AND timestamp > ? LIMIT 1",
            (tenant_id, ip, time.time() - 3600)
        ).fetchone() is not None


def check_browser_signals(tenant_id, origin):
    """Valida señales de browser sin usar cookies ni fingerprinting."""
    if origin and not is_origin_allowed(tenant_id, origin):
        return False, "origin_not_allowed"
    referer = request.headers.get('Referer')
    if referer and origin:
        if not referer.startswith(origin):
            return False, "referer_mismatch"
    sec_fetch_site = request.headers.get('Sec-Fetch-Site')
    sec_fetch_mode = request.headers.get('Sec-Fetch-Mode')
    if sec_fetch_site and sec_fetch_mode:
        # petición cross-origin debe venir de otro sitio o same-site, no 'none' salvo navegación directa
        if sec_fetch_site == 'none' and sec_fetch_mode != 'navigate':
            return False, "fetch_metadata_suspicious"
    return True, None


def get_difficulty(ip, tenant_id=''):
    """Adaptive difficulty: combines average nonce, solve time and recent failures."""
    if DIFFICULTY_NEW_IP and not _has_recent_solves(ip, tenant_id):
        return _max_difficulty(DIFFICULTY_NEW_IP, MIN_DIFFICULTY)

    now = time.time()
    with get_db() as conn:
        solves = conn.execute(
            "SELECT nonce, solve_time FROM solved_challenges WHERE tenant_id = ? AND ip = ? AND timestamp > ?",
            (tenant_id, ip, now - 3600)
        ).fetchall()
        fails = conn.execute(
            "SELECT COUNT(*) FROM failed_attempts WHERE tenant_id = ? AND ip = ? AND timestamp > ?",
            (tenant_id, ip, now - 600)
        ).fetchone()[0]

    if not solves:
        if fails > 2:
            return _max_difficulty("000000", MIN_DIFFICULTY)
        return _max_difficulty("0000", MIN_DIFFICULTY)

    count = len(solves)
    avg_nonce = sum(s["nonce"] for s in solves) / count
    avg_solve_time = sum(s["solve_time"] for s in solves) / count

    low_nonce = avg_nonce < 500
    fast_solve = avg_solve_time < 1.0

    result = "0000"
    if fails > 5:
        result = "0000000"
    elif fails > 2:
        result = "000000"
    elif (low_nonce or fast_solve) and count >= 3:
        result = "000000"
    elif count >= 5:
        result = "00000"

    return _max_difficulty(result, MIN_DIFFICULTY)

def log_failure(ip, endpoint, reason, challenge_id=None, tenant_id=''):
    """Logs a failed attempt for audit and attack detection."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO failed_attempts (tenant_id, ip, endpoint, reason, challenge_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (tenant_id, ip, endpoint, reason, challenge_id, time.time())
            )
    except Exception as e:
        print("[AUDIT ERROR] %s" % e)

def check_rate_limit(ip, endpoint, max_requests, window_seconds, tenant_id=''):
    now = time.time()
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE tenant_id = ? AND ip = ? AND endpoint = ? AND timestamp > ?",
            (tenant_id, ip, endpoint, now - window_seconds)
        ).fetchone()[0]
        if count >= max_requests:
            return False
        conn.execute(
            "INSERT INTO rate_limits (tenant_id, ip, endpoint, timestamp) VALUES (?, ?, ?, ?)",
            (tenant_id, ip, endpoint, now)
        )
    return True

def check_bot_signals(ip, tenant_id=''):
    """Detects IPs with suspicious patterns before spending resources on challenge."""
    now = time.time()
    with get_db() as conn:
        recent_fails = conn.execute(
            "SELECT COUNT(*) FROM failed_attempts WHERE tenant_id = ? AND ip = ? AND timestamp > ?",
            (tenant_id, ip, now - 600)
        ).fetchone()[0]
        if recent_fails > 5:
            return True, "too_many_failures"
        recent_challenges = conn.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE tenant_id = ? AND ip = ? AND endpoint = '/challenge' AND timestamp > ?",
            (tenant_id, ip, now - 60)
        ).fetchone()[0]
        if recent_challenges > 5:
            return True, "challenge_flood"
    return False, None

def check_nonce_entropy(ip, nonce, tenant_id=''):
    """Detects reused or suspiciously low nonces."""
    try:
        nonce_int = int(nonce)
    except (ValueError, TypeError):
        return False, "invalid_nonce"
    if nonce_int <= 0:
        return False, "invalid_nonce"
    now = time.time()
    with get_db() as conn:
        recent = conn.execute(
            "SELECT COUNT(*) FROM solved_challenges WHERE tenant_id = ? AND ip = ? AND nonce = ? AND timestamp > ?",
            (tenant_id, ip, nonce_int, now - 3600)
        ).fetchone()[0]
        if recent > 0:
            return False, "nonce_reuse"
        if nonce_int < 100:
            count = conn.execute(
                "SELECT COUNT(*) FROM solved_challenges WHERE tenant_id = ? AND ip = ? AND nonce < 100 AND timestamp > ?",
                (tenant_id, ip, now - 3600)
            ).fetchone()[0]
            if count > 3:
                return False, "low_nonce_pattern"
    return True, None

def check_client_pattern(ip, solve_time, nonce=None, tenant_id=''):
    """Detects bots with suspiciously consistent solve times or nonce patterns."""
    now = time.time()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT solve_time, nonce FROM solved_challenges WHERE tenant_id = ? AND ip = ? AND timestamp > ?",
            (tenant_id, ip, now - 1800)
        ).fetchall()
    if len(rows) < 5:
        return True, None
    times = [r["solve_time"] for r in rows]
    mean = sum(times) / len(times)
    variance = sum((t - mean) ** 2 for t in times) / len(times)
    stddev = variance ** 0.5
    if stddev < 0.05:
        return False, "too_consistent"
    nonces = [r["nonce"] for r in rows]
    if len(nonces) >= 5:
        mean_n = sum(nonces) / len(nonces)
        var_n = sum((n - mean_n) ** 2 for n in nonces) / len(nonces)
        if var_n < 100:
            return False, "nonce_too_consistent"
    return True, None

@app.before_request
def enforce_proxy_and_cors():
    """Rechaza peticiones con proxy mal configurado y origenes no autorizados."""
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin')
        tenant = current_tenant()
        if origin and not is_origin_allowed(tenant, origin):
            return jsonify({
                "success": False,
                "error": "This domain is not registered or authorized by Menta.",
                "origin": origin,
                "support_url": "/support?subject=domain-not-authorized"
            }), 403
        return None

    if check_proxy_misconfiguration():
        if PROXY_FAIL_CLOSED:
            return jsonify({"success": False, "error": "Proxy misconfiguration. TRUSTED_PROXIES must be set."}), 400

    origin = request.headers.get('Origin')
    if origin and not is_origin_allowed(current_tenant(), origin):
        return jsonify({
            "success": False,
            "error": "This domain is not registered or authorized by Menta.",
            "origin": origin,
            "support_url": "/support?subject=domain-not-authorized"
        }), 403


@app.after_request
def cors(response):
    origin = request.headers.get('Origin')
    tenant = current_tenant()
    if origin and is_origin_allowed(tenant, origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    else:
        response.headers.pop('Access-Control-Allow-Origin', None)
        response.headers.pop('Access-Control-Allow-Headers', None)
        response.headers.pop('Access-Control-Allow-Methods', None)
    return response


@app.after_request
def security_headers(response):
    """Añade headers de seguridad y privacidad a cada respuesta."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
    return response

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(days=30)

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", '')
ADMIN_TOKEN_READONLY = os.environ.get("ADMIN_TOKEN_READONLY", '')


def _admin_authorized(readonly=False, skip_totp=False):
    """Valida token de admin. readonly=True permite el token de solo lectura.
    Cuando 2FA admin está configurado, requiere además X-Admin-TOTP o X-Admin-Recovery-Code,
    a menos que exista una sesión recordada activa.
    skip_totp permite endpoints de setup 2FA sin código TOTP.
    """
    auth = request.headers.get('Authorization', '')
    expected_full = f'Bearer {ADMIN_TOKEN}'
    expected_ro = f'Bearer {ADMIN_TOKEN_READONLY}'
    token_type = None
    if hmac.compare_digest(auth, expected_full):
        token_type = 'full'
    elif readonly and ADMIN_TOKEN_READONLY and hmac.compare_digest(auth, expected_ro):
        token_type = 'readonly'

    if skip_totp:
        if token_type:
            return True, token_type, False
        # Check remembered session for setup endpoints
        required_type = 'full' if not readonly else None
        if _admin_session_valid(required_type):
            return True, session.get('admin_token_type', 'full'), False
        return False, None, False

    if not token_type:
        # Check remembered session
        required_type = 'full' if not readonly else None
        if _admin_session_valid(required_type):
            return True, session.get('admin_token_type', 'full'), False
        return False, None, False

    # TOTP admin
    admin_secret = _get_admin_totp_secret()
    if admin_secret:
        totp = request.headers.get('X-Admin-TOTP', '')
        recovery = request.headers.get('X-Admin-Recovery-Code', '')
        if totp and pyotp.TOTP(admin_secret).verify(totp, valid_window=1):
            remember = request.headers.get('X-Remember-Me', 'false').lower() == 'true'
            _refresh_admin_session(token_type, remember)
            return True, token_type, False
        if recovery and _consume_recovery_code('__admin__', recovery):
            remember = request.headers.get('X-Remember-Me', 'false').lower() == 'true'
            _refresh_admin_session(token_type, remember)
            return True, token_type, False
        # Check remembered session for this token
        if _admin_session_valid(token_type):
            return True, token_type, False
        return False, None, False
    # No admin 2FA configured -> force setup
    return False, None, True


def _admin_session_valid(token_type=None):
    """Verifica si existe una sesión de admin recordada activa."""
    try:
        session_token = session.get('admin_token')
        session_expires = session.get('admin_session_expires', 0)
        if not session_token or not session_expires or session_expires < time.time():
            return False
        if session_token not in (ADMIN_TOKEN, ADMIN_TOKEN_READONLY):
            return False
        session_token_type = session.get('admin_token_type')
        if token_type and session_token_type != token_type:
            return False
        return True
    except Exception:
        return False


def _refresh_admin_session(token_type, remember=True):
    """Refresca o crea la sesión de admin."""
    try:
        session['admin_token'] = ADMIN_TOKEN if token_type == 'full' else ADMIN_TOKEN_READONLY
        session['admin_token_type'] = token_type
        session['admin_2fa_verified'] = True
        session['admin_session_expires'] = time.time() + (30 * 24 * 60 * 60)
        if remember:
            session.permanent = True
        else:
            session.permanent = False
    except Exception:
        pass


def _get_admin_totp_secret():
    """Devuelve el secret TOTP del admin, o None si no está configurado."""
    try:
        with get_db() as conn:
            row = conn.execute("SELECT secret FROM admin_2fa WHERE id = 1").fetchone()
            return row['secret'] if row else None
    except Exception:
        return None


def _generate_recovery_codes(owner, count=8):
    """Genera códigos de recuperación, almacena sus hashes y los devuelve en texto claro una sola vez."""
    codes = [''.join(str(secrets.randbelow(10)) for _ in range(8)) for _ in range(count)]
    now = time.time()
    with get_db() as conn:
        # Remove previous unused codes for this owner
        conn.execute("DELETE FROM totp_recovery_codes WHERE owner = ? AND used = 0", (owner,))
        for code in codes:
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            conn.execute(
                "INSERT INTO totp_recovery_codes (owner, code_hash, used, created_at) VALUES (?, ?, 0, ?)",
                (owner, code_hash, now)
            )
    return codes


def _consume_recovery_code(owner, code):
    """Verifica un código de recuperación, lo marca como usado y devuelve True si es válido."""
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM totp_recovery_codes WHERE owner = ? AND code_hash = ? AND used = 0",
            (owner, code_hash)
        ).fetchone()
        if row:
            conn.execute("UPDATE totp_recovery_codes SET used = 1 WHERE id = ?", (row['id'],))
            return True
    return False


def _qr_svg(data):
    """Genera un QR code SVG en base64 para mostrar en el dashboard."""
    qr = qrcode.make(data, image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    qr.save(buf)
    return base64.b64encode(buf.getvalue()).decode()


def _log_admin_access(endpoint, token_type):
    """Registra acceso al panel de administración para auditoría."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO admin_access_log (endpoint, token_type, ip, timestamp) VALUES (?, ?, ?, ?)",
                (endpoint, token_type, get_client_ip(), time.time())
            )
    except Exception:
        pass


def _hmac(data):
    """HMAC-SHA256 of any string using SECRET_KEY."""
    return hmac.new(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()

def sign_session(session_id, ip, expires):
    """Signs the session: HMAC(session_id.ip.expires)"""
    return _hmac("%s.%s.%s" % (session_id, ip, expires))

def sign_challenge(challenge_id, salt, target, expires):
    """Signs the challenge: HMAC(challenge_id.salt.target.expires)"""
    return _hmac("%s.%s.%s.%s" % (challenge_id, salt, target, expires))

@app.route('/privacy')
def privacy():
    return render_template_string(PRIVACY_HTML)

@app.route('/terms')
def terms():
    return render_template_string(TERMS_HTML)

@app.route('/dpa')
def dpa():
    return render_template_string(DPA_HTML)

@app.route('/baa')
def baa():
    return render_template_string(BAA_HTML)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', admin_token_required=bool(ADMIN_TOKEN))


@app.route('/account')
def account():
    return render_template('account.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

@app.route('/menta-logo.svg')
def logo():
    return send_file(os.path.join(os.path.dirname(__file__), 'menta-logo.svg'), mimetype='image/svg+xml')

@app.route('/menta-in-action.gif')
def hero_gif():
    return send_file(os.path.join(os.path.dirname(__file__), 'menta-in-action.gif'), mimetype='image/gif')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/init', methods=['POST'])
def init_session():
    ip = get_client_ip()
    tenant_id = current_tenant()
    origin = request.headers.get('Origin')

    status = check_account_status(tenant_id)
    if not status['ok']:
        log_failure(ip, '/init', 'account_' + status.get('status', 'inactive'), tenant_id=tenant_id)
        return jsonify({"success": False, "error": status['error'], "support_url": status.get('support_url')}), 402

    ok, reason = check_browser_signals(tenant_id, origin)
    if not ok:
        log_failure(ip, '/init', 'browser_' + reason, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    if not check_rate_limit(ip, '/init', 5, 60, tenant_id=tenant_id):
        log_failure(ip, '/init', 'rate_limit', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_tenant(tenant_id, '/init', RL_INIT_PER_TENANT):
        log_failure(ip, '/init', 'rate_limit_tenant', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_global('/init', RL_GLOBAL_INIT):
        log_failure(ip, '/init', 'rate_limit_global', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    update_account_last_seen(tenant_id)

    session_id = secrets.token_hex(16)
    now = time.time()
    expires = now + 120
    sig = sign_session(session_id, ip, expires)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions (id, tenant_id, ip, created_at, expires, used) VALUES (?, ?, ?, ?, ?, 0)",
            (session_id, tenant_id, ip, now, expires)
        )
    return jsonify({"session_id": session_id, "session_signature": sig})

@app.route('/challenge', methods=['POST'])
def get_challenge():
    ip = get_client_ip()
    tenant_id = current_tenant()
    origin = request.headers.get('Origin')

    status = check_account_status(tenant_id)
    if not status['ok']:
        log_failure(ip, '/challenge', 'account_' + status.get('status', 'inactive'), tenant_id=tenant_id)
        return jsonify({"success": False, "error": status['error'], "support_url": status.get('support_url')}), 402

    ok, reason = check_browser_signals(tenant_id, origin)
    if not ok:
        log_failure(ip, '/challenge', 'browser_' + reason, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    if not check_rate_limit(ip, '/challenge', 5, 60, tenant_id=tenant_id):
        log_failure(ip, '/challenge', 'rate_limit', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_tenant(tenant_id, '/challenge', RL_CHALLENGE_PER_TENANT):
        log_failure(ip, '/challenge', 'rate_limit_tenant', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_global('/challenge', RL_GLOBAL_CHALLENGE):
        log_failure(ip, '/challenge', 'rate_limit_global', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    is_bot, reason = check_bot_signals(ip, tenant_id=tenant_id)
    if is_bot:
        log_failure(ip, '/challenge', 'bot_detected_' + reason, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    data = request.json or {}
    session_id = data.get('session_id')
    session_sig = data.get('session_signature')
    if not session_id or not session_sig:
        return jsonify({"success": False, "error": "Session and signature required. Call /init first."}), 403

    with get_db() as conn:
        session = conn.execute(
            "SELECT id, tenant_id, ip, created_at, expires, used FROM sessions WHERE id = ? AND tenant_id = ?",
            (session_id, tenant_id)
        ).fetchone()

    if not session or session["expires"] < time.time():
        log_failure(ip, '/challenge', 'session_invalid', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Invalid or expired session. Call /init first."}), 403
    if session["used"]:
        log_failure(ip, '/challenge', 'session_reuse', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Session already used."}), 403
    if session["ip"] != ip:
        log_failure(ip, '/challenge', 'ip_mismatch', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "IP does not match the session."}), 403

    expected_sig = sign_session(session_id, session["ip"], session["expires"])
    if not hmac.compare_digest(session_sig, expected_sig):
        log_failure(ip, '/challenge', 'bad_signature', session_id, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Invalid session signature."}), 403

    if time.time() - session["created_at"] < 0.5:
        log_failure(ip, '/challenge', 'too_fast', session_id, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    update_account_last_seen(tenant_id)

    challenge_id = secrets.token_hex(16)
    salt = secrets.token_hex(8)
    target = get_difficulty(ip, tenant_id=tenant_id)
    ch_expires = time.time() + 300

    with get_db() as conn:
        conn.execute(
            "INSERT INTO challenges (id, tenant_id, salt, target, created_at, expires) VALUES (?, ?, ?, ?, ?, ?)",
            (challenge_id, tenant_id, salt, target, time.time(), ch_expires)
        )

    ch_sig = sign_challenge(challenge_id, salt, target, ch_expires)

    return jsonify({
        "token": challenge_id,
        "challenge": {"salt": salt, "target": target, "expires": ch_expires, "challenge_signature": ch_sig}
    })

@app.route('/redeem', methods=['POST'])
def redeem():
    ip = get_client_ip()
    tenant_id = current_tenant()
    origin = request.headers.get('Origin')

    status = check_account_status(tenant_id)
    if not status['ok']:
        log_failure(ip, '/redeem', 'account_' + status.get('status', 'inactive'), tenant_id=tenant_id)
        return jsonify({"success": False, "error": status['error'], "support_url": status.get('support_url')}), 402

    ok, reason = check_browser_signals(tenant_id, origin)
    if not ok:
        log_failure(ip, '/redeem', 'browser_' + reason, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    if not check_rate_limit(ip, '/redeem', 5, 60, tenant_id=tenant_id):
        log_failure(ip, '/redeem', 'rate_limit', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_tenant(tenant_id, '/redeem', RL_REDEEM_PER_TENANT):
        log_failure(ip, '/redeem', 'rate_limit_tenant', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_global('/redeem', RL_GLOBAL_REDEEM):
        log_failure(ip, '/redeem', 'rate_limit_global', tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Too many requests. Try again later."}), 429

    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({"success": False, "error": "Session required."}), 403

    with get_db() as conn:
        session = conn.execute(
            "SELECT id, tenant_id, ip, created_at, expires, used FROM sessions WHERE id = ? AND tenant_id = ?",
            (session_id, tenant_id)
        ).fetchone()
        if not session or session["expires"] < time.time():
            log_failure(ip, '/redeem', 'session_invalid', tenant_id=tenant_id)
            return jsonify({"success": False, "error": "Invalid or expired session."}), 403
        if session["used"]:
            log_failure(ip, '/redeem', 'session_reuse', tenant_id=tenant_id)
            return jsonify({"success": False, "error": "Session already used."}), 403
        if session["ip"] != ip:
            log_failure(ip, '/redeem', 'ip_mismatch', tenant_id=tenant_id)
            return jsonify({"success": False, "error": "IP does not match."}), 403

    if time.time() - session["created_at"] < 1.0:
        log_failure(ip, '/redeem', 'too_fast', session_id, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    challenge_id = data.get('token')
    nonce = str(data.get('solutions'))
    ch_sig = data.get('challenge_signature')
    if not challenge_id or not ch_sig:
        return jsonify({"success": False, "error": "Challenge signature required."}), 403

    with get_db() as conn:
        row = conn.execute(
            "DELETE FROM challenges WHERE id = ? AND tenant_id = ? RETURNING salt, target, created_at, expires",
            (challenge_id, tenant_id)
        ).fetchone()

    if not row or row["expires"] < time.time():
        log_failure(ip, '/redeem', 'challenge_not_found', challenge_id, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Challenge not found or expired"}), 400

    expected_ch_sig = sign_challenge(challenge_id, row['salt'], row['target'], row['expires'])
    if not hmac.compare_digest(ch_sig, expected_ch_sig):
        log_failure(ip, '/redeem', 'bad_challenge_signature', challenge_id, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Invalid challenge signature."}), 403

    is_valid_nonce, nonce_reason = check_nonce_entropy(ip, nonce, tenant_id=tenant_id)
    if not is_valid_nonce:
        log_failure(ip, '/redeem', 'nonce_' + nonce_reason, challenge_id, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    if time.time() - row["created_at"] < 0.2:
        log_failure(ip, '/redeem', 'too_fast', challenge_id, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    check = hashlib.sha256((row['salt'] + nonce).encode()).hexdigest()

    if check.startswith(row['target']):
        solve_time = time.time() - row["created_at"]
        is_client_ok, client_reason = check_client_pattern(ip, solve_time, nonce=int(nonce), tenant_id=tenant_id)
        if not is_client_ok:
            log_failure(ip, '/redeem', 'pattern_' + client_reason, challenge_id, tenant_id=tenant_id)
            return jsonify({"success": False, "error": "Suspicious activity detected."}), 403
        with get_db() as conn:
            conn.execute(
                "INSERT INTO solved_challenges (tenant_id, ip, nonce, solve_time, timestamp) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, ip, int(nonce), solve_time, time.time())
            )
            conn.execute("UPDATE sessions SET used = 1 WHERE id = ? AND tenant_id = ?", (session_id, tenant_id))
        update_account_last_seen(tenant_id)
        now = int(time.time())
        exp = now + 300
        valid_token = jwt.encode({
            "sub": "human",
            "iat": now,
            "exp": exp,
            "jti": secrets.token_hex(8),
            "ip": ip
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({
            "success": True,
            "token": valid_token,
            "expires": time.ctime(exp)
        })

    log_failure(ip, '/redeem', 'bad_pow', challenge_id, tenant_id=tenant_id)
    return jsonify({"success": False, "error": "Incorrect solution"}), 403


@app.route('/verify', methods=['POST'])
def verify_token():
    """Verifica server-to-server un token emitido por /redeem, sin exponer SECRET_KEY.
    Consume el token (single-use) marcando su jti en verified_tokens."""
    ip = get_client_ip()
    tenant_id = current_tenant()

    status = check_account_status(tenant_id)
    if not status['ok']:
        log_failure(ip, '/verify', 'account_' + status.get('status', 'inactive'), tenant_id=tenant_id)
        return jsonify({"success": False, "valid": False, "error": status['error'], "support_url": status.get('support_url')}), 402

    if not check_rate_limit(ip, '/verify', 20, 60, tenant_id=tenant_id):
        log_failure(ip, '/verify', 'rate_limit', tenant_id=tenant_id)
        return jsonify({"success": False, "valid": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_tenant(tenant_id, '/verify', RL_VERIFY_PER_TENANT):
        log_failure(ip, '/verify', 'rate_limit_tenant', tenant_id=tenant_id)
        return jsonify({"success": False, "valid": False, "error": "Too many requests. Try again later."}), 429

    if not check_rate_limit_global('/verify', RL_GLOBAL_VERIFY):
        log_failure(ip, '/verify', 'rate_limit_global', tenant_id=tenant_id)
        return jsonify({"success": False, "valid": False, "error": "Too many requests. Try again later."}), 429

    data = request.get_json(silent=True) or {}
    token = data.get('token')
    if not token:
        return jsonify({"success": False, "valid": False, "error": "token required"}), 400

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        log_failure(ip, '/verify', 'token_expired', tenant_id=tenant_id)
        return jsonify({"success": True, "valid": False, "error": "expired"})
    except Exception:
        log_failure(ip, '/verify', 'bad_token', tenant_id=tenant_id)
        return jsonify({"success": True, "valid": False, "error": "invalid"})

    if payload.get('sub') != 'human':
        log_failure(ip, '/verify', 'bad_subject', tenant_id=tenant_id)
        return jsonify({"success": True, "valid": False, "error": "invalid"})

    jti = payload.get('jti')
    if not jti:
        log_failure(ip, '/verify', 'missing_jti', tenant_id=tenant_id)
        return jsonify({"success": True, "valid": False, "error": "invalid"})

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO verified_tokens (jti, tenant_id, verified_at, expires) VALUES (?, ?, ?, ?)",
                (jti, tenant_id, time.time(), payload.get('exp', time.time()))
            )
    except Exception:
        log_failure(ip, '/verify', 'token_reuse', tenant_id=tenant_id)
        return jsonify({"success": True, "valid": False, "error": "token already used"})

    update_account_last_seen(tenant_id)
    return jsonify({"success": True, "valid": True})


def _create_account_from_request(data):
    """Crea una cuenta SaaS a partir de datos. Valida dominio y conflictos. Devuelve dict o tuple (response, status)."""
    domains = data.get('domains', '')
    notes = data.get('notes', '')
    plan = data.get('plan', 'beginner')
    ntfy_topic = data.get('ntfy_topic', '')
    domains = _normalize_domains_input(domains)
    # Enforce plan domain limit
    limit_error = _check_domain_plan_limit(domains, plan)
    if limit_error:
        return limit_error

    # determine primary domain
    primary_input = data.get('primary_domain', '')
    if not primary_input:
        primary_input = domains.split(',')[0] if domains else ''
    primary_domain = normalize_domain(primary_input)
    if not primary_domain:
        return jsonify({"error": "A valid domain is required for SaaS accounts"}), 400

    # Check domain conflict across active/locked domains
    conflict = check_domain_conflict(primary_domain)
    if conflict and conflict['type'] == 'active':
        return jsonify({
            "error": "Domain already has an active owner.",
            "domain": conflict['domain'],
            "support_url": '/support?subject=domain-claim'
        }), 409

    account_number = generate_account_number()
    now = time.time()

    if conflict and conflict['type'] == 'locked':
        # Previous domain registration exists; create account in pending_claim with warning
        trial_started = None
        status = 'pending_claim'
        domain_alert = "This domain was previously registered in Menta. It has been inactive for %d day(s). Options: 1) log in with your old account, 2) wait %d days, or 3) open a support claim to validate ownership." % (
            conflict.get('days_inactive', 0),
            max(0, conflict.get('days_until_release', 0))
        )
    else:
        trial_started = now
        status = 'trial'
        domain_alert = None

    with get_db() as conn:
        conn.execute(
            "INSERT INTO accounts (account_number, tenant_id, domains, primary_domain, plan, status, trial_started_at, ntfy_topic, created_at, last_seen_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (account_number, account_number, domains, primary_domain, plan, status, trial_started, ntfy_topic, now, now, notes)
        )
    # Register domain for the account
    if status == 'trial':
        _register_domain_for_account(account_number, primary_domain, paid=False, status='active')

    response = {
        "success": True,
        "account_number": account_number,
        "status": status,
        "primary_domain": primary_domain,
        "trial_days": TRIAL_DAYS if status == 'trial' else None,
        "warning": "Save this number. It will not be shown again."
    }
    if domain_alert:
        response["domain_alert"] = domain_alert
    return response


@app.route('/admin/account', methods=['POST'])
def create_account():
    """Crea una cuenta estilo Mullvad. Requiere token admin."""
    ok, _, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Admin token required"}), 401
    result = _create_account_from_request(request.get_json(silent=True) or {})
    if isinstance(result, tuple):
        return result
    return jsonify(result)


@app.route('/account/register', methods=['POST'])
def register_account():
    """Registro self-service de una cuenta SaaS. No requiere token admin."""
    ip = get_client_ip()
    if not check_rate_limit(ip, '/account/register', 5, 3600):
        return jsonify({"error": "Too many requests. Try again later."}), 429
    data = request.get_json(silent=True) or {}
    result = _create_account_from_request(data)
    if isinstance(result, tuple):
        return result
    return jsonify(result)


@app.route('/admin/account/login', methods=['POST'])
def login_account():
    """Login con número de cuenta. Si 2FA está configurado, requiere TOTP o recovery code. Devuelve un JWT session token."""
    data = request.get_json(silent=True) or {}
    account_number = data.get('account_number', '').strip()
    code = (data.get('totp_code') or data.get('recovery_code') or '').strip()
    if not account_number:
        return jsonify({"error": "account_number required"}), 400
    with get_db() as conn:
        account = conn.execute("SELECT * FROM accounts WHERE account_number = ?", (account_number,)).fetchone()
    if not account:
        return jsonify({"error": "Unauthorized"}), 401
    if account['totp_secret']:
        if not code:
            return jsonify({"error": "TOTP code or recovery code required"}), 403
        totp = pyotp.TOTP(account['totp_secret'])
        if not totp.verify(code, valid_window=1) and not _consume_recovery_code(account_number, code):
            return jsonify({"error": "Invalid TOTP or recovery code"}), 401
    update_account_last_seen(account_number)
    status = check_account_status(account_number)
    token = _issue_account_token(account_number, verified=True)
    return jsonify({
        "success": True,
        "token": token,
        "account": {
            "domains": account["domains"],
            "primary_domain": account["primary_domain"],
            "plan": account["plan"],
            "status": account["status"],
            "trial_days_left": status.get('days_left'),
            "created_at": account["created_at"],
            "last_seen_at": account["last_seen_at"],
            "notes": account["notes"],
            "totp_enabled": bool(account['totp_secret'])
        }
    })


def _require_account():
    """Verifica autenticación de cuenta. Si 2FA está activado, requiere token de sesión verificado."""
    account_number, verified = _get_account_auth()
    if not account_number:
        return None, jsonify({"error": "account_number required"}), 401
    with get_db() as conn:
        account = conn.execute("SELECT * FROM accounts WHERE account_number = ?", (account_number,)).fetchone()
    if not account:
        return None, jsonify({"error": "Unauthorized"}), 401
    if account['totp_secret'] and not verified:
        return None, jsonify({"error": "TOTP verification required"}), 403
    return account, None, None


@app.route('/admin/account', methods=['GET'])
def get_account_info():
    """Devuelve información de la cuenta autenticada."""
    account, err, status = _require_account()
    if err:
        return err, status
    account_number = account['account_number']
    update_account_last_seen(account_number)
    status = check_account_status(account_number)
    return jsonify({
        "success": True,
        "account": {
            "domains": account["domains"],
            "primary_domain": account["primary_domain"],
            "plan": account["plan"],
            "status": account["status"],
            "trial_days_left": status.get('days_left'),
            "created_at": account["created_at"],
            "last_seen_at": account["last_seen_at"],
            "notes": account["notes"],
            "totp_enabled": bool(account['totp_secret'])
        }
    })


@app.route('/admin/account/activate', methods=['POST'])
def activate_account():
    """Activa manualmente una cuenta tras pago verificado (crypto). Requiere admin."""
    ok, _, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    account_number = data.get('account_number', '').strip()
    plan = data.get('plan', 'beginner')
    if not account_number:
        return jsonify({"error": "account_number required"}), 400
    with get_db() as conn:
        account = conn.execute("SELECT * FROM accounts WHERE account_number = ?", (account_number,)).fetchone()
    if not account:
        return jsonify({"error": "Account not found"}), 404
    now = time.time()
    with get_db() as conn:
        conn.execute(
            "UPDATE accounts SET status = 'active', plan = ?, payment_activated_at = ?, trial_started_at = ? WHERE account_number = ?",
            (plan, now, now, account_number)
        )
    # Unlock and mark domain as paid
    _register_domain_for_account(account_number, account['primary_domain'], paid=True, status='active')
    return jsonify({
        "success": True,
        "status": "active",
        "account_number": account_number,
        "plan": plan
    })


@app.route('/admin/account/<account_number>/delete', methods=['POST'])
def delete_account(account_number):
    """Elimina una cuenta SaaS y sus datos asociados. Requiere admin."""
    ok, _, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        account = conn.execute("SELECT account_number FROM accounts WHERE account_number = ?", (account_number,)).fetchone()
        if not account:
            return jsonify({"error": "Account not found"}), 404
        # Remove related tenant data
        for table in ['challenges', 'failed_attempts', 'rate_limits', 'rate_limits_tenant', 'sessions', 'solved_challenges']:
            conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (account_number,))
        # Remove domain history and recovery codes
        conn.execute("DELETE FROM domain_history WHERE account_number = ?", (account_number,))
        conn.execute("DELETE FROM totp_recovery_codes WHERE owner = ?", (account_number,))
        # Dissociate support tickets from account (keep tickets for audit)
        conn.execute("UPDATE support_tickets SET account_number = NULL WHERE account_number = ?", (account_number,))
        # Delete account
        conn.execute("DELETE FROM accounts WHERE account_number = ?", (account_number,))
    return jsonify({"success": True, "account_number": account_number})


@app.route('/admin/accounts', methods=['GET'])
def list_accounts():
    """Lista cuentas para administración."""
    ok, _, setup_required = _admin_authorized(readonly=True)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    status_filter = request.args.get('status', '')
    with get_db() as conn:
        if status_filter:
            rows = conn.execute("SELECT account_number, primary_domain, plan, status, trial_started_at, payment_activated_at, created_at, last_seen_at FROM accounts WHERE status = ? ORDER BY created_at DESC", (status_filter,)).fetchall()
        else:
            rows = conn.execute("SELECT account_number, primary_domain, plan, status, trial_started_at, payment_activated_at, created_at, last_seen_at FROM accounts ORDER BY created_at DESC").fetchall()
    result = []
    for r in rows:
        s = check_account_status(r['account_number'])
        result.append({
            "account_number": r['account_number'],
            "primary_domain": r['primary_domain'],
            "plan": r['plan'],
            "status": r['status'],
            "trial_days_left": s.get('days_left'),
            "created_at": r['created_at'],
            "last_seen_at": r['last_seen_at'],
            "payment_activated_at": r['payment_activated_at']
        })
    return jsonify({"success": True, "accounts": result})


@app.route('/admin/account/domains', methods=['POST'])
def update_account_domains():
    """Actualiza los dominios permitidos de una cuenta."""
    account, err, status = _require_account()
    if err:
        return err, status
    account_number = account['account_number']
    plan = account['plan']
    data = request.get_json(silent=True) or {}
    domains = data.get('domains', '')
    domains = _normalize_domains_input(domains)
    # Enforce plan domain limit
    limit_error = _check_domain_plan_limit(domains, plan)
    if limit_error:
        return limit_error
    # Validate no new domain conflicts with another active account
    for d in domains.split(','):
        if not d:
            continue
        host = normalize_domain(d)
        if not host:
            continue
        conflict = check_domain_conflict(host, account_number=account_number)
        if conflict and conflict['type'] == 'active' and conflict['account_number'] != account_number:
            return jsonify({"error": "Domain conflict with another account", "domain": host}), 409
    with get_db() as conn:
        conn.execute("UPDATE accounts SET domains = ? WHERE account_number = ?", (domains, account_number))
    update_account_last_seen(account_number)
    return jsonify({"success": True, "domains": domains})


@app.route('/admin/account/totp/status', methods=['GET'])
def account_totp_status():
    """Devuelve el estado de 2FA de la cuenta."""
    account, err, status = _require_account()
    if err:
        return err, status
    return jsonify({"success": True, "enabled": bool(account['totp_secret'])})


@app.route('/admin/account/totp/setup', methods=['POST'])
def account_totp_setup():
    """Inicia configuración de 2FA para una cuenta; devuelve secret y QR."""
    account, err, status = _require_account()
    if err:
        return err, status
    if account['totp_secret']:
        return jsonify({"error": "2FA already configured"}), 400
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=account['account_number'], issuer_name='Menta')
    qr = _qr_svg(uri)
    return jsonify({"success": True, "secret": secret, "qr": qr, "uri": uri})


@app.route('/admin/account/totp/verify', methods=['POST'])
def account_totp_verify():
    """Verifica un código TOTP y habilita 2FA para la cuenta."""
    account, err, status = _require_account()
    if err:
        return err, status
    data = request.get_json(silent=True) or {}
    secret = (data.get('secret') or '').strip()
    code = (data.get('code') or '').strip()
    if not secret or not code:
        return jsonify({"error": "secret and code required"}), 400
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return jsonify({"error": "Invalid code"}), 400
    codes = _generate_recovery_codes(account['account_number'])
    with get_db() as conn:
        conn.execute("UPDATE accounts SET totp_secret = ? WHERE account_number = ?", (secret, account['account_number']))
    return jsonify({"success": True, "recovery_codes": codes, "enabled": True})


@app.route('/admin/account/totp/disable', methods=['POST'])
def account_totp_disable():
    """Deshabilita 2FA para la cuenta."""
    account, err, status = _require_account()
    if err:
        return err, status
    data = request.get_json(silent=True) or {}
    code = (data.get('code') or '').strip()
    if not code:
        return jsonify({"error": "code required"}), 400
    if account['totp_secret']:
        if not pyotp.TOTP(account['totp_secret']).verify(code, valid_window=1) and not _consume_recovery_code(account['account_number'], code):
            return jsonify({"error": "Invalid TOTP or recovery code"}), 401
    with get_db() as conn:
        conn.execute("UPDATE accounts SET totp_secret = NULL WHERE account_number = ?", (account['account_number'],))
        conn.execute("DELETE FROM totp_recovery_codes WHERE owner = ?", (account['account_number'],))
    return jsonify({"success": True, "enabled": False})


@app.route('/admin/account/totp/recovery', methods=['POST'])
def account_totp_recovery():
    """Usa un recovery code para obtener un session token de cuenta."""
    data = request.get_json(silent=True) or {}
    account_number = data.get('account_number', '').strip()
    code = (data.get('recovery_code') or '').strip()
    if not account_number or not code:
        return jsonify({"error": "account_number and recovery_code required"}), 400
    with get_db() as conn:
        account = conn.execute("SELECT * FROM accounts WHERE account_number = ?", (account_number,)).fetchone()
    if not account:
        return jsonify({"error": "Unauthorized"}), 401
    if not _consume_recovery_code(account_number, code):
        return jsonify({"error": "Invalid recovery code"}), 401
    update_account_last_seen(account_number)
    token = _issue_account_token(account_number, verified=True)
    return jsonify({"success": True, "token": token})


@app.route('/support', methods=['GET'])
def support_page():
    """Página de soporte anónimo."""
    return render_template('support.html')


@app.route('/support/<ticket_id>')
def view_ticket_page(ticket_id):
    """Página para ver un ticket por su enlace secreto."""
    return render_template('support.html', ticket_id=ticket_id)


@app.route('/support/ticket', methods=['POST'])
def create_ticket():
    """Crea un ticket de soporte anónimo."""
    data = request.get_json(silent=True) or {}
    subject = (data.get('subject') or '').strip()
    message = (data.get('message') or '').strip()
    ntfy_topic = (data.get('ntfy_topic') or '').strip()
    account_number = (data.get('account_number') or '').strip()
    if not subject or not message:
        return jsonify({"error": "subject and message are required"}), 400
    ticket_id = secrets.token_urlsafe(16)
    now = time.time()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO support_tickets (id, account_number, ntfy_topic, subject, message, status, created_at, last_reply_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, account_number or None, ntfy_topic or None, subject, message, 'open', now, now)
        )
    link = _support_link(ticket_id, request)
    # Notify user that ticket was created
    if ntfy_topic:
        _notify_ntfy(ntfy_topic, "Tu ticket de soporte ha sido creado. Guarda este enlace:", link)
    # Notify admin of new ticket
    if NTFY_ADMIN_TOPIC:
        _notify_ntfy(NTFY_ADMIN_TOPIC, "Nuevo ticket de soporte: %s" % subject, link)
    return jsonify({
        "success": True,
        "ticket_id": ticket_id,
        "link": link,
        "message": "Save this secret link. It will not be shown again."
    })


@app.route('/support/ticket/<ticket_id>', methods=['GET'])
def get_ticket(ticket_id):
    """Devuelve un ticket y sus respuestas por el enlace secreto."""
    with get_db() as conn:
        ticket = conn.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        replies = conn.execute("SELECT * FROM support_replies WHERE ticket_id = ? ORDER BY created_at ASC", (ticket_id,)).fetchall()
    return jsonify({
        "success": True,
        "ticket": dict(ticket),
        "replies": [dict(r) for r in replies]
    })


@app.route('/support/ticket/<ticket_id>/reply', methods=['POST'])
def add_user_reply(ticket_id):
    """Añade una respuesta de un usuario o del admin a un ticket."""
    data = request.get_json(silent=True) or {}
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({"error": "body is required"}), 400
    auth = request.headers.get('Authorization', '')
    is_admin = bool(ADMIN_TOKEN) and hmac.compare_digest(auth, 'Bearer ' + ADMIN_TOKEN)
    with get_db() as conn:
        ticket = conn.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if not is_admin and ticket['status'] == 'closed':
            return jsonify({"error": "Ticket is closed"}), 403
        author = 'admin' if is_admin else 'user'
        conn.execute(
            "INSERT INTO support_replies (ticket_id, author, body, created_at) VALUES (?, ?, ?, ?)",
            (ticket_id, author, body, time.time())
        )
        conn.execute("UPDATE support_tickets SET last_reply_at = ? WHERE id = ?", (time.time(), ticket_id))
    if ticket['ntfy_topic']:
        link = _support_link(ticket_id, request)
        _notify_ntfy(ticket['ntfy_topic'], "Tienes un nuevo mensaje en tu ticket de soporte.", link)
    return jsonify({"success": True})


@app.route('/admin/support/tickets', methods=['GET'])
def list_support_tickets():
    """Lista tickets de soporte para administración."""
    ok, _, setup_required = _admin_authorized(readonly=True)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, account_number, subject, status, created_at, last_reply_at FROM support_tickets ORDER BY created_at DESC"
        ).fetchall()
    return jsonify({"success": True, "tickets": [dict(r) for r in rows]})


@app.route('/admin/support/ticket/<ticket_id>', methods=['GET'])
def admin_get_ticket(ticket_id):
    """Devuelve un ticket para administración."""
    ok, _, setup_required = _admin_authorized(readonly=True)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        ticket = conn.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        replies = conn.execute("SELECT * FROM support_replies WHERE ticket_id = ? ORDER BY created_at ASC", (ticket_id,)).fetchall()
    return jsonify({"success": True, "ticket": dict(ticket), "replies": [dict(r) for r in replies]})


@app.route('/admin/support/ticket/<ticket_id>/reply', methods=['POST'])
def admin_reply_ticket(ticket_id):
    """Añade una respuesta del admin a un ticket y notifica al usuario."""
    ok, _, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({"error": "body is required"}), 400
    with get_db() as conn:
        ticket = conn.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        conn.execute(
            "INSERT INTO support_replies (ticket_id, author, body, created_at) VALUES (?, ?, ?, ?)",
            (ticket_id, 'admin', body, time.time())
        )
        conn.execute("UPDATE support_tickets SET last_reply_at = ?, status = 'open' WHERE id = ?", (time.time(), ticket_id))
    if ticket['ntfy_topic']:
        link = _support_link(ticket_id, request)
        _notify_ntfy(ticket['ntfy_topic'], "Tienes un nuevo mensaje en tu ticket de soporte.", link)
    return jsonify({"success": True})


@app.route('/admin/support/ticket/<ticket_id>/close', methods=['POST'])
def admin_close_ticket(ticket_id):
    """Cierra un ticket de soporte."""
    ok, _, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        conn.execute("UPDATE support_tickets SET status = 'closed' WHERE id = ?", (ticket_id,))
    return jsonify({"success": True})


@app.route('/admin/support/ticket/<ticket_id>/delete', methods=['POST'])
def admin_delete_ticket(ticket_id):
    """Elimina un ticket de soporte y sus respuestas."""
    ok, _, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        conn.execute("DELETE FROM support_replies WHERE ticket_id = ?", (ticket_id,))
        conn.execute("DELETE FROM support_tickets WHERE id = ?", (ticket_id,))
    return jsonify({"success": True})


@app.route('/admin/metrics', methods=['GET'])
def metrics():
    ok, token_type, setup_required = _admin_authorized(readonly=True)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    _log_admin_access('/admin/metrics', token_type)
    with get_db() as conn:
        now = time.time()
        tenant_id = current_tenant()
        bot_detected = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM failed_attempts WHERE tenant_id = ? AND reason IN ('bad_pow', 'bad_signature') AND timestamp > ?",
            (tenant_id, now - 3600)
        ).fetchone()[0]
        total_failures_1h = conn.execute(
            "SELECT COUNT(*) FROM failed_attempts WHERE tenant_id = ? AND timestamp > ?",
            (tenant_id, now - 3600)
        ).fetchone()[0]
        solves_1h = conn.execute(
            "SELECT COUNT(*) FROM solved_challenges WHERE tenant_id = ? AND timestamp > ?",
            (tenant_id, now - 3600)
        ).fetchone()[0]
        return jsonify({
            "bot_ips_1h": bot_detected,
            "total_failures_1h": total_failures_1h,
            "solves_1h": solves_1h,
            "sessions_active": conn.execute("SELECT COUNT(*) FROM sessions WHERE tenant_id = ? AND expires > ?", (tenant_id, now)).fetchone()[0],
            "db_size": os.path.getsize(DB_PATH)
        })


@app.route('/admin/export-data', methods=['GET', 'POST'])
def export_data():
    ok, token_type, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    _log_admin_access('/admin/export-data', token_type)

    tenant_id = current_tenant()
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        ip = data.get('ip')
    else:
        ip = request.args.get('ip')

    if not ip:
        return jsonify({"error": "ip identifier is required"}), 400

    with get_db() as conn:
        result = {
            "sessions": [dict(r) for r in conn.execute(
                "SELECT id, ip, created_at, expires, used FROM sessions WHERE tenant_id = ? AND ip = ?",
                (tenant_id, ip)
            ).fetchall()],
            "solved_challenges": [dict(r) for r in conn.execute(
                "SELECT ip, nonce, solve_time, timestamp FROM solved_challenges WHERE tenant_id = ? AND ip = ?",
                (tenant_id, ip)
            ).fetchall()],
            "failed_attempts": [dict(r) for r in conn.execute(
                "SELECT ip, endpoint, reason, challenge_id, timestamp FROM failed_attempts WHERE tenant_id = ? AND ip = ?",
                (tenant_id, ip)
            ).fetchall()],
            "rate_limits": [dict(r) for r in conn.execute(
                "SELECT ip, endpoint, timestamp FROM rate_limits WHERE tenant_id = ? AND ip = ?",
                (tenant_id, ip)
            ).fetchall()],
        }
    return jsonify({"success": True, "ip": ip, "data": result})


@app.route('/admin/delete-data', methods=['POST'])
def delete_data():
    ok, token_type, setup_required = _admin_authorized(readonly=False)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    _log_admin_access('/admin/delete-data', token_type)

    tenant_id = current_tenant()
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "ip identifier is required"}), 400

    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE tenant_id = ? AND ip = ?", (tenant_id, ip))
        conn.execute("DELETE FROM solved_challenges WHERE tenant_id = ? AND ip = ?", (tenant_id, ip))
        conn.execute("DELETE FROM failed_attempts WHERE tenant_id = ? AND ip = ?", (tenant_id, ip))
        conn.execute("DELETE FROM rate_limits WHERE tenant_id = ? AND ip = ?", (tenant_id, ip))
    return jsonify({"success": True, "deleted_for": ip})


@app.route('/admin/2fa/status', methods=['GET'])
def admin_2fa_status():
    """Devuelve el estado de 2FA del admin. No requiere TOTP para permitir setup forzado."""
    ok, token_type, _ = _admin_authorized(readonly=True, skip_totp=True)
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    secret = _get_admin_totp_secret()
    return jsonify({"success": True, "enabled": bool(secret)})


@app.route('/admin/2fa/setup', methods=['POST'])
def admin_2fa_setup():
    """Genera un nuevo secret TOTP para el admin y devuelve QR. No lo persiste hasta verificar."""
    ok, _, _ = _admin_authorized(readonly=False, skip_totp=True)
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    if _get_admin_totp_secret():
        return jsonify({"error": "2FA already configured"}), 400
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name='admin', issuer_name='Menta')
    qr = _qr_svg(uri)
    return jsonify({"success": True, "secret": secret, "qr": qr, "uri": uri})


@app.route('/admin/2fa/verify', methods=['POST'])
def admin_2fa_verify():
    """Verifica un código TOTP y persiste el secret. Si es recovery code, lo consume."""
    ok, _, _ = _admin_authorized(readonly=False, skip_totp=True)
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    secret = (data.get('secret') or '').strip()
    code = (data.get('code') or '').strip()
    if not secret or not code:
        return jsonify({"error": "secret and code required"}), 400
    # If an admin secret is already configured, only verify against that.
    configured = _get_admin_totp_secret()
    if configured and configured != secret:
        return jsonify({"error": "2FA already configured"}), 400
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        codes = _generate_recovery_codes('__admin__')
        with get_db() as conn:
            conn.execute(
                "INSERT INTO admin_2fa (id, secret, created_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, created_at=excluded.created_at",
                (secret, time.time())
            )
        return jsonify({"success": True, "valid": True, "recovery_codes": codes})
    if _consume_recovery_code('__admin__', code):
        return jsonify({"success": True, "valid": True, "recovery": True})
    return jsonify({"success": False, "valid": False}), 400


@app.route('/menta-captcha.js')
def widget_js():
    return WIDGET_JS, 200, {'Content-Type': 'application/javascript'}

WIDGET_JS = r"""class CapWidget extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.token = null;
        this.sessionId = null;
        this.sessionSignature = null;
    }

    connectedCallback() {
        this.render();
        this.initSession();
    }

    i18n(key, fallback) {
        const val = this.getAttribute('data-cap-i18n-' + key);
        return val !== null && val !== '' ? val : fallback;
    }

    get isRTL() {
        if (this.hasAttribute('data-cap-rtl')) {
            const v = this.getAttribute('data-cap-rtl');
            return v !== 'false';
        }
        const host = this.getAttribute('data-cap-rtl') !== null;
        if (host) return true;
        if (this.closest('[dir]') && this.closest('[dir]').getAttribute('dir') === 'rtl') return true;
        return document.dir === 'rtl';
    }

    get headers() {
        return { 'Content-Type': 'application/json' };
    }

    async initSession() {
        const ep = this.getAttribute('data-cap-api-endpoint');
        const headers = { ...this.headers };
        delete headers['Content-Type'];
        try {
            const r = await fetch(ep + '/init', { method: 'POST', headers: headers });
            if (!r.ok) {
                const data = await r.json().catch(() => ({}));
                this._handleError(r.status, data, '/init');
                return;
            }
            const d = await r.json();
            this.sessionId = d.session_id;
            this.sessionSignature = d.session_signature;
        } catch(e) {
            // Suppress init error, will retry on click
        }
    }

    _handleError(status, data, endpoint) {
        const box = this.shadowRoot.getElementById('box');
        const label = this.shadowRoot.getElementById('label');
        const msg = this.shadowRoot.getElementById('message');
        const spin = this.shadowRoot.getElementById('spin');
        if (spin) spin.style.display = 'none';
        const origin = data.origin || this.getAttribute('data-cap-api-endpoint') || 'unknown';
        if (status === 403) {
            label.innerText = this.i18n('not-authorized', 'Protected by Menta');
            if (msg) {
                msg.innerText = this.i18n('not-authorized-detail', 'This domain is not registered or authorized by Menta.');
                msg.classList.add('protected');
                msg.style.display = 'block';
            }
            console.warn('[Menta protection] This website is not registered or authorized by Menta.', { status, endpoint, origin, support_url: data.support_url, error: data.error });
        } else {
            label.innerText = this.i18n('error', 'Error. Try again.');
            if (msg) {
                msg.innerText = data.error || this.i18n('error', 'Error. Try again.');
                msg.style.display = 'block';
            }
            console.warn('[Menta] Request failed.', { status, endpoint, error: data.error });
        }
        if (box) {
            box.setAttribute('aria-label', label.innerText);
            box.setAttribute('aria-busy', 'false');
        }
    }

    render() {
        const rtl = this.isRTL;
        const dir = rtl ? 'rtl' : 'ltr';
        const initialLabel = this.i18n('initial-state', "Verify you're human");
        const privacyLabel = this.i18n('privacy', 'Privacy');
        const termsLabel = this.i18n('terms', 'Terms');
        const privacyUrl = this.getAttribute('data-cap-privacy-url');
        const termsUrl = this.getAttribute('data-cap-terms-url');
        const ep = this.getAttribute('data-cap-api-endpoint') || '';
        const logoUrl = ep.replace(/\/*$/, '') + '/menta-logo.svg';
        const privacyLink = privacyUrl ? `<a href="${privacyUrl}" target="_blank" rel="noopener" class="link">${privacyLabel}</a>` : `<span class="link">${privacyLabel}</span>`;
        const termsLink = termsUrl ? `<a href="${termsUrl}" target="_blank" rel="noopener" class="link">${termsLabel}</a>` : `<span class="link">${termsLabel}</span>`;
        this.shadowRoot.innerHTML = `
<style>
:host { display: inline-block; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.container { display:flex; align-items:center; width:300px; height:70px; background:#fff; border:1px solid #e0e0e0; border-radius:20px; padding:0 15px; position:relative; box-shadow:0 2px 4px rgba(0,0,0,0.05); cursor:pointer; user-select:none; }
.container:hover { border-color:#bdbdbd; }
.container:focus-visible { outline: 2px solid #333; outline-offset: 2px; }
.checkbox { width:24px; height:24px; border:2px solid #d1d1d1; border-radius:6px; margin-right:15px; display:flex; align-items:center; justify-content:center; }
.label { font-size:16px; color:#333; flex-grow:1; }
.brand { position:absolute; right:20px; bottom:24px; font-size:12px; color:#757575; text-decoration:underline; text-underline-offset:3px; }
.logo { position:absolute; right:20px; bottom:42px; width:24px; height:24px; }
.spinner { display:none; width:18px; height:18px; border:2px solid #f3f3f3; border-top:2px solid #333; border-radius:50%; animation:spin 1s linear infinite; }
@media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
@keyframes spin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }
.solved .checkbox { background:#f0f0f0; border-color:#4CAF50; }
.solved .checkbox::after { content:'\u2713'; color:#4CAF50; font-weight:bold; }
.links { position:absolute; right:20px; bottom:8px; display:flex; gap:0.4rem; font-size:8px; color:#757575; }
.links .link { color:#757575; text-decoration:underline; text-underline-offset:2px; }
.links .link:hover { color:#333; }
.links span.link { text-decoration:none; cursor:default; }
.mint-accent { fill: #2ECC71; color: #2ECC71; }
.message { display:none; margin-top:6px; font-size:11px; color:#757575; max-width:300px; line-height:1.4; }
.message.protected { color:#2ECC71; }
</style>
<div class="container" id="box" role="button" tabindex="0" aria-label="${initialLabel}" aria-live="polite" aria-atomic="true" dir="${dir}">
  <div class="checkbox" id="check" aria-hidden="true"><div class="spinner" id="spin"></div></div>
  <span class="label" id="label">${initialLabel}</span>
  <span class="brand">Menta<span class="mint-accent">.</span></span>
  <div class="links" id="links">
    ${privacyLink} &middot; ${termsLink}
  </div>
</div>
<div class="message" id="message" style="display:none;"></div>`;
        const box = this.shadowRoot.getElementById('box');
        box.addEventListener('click', () => this.solve());
        box.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.solve();
            }
        });
    }

    async solve() {
        const ep = this.getAttribute('data-cap-api-endpoint');
        const box = this.shadowRoot.getElementById('box');
        const label = this.shadowRoot.getElementById('label');
        const spin = this.shadowRoot.getElementById('spin');
        if (this.token) return;

        const loadingLabel = this.i18n('loading', 'Initializing...');
        const verifyingLabel = this.i18n('verifying', 'Verifying...');
        const successLabel = this.i18n('success', "You're human");

        if (!this.sessionId) {
            label.innerText = loadingLabel;
            box.setAttribute('aria-label', loadingLabel);
            box.setAttribute('aria-busy', 'true');
            try {
                const initHeaders = { ...this.headers };
                delete initHeaders['Content-Type'];
                const r = await fetch(ep + '/init', { method: 'POST', headers: initHeaders });
                if (!r.ok) {
                    const data = await r.json().catch(() => ({}));
                    this._handleError(r.status, data, '/init');
                    return;
                }
                const d = await r.json();
                this.sessionId = d.session_id;
                this.sessionSignature = d.session_signature;
            } catch(e) {
                this._handleError(0, { error: this.i18n('error', 'Error. Try again.') }, '/init');
                return;
            }
        }

        label.innerText = verifyingLabel;
        box.setAttribute('aria-label', verifyingLabel);
        box.setAttribute('aria-busy', 'true');
        spin.style.display = "block";
        try {
            const r = await fetch(ep + '/challenge', {
                method: 'POST',
                headers: this.headers,
                body: JSON.stringify({ session_id: this.sessionId, session_signature: this.sessionSignature })
            });
            if (!r.ok) {
                const data = await r.json().catch(() => ({}));
                this._handleError(r.status, data, '/challenge');
                this.sessionId = null;
                this.sessionSignature = null;
                return;
            }
            const { token, challenge } = await r.json();
            let nonce = 0;
            while (true) {
                const h = await this.sha256(challenge.salt + nonce);
                if (h.startsWith(challenge.target)) break;
                nonce++;
            }
            const v = await fetch(ep + '/redeem', {
                method: 'POST',
                headers: this.headers,
                body: JSON.stringify({ session_id: this.sessionId, token, solutions: nonce, challenge_signature: challenge.challenge_signature })
            });
            if (!v.ok) {
                const data = await v.json().catch(() => ({}));
                this._handleError(v.status, data, '/redeem');
                this.sessionId = null;
                this.sessionSignature = null;
                return;
            }
            const result = await v.json();
            if (result.success) {
                spin.style.display = "none";
                label.innerText = successLabel;
                box.setAttribute('aria-label', successLabel);
                box.setAttribute('aria-busy', 'false');
                box.classList.add('solved');
                this.token = result.token;
                this.dispatchEvent(new CustomEvent('solve', { detail: { token: result.token }, bubbles: true, composed: true }));
            } else {
                this._handleError(0, result, '/redeem');
                this.sessionId = null;
                this.sessionSignature = null;
            }
        } catch(e) {
            this._handleError(0, { error: this.i18n('error', 'Error. Try again.') }, '/challenge');
            this.sessionId = null;
            this.sessionSignature = null;
        }
    }

    async sha256(m) {
        const b = new TextEncoder().encode(m);
        const d = await crypto.subtle.digest('SHA-256', b);
        return Array.from(new Uint8Array(d)).map(x => x.toString(16).padStart(2,'0')).join('');
    }
}
customElements.define('menta-widget', CapWidget);"""

PRIVACY_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Privacy Policy — Menta</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;max-width:700px;margin:2rem auto;padding:0 1rem;line-height:1.6;}h1{font-size:1.5rem;}a{color:#000;}</style>
</head>
<body>
<h1>Privacy Policy</h1>
<p>MentaCaptcha is a privacy-first, self-hosted CAPTCHA. We do not use cookies, fingerprinting or third-party telemetry.</p>
<ul>
<li>We collect only the minimum data needed for bot protection: a hashed/anonymized IP prefix, challenge metadata, and solve timestamps.</li>
<li>Full IP addresses are not logged by default. Where required, they may be kept only for the time needed for rate limiting.</li>
<li>Data is stored in the EU region for our SaaS offering and encrypted at rest with SQLCipher.</li>
<li>Data retention is configurable and automatically enforced by the platform.</li>
<li>Users have the right to access, export and delete their data via the admin endpoints.</li>
</ul>
<p>For data subject requests, contact the site operator.</p>
<p><a href="/">&larr; Back</a></p>
</body>
</html>"""

TERMS_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Terms of Service — Menta</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;max-width:700px;margin:2rem auto;padding:0 1rem;line-height:1.6;}h1{font-size:1.5rem;}a{color:#000;}</style>
</head>
<body>
<h1>Terms of Service</h1>
<p>MentaCaptcha is provided "as is" for bot protection on websites and applications.</p>
<ul>
<li>Self-hosted deployments are the responsibility of the operator.</li>
<li>SaaS users are bound by the Data Processing Addendum and Privacy Policy.</li>
<li>Do not use MentaCaptcha to violate any applicable law.</li>
<li>We may update these terms; continued use constitutes acceptance.</li>
</ul>
<p><a href="/">&larr; Back</a></p>
</body>
</html>"""

DPA_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Data Processing Addendum — Menta</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;max-width:700px;margin:2rem auto;padding:0 1rem;line-height:1.6;}h1{font-size:1.5rem;}a{color:#000;}</style>
</head>
<body>
<h1>Data Processing Addendum</h1>
<p>This DPA applies to MentaCaptcha SaaS customers.</p>
<ul>
<li>Menta acts as a data processor for CAPTCHA challenge and session data.</li>
<li>Processing is limited to rate limiting, abuse detection and token issuance.</li>
<li>Data is encrypted in transit and at rest; hosted in the EU.</li>
<li>Sub-processors are limited to the hosting infrastructure provider.</li>
<li>Customers may request data export or deletion at any time.</li>
</ul>
<p><a href="/">&larr; Back</a></p>
</body>
</html>"""

BAA_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Business Associate Agreement — Menta</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;max-width:700px;margin:2rem auto;padding:0 1rem;line-height:1.6;}h1{font-size:1.5rem;}a{color:#000;}</style>
</head>
<body>
<h1>Business Associate Agreement</h1>
<p>MentaCaptcha does not process Protected Health Information (PHI) by default. This BAA is provided for healthcare customers who require it under HIPAA.</p>
<ul>
<li>Menta will safeguard any PHI in accordance with HIPAA Security Rule requirements.</li>
<li>Encryption, access controls, audit logging and backup are implemented.</li>
<li>Self-hosted deployments remain the responsibility of the covered entity.</li>
</ul>
<p>Contact us to execute a signed BAA.</p>
<p><a href="/">&larr; Back</a></p>
</body>
</html>"""

if __name__ == '__main__':
    app.run(port=5000)
