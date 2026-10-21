import base64
import collections
import hashlib
import hmac
import ipaddress
import io
import threading
import analytics
import bot_shield
import jwt
import os

import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
import urllib.error
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        pass

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
from flask import Flask, request, jsonify, render_template_string, render_template, send_file, send_from_directory, g, session
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
LOG_IP_FULL = os.environ.get('LOG_IP_FULL', 'false').lower() in ('1', 'true', 'yes', 'on')


def _env_int(name, default):
    """Lee una variable de entorno entera sin romper el arranque si es invalida."""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == '':
        return default
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        print('[CONFIG] %s invalido (%r), se usa %s' % (name, raw, default))
        return default


DATA_RETENTION_HOURS = _env_int('DATA_RETENTION_HOURS', 24)

# --- Analiticas de trafico (privacy-first) ----------------------------------
# Las IPs nunca se persisten en claro: solo se guarda un pseudonimo HMAC.
ANALYTICS_ENABLED = os.environ.get('ANALYTICS_ENABLED', 'true').lower() in ('1', 'true', 'yes', 'on')
ANALYTICS_RETENTION_HOURS = _env_int('ANALYTICS_RETENTION_HOURS', DATA_RETENTION_HOURS)
# El rate de muestreo (ANALYTICS_LOG_SAMPLE_RATE) lo aplica el modulo analytics.
# Solo se registran estos endpoints (whitelist). Admin y estaticos quedan fuera.
ANALYTICS_ENDPOINTS = (
    '/init',
    '/challenge',
    '/redeem',
    '/verify',
    '/challenge-page',
    '/shield/check',
    '/shield/redeem',
    '/shield/verify',
)

CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '')
CORS_MODE = os.environ.get('CORS_MODE', 'strict')  # strict or permissive

# Modo ante peticiones con headers de proxy cuando el origen no es confiable:
#   - 'fail_closed' (por defecto): rechaza la peticion con 400.
#   - 'warn': sigue sirviendo la peticion pero registra una advertencia
#     (rate-limited) para que sea visible en los logs.
#   - 'off': desactiva el check por completo.
_raw_proxy_fail_closed = os.environ.get('PROXY_FAIL_CLOSED', 'true').strip().lower()
if _raw_proxy_fail_closed in ('1', 'true', 'yes', 'on'):
    PROXY_FAIL_MODE = 'fail_closed'
elif _raw_proxy_fail_closed == 'warn':
    PROXY_FAIL_MODE = 'warn'
elif _raw_proxy_fail_closed in ('', '0', 'false', 'no', 'off'):
    PROXY_FAIL_MODE = 'off'
else:
    print('[CONFIG] PROXY_FAIL_CLOSED invalido (%r), se usa fail_closed. Valores: fail_closed | warn | off' % _raw_proxy_fail_closed)
    PROXY_FAIL_MODE = 'fail_closed'


def _warn_proxy_misconfiguration(remote):
    """Registra una advertencia de proxy mal configurado (max 1 cada 60s)."""
    now = time.time()
    if now - _warn_proxy_misconfiguration.last_log < _warn_proxy_misconfiguration.interval:
        return
    _warn_proxy_misconfiguration.last_log = now
    print(
        '[PROXY] Cabeceras de proxy detectadas pero remote_addr (%s) no esta en TRUSTED_PROXIES; '
        'las cabeceras de cliente se ignoran. Configura TRUSTED_PROXIES con las IPs/CIDRs de tu '
        'proxy (Cloudflare, nginx, ...) o ajusta PROXY_FAIL_CLOSED (fail_closed | warn | off).'
        % remote
    )

_warn_proxy_misconfiguration.last_log = 0.0
_warn_proxy_misconfiguration.interval = 60

# Aviso al arrancar: si no hay proxies de confianza configurados, cualquier
# desplegable detrás de Cloudflare/nginx (o un atacante enviando headers de
# proxy a Menta expuesto a internet) dispara el check de misconfiguration.
if not os.environ.get('TRUSTED_PROXIES', '').strip():
    print(
        '[CONFIG] TRUSTED_PROXIES no esta configurado. Si Menta corre detras de un proxy '
        'reverso (Cloudflare, nginx, ...) configuralo con las IPs/CIDRs del proxy para resolver '
        'la IP del cliente. Con PROXY_FAIL_CLOSED=%s las peticiones con headers de proxy '
        '(CF-Connecting-IP, X-Forwarded-For, X-Real-IP) desde origenes no confiables se '
        'rechazan con 400; usa PROXY_FAIL_CLOSED=warn para avisar en log sin rechazar, u off '
        'para desactivar el check.' % PROXY_FAIL_MODE
    )

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
MAX_DIFFICULTY = os.environ.get('MAX_DIFFICULTY', '00000000')
# Tenant global para el widget de protección universal (sin registro de dominio).
SHIELD_TENANT = '__shield__'
# Validez del clearance token emitido por /shield/redeem (segundos).
SHIELD_CLEARANCE_TTL = int(os.environ.get('SHIELD_CLEARANCE_TTL', '86400'))
# Dificultad del PoW invisible del shield (4 ceros ≈ ~70k hashes ≈ <2s en JS).
SHIELD_DIFFICULTY = os.environ.get('SHIELD_DIFFICULTY', '0000')

# Rate limits del shield. /shield/* no valida Origin por diseño, así que el
# cupo por prefijo /24 se quema fácilmente: un único atacante podría bloquear
# a todo un ISP. Por eso el límite primario usa la IP exacta pseudonimizada
# (HMAC-SHA256, irreversible y sin almacenar la IP en claro) y el prefijo
# solo actúa como backstop con un cupo mucho más generoso.
RL_SHIELD_CHECK_PER_IP = os.environ.get('RL_SHIELD_CHECK_PER_IP', '20,60')
RL_SHIELD_REDEEM_PER_IP = os.environ.get('RL_SHIELD_REDEEM_PER_IP', '10,60')
RL_SHIELD_CHECK_PREFIX = os.environ.get('RL_SHIELD_CHECK_PREFIX', '120,60')
RL_SHIELD_REDEEM_PREFIX = os.environ.get('RL_SHIELD_REDEEM_PREFIX', '60,60')

# Días de inactividad tras los cuales se purgan cuentas y dominios obsoletos.
ACCOUNT_INACTIVITY_DAYS = int(os.environ.get('ACCOUNT_INACTIVITY_DAYS', 365))


# --- Conexiones -------------------------------------------------------------

# Pool de conexiones por proceso. Abrir una conexion SQLite (y descifrar la
# key/master con SQLCipher) en cada llamada era lo mas caro del request path;
# con el pool se conecta una vez por worker y las llamadas reutilizan conexiones.
_DB_POOL = []
_DB_POOL_LOCK = threading.Lock()
_DB_POOL_SIZE = _env_int('DB_CONN_POOL_SIZE', 8)
_DB_READY_LOCK = threading.Lock()
_DB_READY = False
_DB_WARNED_PLAIN = False


def _open_connection():
    """Abre una conexion nueva con los PRAGMA de rendimiento aplicados."""
    global _DB_WARNED_PLAIN, _DB_READY
    use_sqlcipher = DB_ENCRYPTION_KEY and sqlcipher3 is not None
    if use_sqlcipher:
        # La migracion (cifrar una BD en claro) solo puede pasar una vez y en un
        # solo hilo; el resto de conexiones van directo a abrir con clave.
        with _DB_READY_LOCK:
            migrate_plain = not _DB_READY and os.path.exists(DB_PATH)
            conn = sqlcipher3.connect(DB_PATH, check_same_thread=False)
            conn.row_factory = sqlcipher3.Row
            # Safe string literal for the PRAGMA key
            key_escaped = DB_ENCRYPTION_KEY.replace("'", "''")
            conn.execute("PRAGMA key='{}'".format(key_escaped))
            if migrate_plain:
                try:
                    conn.execute("SELECT 1")
                except Exception:
                    # If the existing DB is plain, back it up and create a fresh encrypted one.
                    backup = DB_PATH + '.legacy-' + str(int(time.time()))
                    conn.close()
                    os.rename(DB_PATH, backup)
                    print('[DB] Backed up plain database to:', backup)
                    conn = sqlcipher3.connect(DB_PATH, check_same_thread=False)
                    conn.row_factory = sqlcipher3.Row
                    conn.execute("PRAGMA key='{}'".format(key_escaped))
                _DB_READY = True
    else:
        if DB_ENCRYPTION_KEY and sqlcipher3 is None and not _DB_WARNED_PLAIN:
            _DB_WARNED_PLAIN = True
            print('[WARN] DB_ENCRYPTION_KEY is set but sqlcipher3 is not installed; using plain sqlite3.')
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
    # WAL permite lectores concurrentes; synchronous=NORMAL ya no pierde datos
    # ante una caida del proceso (solo ante corte de energia) y evita el fsync
    # por commit, el principal cuello de botella de escritura.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    # Espera hasta 5s el lock de escritura antes de fallar con 'database is
    # locked' (varios workers gunicorn escribiendo a la vez).
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


class _PooledConnection:
    """Wrapper que replica la semantica de `with conn` de sqlite3 y al salir
    devuelve la conexion al pool en lugar de cerrarla."""

    def __init__(self, conn):
        self._conn = conn

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        return self._conn

    def __exit__(self, exc_type, exc_val, tb):
        conn = self._conn
        healthy = True
        try:
            if exc_type is None:
                if conn.in_transaction:
                    conn.commit()
            else:
                try:
                    conn.rollback()
                except Exception:
                    healthy = False
        except Exception:
            # El error se propaga (misma semantica que `with conn` de sqlite3),
            # pero una conexion en estado dudoso se cierra y no vuelve al pool.
            healthy = False
            raise
        finally:
            if healthy:
                with _DB_POOL_LOCK:
                    if len(_DB_POOL) < _DB_POOL_SIZE:
                        _DB_POOL.append(conn)
                        conn = None
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        return False


def get_db():
    """Open the database. If DB_ENCRYPTION_KEY is set, use SQLCipher via sqlcipher3."""
    with _DB_POOL_LOCK:
        if _DB_POOL:
            return _PooledConnection(_DB_POOL.pop())
    return _PooledConnection(_open_connection())

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
            CREATE TABLE IF NOT EXISTS admin_2fa (
                id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                created_at REAL NOT NULL,
                confirmed INTEGER NOT NULL DEFAULT 1
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
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_totp_recovery ON totp_recovery_codes(owner, used)""")
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
        # Tenant separation for self-hosted multi-site deployments
        for table in ["challenges", "rate_limits", "solved_challenges", "sessions", "failed_attempts"]:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
            if "tenant_id" not in cols:
                conn.execute("ALTER TABLE %s ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''" % table)
        # Accounts columns
        cols_accounts = {r[1] for r in conn.execute("PRAGMA table_info(accounts)").fetchall()}
        for col in ["primary_domain", "totp_secret"]:
            if col not in cols_accounts:
                conn.execute("ALTER TABLE accounts ADD COLUMN %s TEXT" % col)
        # New tables for domain anti-bypass
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_history (
                domain_root TEXT PRIMARY KEY,
                account_number TEXT NOT NULL,
                first_seen_at REAL NOT NULL,
                last_active_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                release_after REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_history ON domain_history(account_number, status, last_active_at)")
        cols_dh = {r[1] for r in conn.execute("PRAGMA table_info(domain_history)").fetchall()}
        if "paid" not in cols_dh:
            conn.execute("ALTER TABLE domain_history ADD COLUMN paid INTEGER NOT NULL DEFAULT 0")
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL DEFAULT '',
                timestamp REAL NOT NULL,
                ip_hash TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT 'Unknown',
                country_code TEXT NOT NULL DEFAULT 'Unknown',
                region TEXT NOT NULL DEFAULT 'Unknown',
                city TEXT NOT NULL DEFAULT 'Unknown',
                method TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                endpoint TEXT NOT NULL DEFAULT '',
                status INTEGER NOT NULL DEFAULT 0,
                bytes INTEGER NOT NULL DEFAULT 0,
                duration_ms REAL NOT NULL DEFAULT 0,
                cache_status TEXT NOT NULL DEFAULT 'DYNAMIC',
                user_agent TEXT NOT NULL DEFAULT '',
                browser TEXT NOT NULL DEFAULT 'Unknown',
                os TEXT NOT NULL DEFAULT 'Unknown',
                device TEXT NOT NULL DEFAULT 'Unknown',
                http_version TEXT NOT NULL DEFAULT 'Unknown',
                referer TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                colo TEXT NOT NULL DEFAULT 'Unknown',
                outcome TEXT NOT NULL DEFAULT 'other'
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rlog_tt ON request_log(tenant_id, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rlog_te ON request_log(tenant_id, endpoint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rlog_ti ON request_log(tenant_id, ip_hash)")

        # 2FA tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_2fa (
                id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                created_at REAL NOT NULL,
                confirmed INTEGER NOT NULL DEFAULT 1
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
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_totp_recovery ON totp_recovery_codes(owner, used)""")
        cols_2fa = {r[1] for r in conn.execute("PRAGMA table_info(admin_2fa)").fetchall()}
        if "confirmed" not in cols_2fa:
            conn.execute("ALTER TABLE admin_2fa ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 1")
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
                ("request_log", "timestamp", max(3600, ANALYTICS_RETENTION_HOURS * 3600)),
            ]:
                conn.execute("DELETE FROM %s WHERE %s < ?" % (table, col), (now - window,))
        print("[CLEANUP] Expired data removed")
    except Exception as e:
        print("[CLEANUP ERROR] %s" % e)
_cleanup()

# --- Bufferes de escritura asíncronos flush -----------------------------------

# Auditoría (failed_attempts) y analítica (request_log) no participan en
# decisiones del request: se acumulan en memoria y un hilo background las
# vacía en SQLite con executemany. En un crash se pierden a lo sumo los
# últimos FLUSH_INTERVAL segundos de auditoría, no datos funcionales.
_FLUSH_INTERVAL = float(os.environ.get('DB_FLUSH_INTERVAL', '3'))
_FLUSH_BATCH = int(os.environ.get('DB_FLUSH_BATCH', '2000'))

_fail_lock = threading.Lock()
_fail_queue = collections.deque()
_fail_index = {}          # (tenant_id, ip) -> deque de timestamps
_fail_gc_last = 0.0

_analytics_lock = threading.Lock()
_analytics_queue = collections.deque()

REQUEST_LOG_SQL = """INSERT INTO request_log (
       tenant_id, timestamp, ip_hash, country, country_code, region, city,
       method, path, endpoint, status, bytes, duration_ms, cache_status,
       user_agent, browser, os, device, http_version, referer, host, colo, outcome
   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

FAILED_ATTEMPTS_SQL = (
    "INSERT INTO failed_attempts (tenant_id, ip, endpoint, reason, challenge_id, timestamp)"
    " VALUES (?, ?, ?, ?, ?, ?)")


def _recent_failures_count(tenant_id, ip, window):
    """Fails recientes de (tenant_id, ip) para las senales anti-bot.

    En modo `memory` se lee del indice en memoria que rellena log_failure,
    equivalente al COUNT(*) sobre failed_attempts que se usaba antes.
    """
    bucket = (tenant_id or '', ip or '')
    now = time.time()
    cutoff = now - window
    if RL_BACKEND == 'memory':
        with _fail_lock:
            dq = _fail_index.get(bucket)
            if not dq:
                return 0
            while dq and dq[0] <= cutoff:
                dq.popleft()
            return len(dq)
    with get_db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM failed_attempts WHERE tenant_id = ? AND ip = ? AND timestamp > ?",
            (tenant_id, ip, cutoff)
        ).fetchone()[0]


def _drain_failure_queue(conn):
    rows = []
    global _fail_gc_last
    now = time.time()
    with _fail_lock:
        if _fail_queue:
            while _fail_queue and len(rows) < _FLUSH_BATCH:
                rows.append(_fail_queue.popleft())
        # GC del índice de fallos recientes: la ventana más larga usada es 600s.
        if now - _fail_gc_last >= 60:
            _fail_gc_last = now
            stale = [k for k, dq in _fail_index.items() if not dq or dq[-1] <= now - 900]
            for k in stale:
                _fail_index.pop(k, None)
    if rows:
        try:
            conn.executemany(FAILED_ATTEMPTS_SQL, rows)
        except Exception as e:
            print('[AUDIT ERROR] %s (se perdieron %d filas)' % (e, len(rows)))


def _drain_analytics_queue(conn):
    rows = []
    with _analytics_lock:
        while _analytics_queue and len(rows) < _FLUSH_BATCH:
            rows.append(_analytics_queue.popleft())
    if rows:
        try:
            conn.executemany(REQUEST_LOG_SQL, rows)
        except Exception as e:
            print('[ANALYTICS ERROR] %s (se perdieron %d filas)' % (e, len(rows)))


def _drain_queues():
    fails = len(_fail_queue)
    analytics_n = len(_analytics_queue)
    if fails == 0 and analytics_n == 0:
        return
    try:
        with get_db() as conn:
            _drain_failure_queue(conn)
            _drain_analytics_queue(conn)
    except Exception as e:
        print('[FLUSH ERROR] %s' % e)


def _flusher_loop():
    while True:
        time.sleep(_FLUSH_INTERVAL)
        _drain_queues()

threading.Thread(target=_flusher_loop, daemon=True, name='db-flusher').start()

def current_tenant():
    """Identificador de tenant para separación por API key."""
    return getattr(g, 'tenant_id', '')


@app.before_request
def set_tenant():
    """Lee el tenant desde el header X-API-Key."""
    api_key = request.headers.get('X-API-Key', '')
    if api_key:
        g.tenant_id = api_key
    else:
        origin = request.headers.get('Origin')
        account = get_account_by_origin(origin) if origin else None
        g.tenant_id = account['account_number'] if account else ''


def _analytics_endpoint_for(path):
    """Normaliza la ruta y devuelve el endpoint de la whitelist (o '' si no aplica)."""
    normalized = analytics.normalize_path(path)
    if normalized in ANALYTICS_ENDPOINTS:
        return normalized
    return ''


def _analytics_tenant_for(endpoint):
    """Tenant al que se atribuye la peticion.

    El trafico de /shield/* vive siempre en su propio bucket (SHIELD_TENANT)
    para no mezclarse con el de los tenants registrados. El resto usa el tenant
    resuelto por ``set_tenant()`` (API key u origin), vacio si es anonimo.
    """
    if endpoint.startswith('/shield/'):
        return SHIELD_TENANT
    return current_tenant()


@app.before_request
def analytics_begin():
    """Marca el inicio de medicion para los endpoints incluidos en la whitelist."""
    if not ANALYTICS_ENABLED:
        return None
    endpoint = _analytics_endpoint_for(request.path)
    if not endpoint:
        return None
    if not analytics.should_sample():
        return None
    g.analytics_start = time.perf_counter()
    g.analytics_endpoint = endpoint
    return None


def _record_request_log(response):
    """Inserta la peticion en ``request_log`` usando una IP pseudonimizada."""
    endpoint = getattr(g, 'analytics_endpoint', '')
    start = getattr(g, 'analytics_start', None)
    if not endpoint or start is None:
        return

    raw_ip = _get_raw_client_ip()
    ip_hash = analytics.pseudonymize_ip(raw_ip)
    geo = analytics.geolocate(raw_ip)
    user_agent = (request.headers.get('User-Agent') or '')[:512]
    browser, os_name, device = analytics.parse_user_agent(user_agent)

    duration_ms = (time.perf_counter() - start) * 1000.0
    status = response.status_code
    size = response.content_length
    if size is None:
        try:
            size = len(response.get_data())
        except Exception:
            size = 0

    row = (
        _analytics_tenant_for(endpoint),
        time.time(),
        ip_hash,
        geo['country'],
        geo['country_code'],
        geo['region'],
        geo['city'],
        request.method[:16],
        analytics.normalize_path(request.path)[:256],
        endpoint,
        status,
        int(size or 0),
        round(duration_ms, 3),
        analytics.cache_status(response, request),
        user_agent,
        browser,
        os_name,
        device,
        analytics.http_version(request),
        analytics.referer_host(request),
        (request.headers.get('Host') or '')[:128],
        analytics.colo(response, request),
        analytics.classify_outcome(status, response),
    )
    with _analytics_lock:
        _analytics_queue.append(row)
        # Backpressure: si el flusher se retrasa mucho, descartar lo viejo
        # (analitica, no funcional) para no crecer sin limite.
        while len(_analytics_queue) > 10000:
            _analytics_queue.popleft()


@app.after_request
def analytics_record(response):
    """Persiste la medicion de la peticion (nunca la IP cruda)."""
    if getattr(g, 'analytics_endpoint', ''):
        try:
            _record_request_log(response)
        except Exception as e:
            print('[ANALYTICS ERROR] %s' % e)
        finally:
            g.analytics_endpoint = ''
            g.analytics_start = None
    return response


def generate_account_number(conn, now):
    """Genera un número de cuenta de 16 dígitos único (la PK resuelve la carrera).

    Inserta usando la MISMA conexión del caller y reintenta en colisión de PK,
    eliminando el TOCTOU de comprobar existencia en una conexión distinta.
    El caller completa el resto de campos en la misma transacción.
    """
    while True:
        number = ''.join(str(secrets.randbelow(10)) for _ in range(16))
        try:
            conn.execute(
                "INSERT INTO accounts (account_number, tenant_id, domains, primary_domain, created_at, last_seen_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (number, '', '', '', now, now, None)
            )
            return number
        except Exception as e:
            # sqlcipher3 y sqlite3 tienen clases IntegrityError distintas; da igual
            # el driver, la-violacion-de-PK la reconocemos por nombre de tipo.
            if type(e).__name__ != 'IntegrityError':
                raise
            continue  # colisión rara; reintentar con otro número


def get_account(tenant_id):
    """Obtiene la cuenta asociada al tenant_id (número de cuenta)."""
    if not tenant_id:
        return None
    try:
        with get_db() as conn:
            return conn.execute("SELECT * FROM accounts WHERE tenant_id = ? OR account_number = ?", (tenant_id, tenant_id)).fetchone()
    except Exception:
        return None


# `last_seen_at` se usa para la purga de cuentas inactivas: no hace falta
# persistirlo en cada request. Debounce en memoria persiste la marca como
# maximo una vez por ventana; introduce error de +/- ACCOUNT_LAST_SEEN_FLUSH
# segundos en la fecha de inactividad (irrelevante con 365 dias de purga).
_last_seen_lock = threading.Lock()
_last_seen_cache = {}
LAST_SEEN_FLUSH_SECONDS = float(os.environ.get('ACCOUNT_LAST_SEEN_FLUSH', '30'))


def update_account_last_seen(tenant_id, conn=None):
    """Actualiza el último visto de una cuenta (con debounce en memoria).

    Si se pasa ``conn`` (transaccion ya abierta del caller), el UPDATE se hace
    dentro de esa transaccion al evitar un commit extra en el request path.
    """
    if not tenant_id:
        return
    now = time.time()
    with _last_seen_lock:
        if now - _last_seen_cache.get(tenant_id, 0) < LAST_SEEN_FLUSH_SECONDS:
            return
        _last_seen_cache[tenant_id] = now
        # Bound del cache: cuentas se purgan por inactividad, la lista crece
        # poco; igualmente evitamos que crezca indefinidamente.
        if len(_last_seen_cache) > 65536:
            cutoff = now - LAST_SEEN_FLUSH_SECONDS * 2
            stale = [k for k, v in _last_seen_cache.items() if v < cutoff]
            for k in stale:
                _last_seen_cache.pop(k, None)
    try:
        sql = "UPDATE accounts SET last_seen_at = ? WHERE tenant_id = ? OR account_number = ?"
        if conn is not None:
            conn.execute(sql, (now, tenant_id, tenant_id))
        else:
            with get_db() as c:
                c.execute(sql, (now, tenant_id, tenant_id))
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
        host = value.split('/')[0]
        # Conservar hosts IPv6 literales con puerto, p. ej. [2001:db8::1]:8080
        if host.startswith('[') and ']' in host:
            host = host[1:host.index(']')]
        else:
            host = host.split(':')[0]
    if not host:
        return None
    host = host.strip('[]')
    # Hosts IPv6 literales: forma canónica entre corchetes en minúsculas
    if ':' in host:
        return '[' + host.lower() + ']'
    # Convertir IDN (unicode) a punycode cuando aplique
    if not host.isascii():
        try:
            host = host.encode('idna').decode('ascii').lower()
        except UnicodeError:
            pass
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
    """Busca la cuenta activa asociada a un origen CORS usando el historial de dominios."""
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
                "INSERT INTO domain_history (domain_root, account_number, first_seen_at, last_active_at, status, paid) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(domain_root) DO UPDATE SET account_number = excluded.account_number, last_active_at = excluded.last_active_at, status = excluded.status, paid = excluded.paid",
                (domain_root, account_number, now, now, status, 1 if paid else 0)
            )
    except Exception:
        pass


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


# --- Rate limiting en memoria ------------------------------------------------

# Los rate limits no necesitan durabilidad: si el proceso se reinicia, el peor
# caso es que una ventana se reinicie (el atacante recupera el cupo que perdia
# con el reinicio del servicio, no puede crear ventanas nuevas). Al vivir en
# memoria desaparecen del path de transacciones SQLite por completo: ni
# COUNT(*) sobre filas de log crecientes ni INSERT por request.
# En despliegues multi-worker (varios gunicorn workers) los cupos son por
# worker en este modo (limite global = suma suave de los workers); usar
# RL_BACKEND=sqlite si se necesita un contador unico compartido entre procesos.
RL_BACKEND = os.environ.get('RL_BACKEND', 'memory')

_rl_lock = threading.Lock()
_rl_windows = {}   # (tenant_id, ident, endpoint, window) -> deque de timestamps
_rl_gc_last = 0.0


def _rl_prune(deq, cutoff):
    while deq and deq[0] <= cutoff:
        deq.popleft()


def _rl_allow_memory(tenant_id, ident, endpoint, max_requests, window_seconds):
    """Ventana deslizante en memoria, mismo criterio que el backend sqlite."""
    ident = ident or ''
    now = time.time()
    cutoff = now - window_seconds
    with _rl_lock:
        global _rl_gc_last
        if now - _rl_gc_last >= 60:
            _rl_gc_last = now
            stale = [k for k, dq in _rl_windows.items() if not dq or dq[-1] <= now - 2 * window_seconds]
            for k in stale:
                _rl_windows.pop(k, None)
        key = (tenant_id or '', ident, endpoint, window_seconds)
        dq = _rl_windows.get(key)
        if dq is None:
            dq = collections.deque()
            _rl_windows[key] = dq
        _rl_prune(dq, cutoff)
        if len(dq) >= max_requests:
            return False
        dq.append(now)
        return True


def check_rate_limit_tenant(tenant_id, endpoint, limit_str):
    """Rate limit por tenant (cuenta) para mitigar farms distribuidas."""
    if not tenant_id or not limit_str:
        return True
    max_requests, window = _parse_rate_limit(limit_str)
    if max_requests is None:
        return True
    if RL_BACKEND == 'memory':
        return _rl_allow_memory(tenant_id, '', endpoint, max_requests, window)
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
    if RL_BACKEND == 'memory':
        return _rl_allow_memory('__global__', '', endpoint, max_requests, window)
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
    fails = _recent_failures_count(tenant_id, ip, 600)

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
    """Logs a failed attempt for audit and attack detection.

    No toca SQLite en el request path: encola para el flusher y, en modo
    `memory`, alimenta el indice en memoria que consume check_bot_signals /
    get_difficulty. Solo se pierde la ultima ventana de auditoria (de ahi a
    DB_FLUSH_INTERVAL segundos) si el proceso muere.
    """
    if not ip and not tenant_id:
        return
    row = (tenant_id or '', ip or '', endpoint, reason, challenge_id, time.time())
    try:
        with _fail_lock:
            _fail_queue.append(row)
            # Backpressure: descartar lo mas viejo si el flusher se atrasa
            # (p.ej. ataque masivo); acota memoria, no es dato funcional.
            while len(_fail_queue) > 100000:
                _fail_queue.popleft()
            dq = _fail_index.get((row[0], row[1]))
            if dq is None:
                dq = collections.deque()
                _fail_index[(row[0], row[1])] = dq
            dq.append(row[5])
            while dq and dq[0] <= row[5] - 900:
                dq.popleft()
    except Exception as e:
        print("[AUDIT ERROR] %s" % e)

def check_rate_limit(ip, endpoint, max_requests, window_seconds, tenant_id='', key=None):
    """Limita peticiones por identificador de red (``key`` si se pasa, ``ip`` si no).

    ``key`` permite limitar por otro identificador (ej. pseudonimo HMAC de la
    IP completa) sin alterar lo que se audita en ``failed_attempts``.
    """
    bucket = key or ip
    if RL_BACKEND == 'memory':
        return _rl_allow_memory(tenant_id, bucket, endpoint, max_requests, window_seconds)
    now = time.time()
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE tenant_id = ? AND ip = ? AND endpoint = ? AND timestamp > ?",
            (tenant_id, bucket, endpoint, now - window_seconds)
        ).fetchone()[0]
        if count >= max_requests:
            return False
        conn.execute(
            "INSERT INTO rate_limits (tenant_id, ip, endpoint, timestamp) VALUES (?, ?, ?, ?)",
            (tenant_id, bucket, endpoint, now)
        )
    return True


def shield_ip_key():
    """Pseudonimo HMAC-SHA256 de la IP completa, solo para rate limiting del shield.

    A diferencia de ``get_client_ip()`` (que trunca a /24 o /64 para minimizar
    datos personales), este identificador distingue IPs individuales sin
    revelarlas: sin la sal (``ANALYTICS_IP_SALT`` o ``SECRET_KEY``) es
    irreversible. Se usa solo como clave de cupo, no se audita ni se muestra.
    """
    return 'hmac:' + analytics.pseudonymize_ip(_get_raw_client_ip())

def check_bot_signals(ip, tenant_id=''):
    """Detects IPs with suspicious patterns before spending resources on challenge."""
    if _recent_failures_count(tenant_id, ip, 600) > 5:
        return True, "too_many_failures"
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
            if count > 2:
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
    if solve_time is not None and solve_time < 0.03:
        return False, "solve_too_fast"
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
    # El widget de protección universal (menta-shield.js) funciona en cualquier
    # página sin registro previo: no aplicamos el check de origen.
    if request.path.startswith('/shield/') or request.path == '/menta-shield.js':
        if request.method != 'OPTIONS':
            if check_proxy_misconfiguration():
                if PROXY_FAIL_MODE == 'fail_closed':
                    return jsonify({"success": False, "error": "Proxy misconfiguration. TRUSTED_PROXIES must be set."}), 400
                if PROXY_FAIL_MODE == 'warn':
                    _warn_proxy_misconfiguration(request.remote_addr or "unknown")
        return None

    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin')
        tenant = current_tenant()
        if origin and not is_origin_allowed(tenant, origin):
            return jsonify({
                "success": False,
                "error": "This domain is not registered or authorized by Menta.",
                "origin": origin,
            }), 403
        return None

    if check_proxy_misconfiguration():
        if PROXY_FAIL_MODE == 'fail_closed':
            return jsonify({"success": False, "error": "Proxy misconfiguration. TRUSTED_PROXIES must be set."}), 400
        if PROXY_FAIL_MODE == 'warn':
            _warn_proxy_misconfiguration(request.remote_addr or "unknown")

    origin = request.headers.get('Origin')
    if origin and not is_origin_allowed(current_tenant(), origin):
        return jsonify({
            "success": False,
            "error": "This domain is not registered or authorized by Menta.",
            "origin": origin,
        }), 403


@app.after_request
def cors(response):
    origin = request.headers.get('Origin')
    tenant = current_tenant()
    # El shield universal refleja cualquier origen: se usa en páginas no registradas.
    if request.path.startswith('/shield/'):
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
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
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';"
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
    """Devuelve el secret TOTP del admin confirmado, o None si no está configurado."""
    try:
        with get_db() as conn:
            row = conn.execute("SELECT secret FROM admin_2fa WHERE id = 1 AND confirmed = 1").fetchone()
            return row['secret'] if row else None
    except Exception:
        return None


def _get_admin_pending_secret():
    """Devuelve el secret TOTP pendiente de verificar por el admin, o None."""
    try:
        with get_db() as conn:
            row = conn.execute("SELECT secret FROM admin_2fa WHERE id = 1 AND confirmed = 0").fetchone()
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


# Target imposible: SHA-256 produce 64 hex chars; 16 ceros son ~2^64 hashes.
# Inalcanzable incluso para GPUs en un tiempo razonable.
TARPIT_TARGET = '0' * 16
TARPIT_EXPIRES = 3600  # 1 hora, así el bot no ve un "expired" rápido


def _issue_tarpit_challenge(ip, tenant=SHIELD_TENANT):
    challenge_id = secrets.token_hex(16)
    salt = secrets.token_hex(8) + ':' + get_ip_prefix(ip)
    ch_expires = time.time() + TARPIT_EXPIRES
    with get_db() as conn:
        conn.execute(
            "INSERT INTO challenges (id, tenant_id, salt, target, created_at, expires) VALUES (?,?,?,?,?,?)",
            (challenge_id, tenant, salt, TARPIT_TARGET, time.time(), ch_expires)
        )
    return {
        "success": True,
        "action": "shield",
        "tarpit": True,
        "token": challenge_id,
        "challenge": {
            "salt": salt,
            "target": TARPIT_TARGET,
            "expires": ch_expires,
            "challenge_signature": sign_challenge(challenge_id, salt, TARPIT_TARGET, ch_expires)
        }
    }


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', admin_token_required=bool(ADMIN_TOKEN))


@app.route('/demo')
def demo():
    # Aplicamos la lógica de bot_shield antes de servir la página de demo.
    ua = request.headers.get('User-Agent', '')
    ip = get_client_ip()
    decision = bot_shield.evaluate_request(ua, ip, request.path, request.headers.get('X-JA4-Fingerprint') or request.headers.get('X-JA3-Fingerprint'))
    if decision['action'] == 'block':
        # Bloqueamos a bots que explícitamente violen robots.txt y estén verificados.
        return jsonify({"error": "Access denied"}), 403
    # Para 'shield' o 'allow' devolvemos la página normalmente; el middleware
    # antes de la petición ya manejará la capa invisible si corresponde.
    return render_template('demo.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how-it-works.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/menta-logo.svg')
def logo():
    return send_file(os.path.join(os.path.dirname(__file__), 'menta-logo.svg'), mimetype='image/svg+xml')

@app.route('/menta-in-action.gif')
def hero_gif():
    return send_file(os.path.join(os.path.dirname(__file__), 'menta-in-action.gif'), mimetype='image/gif')

@app.route('/css/<path:filename>')
def styles(filename):
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'css'), filename)

@app.route('/fonts/<path:filename>')
def fonts(filename):
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'fonts'), filename)

@app.route('/js/<path:filename>')
def scripts(filename):
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'js'), filename)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/verify', methods=['GET'])
@app.route('/challenge-page', methods=['GET'])
def challenge_page():
    """Página de verificación humana (intersticial tipo Cloudflare Challenge
    Page): resuelve un PoW invisible vía /shield/check + /shield/redeem y
    redirige a `?next=` (solo rutas del mismo origen) tras guardar el clearance.
    """
    ua = request.headers.get('User-Agent', '')
    ip = get_client_ip()
    verdict = bot_shield.evaluate_request(
        ua, ip, request.path,
        request.headers.get('X-JA4-Fingerprint') or request.headers.get('X-JA3-Fingerprint')
    )
    if verdict['action'] in ('block', 'tarpit'):
        # Página trampa: parece normal pero /shield/check devolverá el PoW imposible
        return render_template('challenge.html')
    return render_template('challenge.html')


@app.errorhandler(404)
def not_found(error):
    # Las peticiones a la API esperan JSON; las páginas reciben el template HTML.
    if request.path.startswith(('/init', '/challenge', '/redeem', '/verify', '/shield/')) or \
            request.accept_mimetypes.best == 'application/json':
        return jsonify({"success": False, "error": "Not found"}), 404
    return render_template('404.html'), 404

@app.route('/init', methods=['POST'])
def init_session():
    ip = get_client_ip()
    tenant_id = current_tenant()
    origin = request.headers.get('Origin')

    # bot_shield: los bots conocidos que violan robots.txt y están verificados
    # se bloquean aquí; el resto del veredicto se aplica en /challenge.
    shield_verdict = bot_shield.evaluate_request(request.headers.get('User-Agent', ''), ip, request.path, request.headers.get('X-JA4-Fingerprint') or request.headers.get('X-JA3-Fingerprint'))
    if shield_verdict['action'] == 'block':
        log_failure(ip, '/init', 'bot_shield_' + shield_verdict['reason'], tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    ok, reason = check_browser_signals(tenant_id, origin)
    if not ok:
        log_failure(ip, '/init', 'browser_' + reason, tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    if not check_rate_limit(ip, '/init', 20, 60, tenant_id=tenant_id):
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

    # bot_shield: bloqueamos bots verificados que desobedecen robots.txt y
    # marcamos clientes sospechosos (impersonadores, scripts genéricos) para
    # recibir el reto PoW a dificultad máxima.
    shield_verdict = bot_shield.evaluate_request(request.headers.get('User-Agent', ''), ip, request.path, request.headers.get('X-JA4-Fingerprint') or request.headers.get('X-JA3-Fingerprint'))
    if shield_verdict['action'] == 'block':
        log_failure(ip, '/challenge', 'bot_shield_' + shield_verdict['reason'], tenant_id=tenant_id)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    # NUEVO: tarpit — el bot recibe un PoW imposible en vez de uno normal
    if shield_verdict['action'] == 'tarpit':
        log_failure(ip, '/challenge', 'bot_shield_tarpit', tenant_id=tenant_id)
        return jsonify(_issue_tarpit_challenge(ip, tenant=tenant_id))

    # Solo forzamos PoW máximo para sospechosos confirmados por el shield
    # (impersonadores de bots, scripts genéricos). Un navegador normal también
    # recibe 'shield' como 'unverified_client', pero sin hint de dificultad.
    client_automation = bool((request.get_json(silent=True) or {}).get('automation'))
    shielded = (shield_verdict['action'] == 'shield'
                and shield_verdict.get('difficulty_hint') == 'max') or client_automation
    if shielded:
        log_failure(ip, '/challenge', 'bot_shield_client_automation' if client_automation else 'bot_shield_' + shield_verdict['reason'], tenant_id=tenant_id)

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
    salt = secrets.token_hex(8) + ':' + get_ip_prefix(ip)
    target = get_difficulty(ip, tenant_id=tenant_id)
    if shielded:
        # Los clientes marcados por bot_shield siempre reciben el PoW más duro.
        target = _max_difficulty(target, MAX_DIFFICULTY)
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
            # Dentro de la misma transaccion: evita abrir otra conexion/commit.
            update_account_last_seen(tenant_id, conn=conn)
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


@app.route('/shield/check', methods=['POST'])
def shield_check():
    """Widget de protección universal (menta-shield.js): evalúa la petición con
    bot_shield sin requerir registro de dominio ni el widget de captcha.
    - block  -> 403 (bot verificado que desobedece robots.txt)
    - shield -> reto PoW invisible a dificultad máxima
    - allow  -> paso directo
    """
    ip = get_client_ip()
    ip_key = shield_ip_key()
    ua = request.headers.get('User-Agent', '')
    data = request.get_json(silent=True) or {}
    path = data.get('path') or request.path

    # Backstop por prefijo (cupo generoso) y límite primario por IP exacta.
    if not check_rate_limit(ip, '/shield/check', *_parse_rate_limit(RL_SHIELD_CHECK_PREFIX), tenant_id=SHIELD_TENANT):
        log_failure(ip, '/shield/check', 'rate_limit', tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "action": "block", "error": "Too many requests."}), 429
    if not check_rate_limit(ip, '/shield/check', *_parse_rate_limit(RL_SHIELD_CHECK_PER_IP), tenant_id=SHIELD_TENANT, key=ip_key):
        log_failure(ip, '/shield/check', 'rate_limit', tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "action": "block", "error": "Too many requests."}), 429

    verdict = bot_shield.evaluate_request(ua, ip, path, request.headers.get('X-JA4-Fingerprint') or request.headers.get('X-JA3-Fingerprint'))
    if verdict['action'] == 'block':
        log_failure(ip, '/shield/check', 'bot_shield_' + verdict['reason'], tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "action": "block"}), 403

    # NUEVO: tarpit para bots conocidos
    if verdict['action'] == 'tarpit':
        log_failure(ip, '/shield/check', 'bot_shield_tarpit', tenant_id=SHIELD_TENANT)
        return jsonify(_issue_tarpit_challenge(ip))

    # `force` (página de verificación humana): emite el PoW aunque el veredicto
    # sea allow, para poder forzar el reto manualmente.
    force_challenge = bool(data.get('force')) or bool(data.get('automation'))

    if (verdict['action'] == 'shield' and verdict.get('difficulty_hint') == 'max') or force_challenge:
        # Impersonador de bot o script genérico con JS: PoW invisible duro
        # (o reto forzado desde la página de verificación).
        if not force_challenge:
            log_failure(ip, '/shield/check', 'bot_shield_' + verdict['reason'], tenant_id=SHIELD_TENANT)
        challenge_id = secrets.token_hex(16)
        salt = secrets.token_hex(8) + ':' + get_ip_prefix(ip)
        target = _max_difficulty(SHIELD_DIFFICULTY, MIN_DIFFICULTY)
        ch_expires = time.time() + 120
        with get_db() as conn:
            conn.execute(
                "INSERT INTO challenges (id, tenant_id, salt, target, created_at, expires) VALUES (?, ?, ?, ?, ?, ?)",
                (challenge_id, SHIELD_TENANT, salt, target, time.time(), ch_expires)
            )
        return jsonify({
            "success": True,
            "action": "shield",
            "token": challenge_id,
            "challenge": {
                "salt": salt,
                "target": target,
                "expires": ch_expires,
                "challenge_signature": sign_challenge(challenge_id, salt, target, ch_expires)
            }
        })

    return jsonify({"success": True, "action": "allow"})


@app.route('/shield/redeem', methods=['POST'])
def shield_redeem():
    """Valida la solución del PoW invisible y emite un clearance token."""
    ip = get_client_ip()
    ip_key = shield_ip_key()

    # Mismo esquema que /shield/check: backstop por prefijo + límite por IP exacta.
    if not check_rate_limit(ip, '/shield/redeem', *_parse_rate_limit(RL_SHIELD_REDEEM_PREFIX), tenant_id=SHIELD_TENANT):
        log_failure(ip, '/shield/redeem', 'rate_limit', tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "error": "Too many requests."}), 429
    if not check_rate_limit(ip, '/shield/redeem', *_parse_rate_limit(RL_SHIELD_REDEEM_PER_IP), tenant_id=SHIELD_TENANT, key=ip_key):
        log_failure(ip, '/shield/redeem', 'rate_limit', tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "error": "Too many requests."}), 429

    data = request.get_json(silent=True) or {}
    challenge_id = data.get('token')
    nonce = str(data.get('solutions') or '')
    ch_sig = data.get('challenge_signature')
    if not challenge_id or not nonce or not ch_sig:
        return jsonify({"success": False, "error": "Challenge data required."}), 403

    with get_db() as conn:
        row = conn.execute(
            "DELETE FROM challenges WHERE id = ? AND tenant_id = ? RETURNING salt, target, created_at, expires",
            (challenge_id, SHIELD_TENANT)
        ).fetchone()
    if not row or row["expires"] < time.time():
        log_failure(ip, '/shield/redeem', 'challenge_not_found', challenge_id, tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "error": "Challenge not found or expired."}), 400

    expected_sig = sign_challenge(challenge_id, row['salt'], row['target'], row['expires'])
    if not hmac.compare_digest(ch_sig, expected_sig):
        log_failure(ip, '/shield/redeem', 'bad_challenge_signature', challenge_id, tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "error": "Invalid challenge signature."}), 403

    if time.time() - row["created_at"] < 0.2:
        log_failure(ip, '/shield/redeem', 'too_fast', challenge_id, tenant_id=SHIELD_TENANT)
        return jsonify({"success": False, "error": "Suspicious activity detected."}), 403

    if hashlib.sha256((row['salt'] + nonce).encode()).hexdigest().startswith(row['target']):
        now = int(time.time())
        clearance = jwt.encode({
            "sub": "shield-clearance",
            "iat": now,
            "exp": now + SHIELD_CLEARANCE_TTL,
            "jti": secrets.token_hex(8),
            "ip": ip
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({"success": True, "clearance_token": clearance})

    log_failure(ip, '/shield/redeem', 'bad_pow', challenge_id, tenant_id=SHIELD_TENANT)
    return jsonify({"success": False, "error": "Incorrect solution."}), 403


@app.route('/shield/verify', methods=['POST'])
def shield_verify():
    """Valida server-to-server un clearance del shield SIN consumirlo
    (es reutilizable durante su TTL). Opcionalmente exige que la IP que
    presenta el token coincida con la IP para la que fue emitido."""
    data = request.get_json(silent=True) or {}
    token = data.get('token')
    if not token:
        return jsonify({"success": False, "valid": False, "error": "token required"}), 400

    if not check_rate_limit_global('/shield/verify', RL_GLOBAL_VERIFY):
        return jsonify({"success": False, "valid": False, "error": "Too many requests."}), 429

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({"success": True, "valid": False, "error": "expired"})
    except Exception:
        return jsonify({"success": True, "valid": False, "error": "invalid"})

    if payload.get('sub') != 'shield-clearance':
        return jsonify({"success": True, "valid": False, "error": "invalid"})

    if data.get('check_ip') and payload.get('ip') != get_client_ip():
        return jsonify({"success": True, "valid": False, "error": "ip_mismatch"})

    return jsonify({"success": True, "valid": True})


@app.route('/verify', methods=['POST'])
def verify_token():
    """Verifica server-to-server un token emitido por /redeem, sin exponer SECRET_KEY.
    Consume el token (single-use) marcando su jti en verified_tokens."""
    ip = get_client_ip()
    tenant_id = current_tenant()

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
            update_account_last_seen(tenant_id, conn=conn)
    except Exception:
        log_failure(ip, '/verify', 'token_reuse', tenant_id=tenant_id)
        return jsonify({"success": True, "valid": False, "error": "token already used"})

    return jsonify({"success": True, "valid": True})


def _create_account_from_request(data):
    """Crea una cuenta de administración a partir de datos. Valida dominio y conflictos."""
    domains = data.get('domains', '')
    notes = data.get('notes', '')
    domains = _normalize_domains_input(domains)

    # determine primary domain
    primary_input = data.get('primary_domain', '')
    if not primary_input:
        primary_input = domains.split(',')[0] if domains else ''
    primary_domain = normalize_domain(primary_input)
    if not primary_domain:
        return jsonify({"error": "A valid domain is required"}), 400

    # Check domain conflict across active/locked domains
    conflict = check_domain_conflict(primary_domain)
    if conflict and conflict['type'] == 'active':
        return jsonify({
            "error": "Domain already has an active owner.",
            "domain": conflict['domain'],
        }), 409

    now = time.time()

    with get_db() as conn:
        # La PK de account_number resuelve la carrera; generate inserta y el
        # UPDATE completa la fila en la misma transacción (sin TOCTOU).
        account_number = generate_account_number(conn, now)
        conn.execute(
            "UPDATE accounts SET tenant_id = ?, domains = ?, primary_domain = ?, created_at = ?, last_seen_at = ?, notes = ? WHERE account_number = ?",
            (account_number, domains, primary_domain, now, now, notes, account_number)
        )
    _register_domain_for_account(account_number, primary_domain, status='active')

    return {
        "success": True,
        "account_number": account_number,
        "primary_domain": primary_domain,
        "warning": "Save this number. It will not be shown again."
    }


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


@app.route('/admin/account/<account_number>/delete', methods=['POST'])
def delete_account(account_number):
    """Elimina una cuenta y sus datos asociados. Requiere admin."""
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
    with get_db() as conn:
        rows = conn.execute("SELECT account_number, primary_domain, created_at, last_seen_at, notes FROM accounts ORDER BY created_at DESC").fetchall()
    result = []
    for r in rows:
        result.append({
            "account_number": r['account_number'],
            "primary_domain": r['primary_domain'],
            "created_at": r['created_at'],
            "last_seen_at": r['last_seen_at'],
            "notes": r['notes']
        })
    return jsonify({"success": True, "accounts": result})


@app.route('/admin/metrics', methods=['GET'])
def metrics():
    ok, token_type, setup_required = _admin_authorized(readonly=True)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    _log_admin_access('/admin/metrics', token_type)
    try:
        hours = int(request.args.get('hours', '1'))
    except (TypeError, ValueError):
        hours = 1
    if hours < 0:
        hours = 0
    with get_db() as conn:
        now = time.time()
        tenant_id = current_tenant()
        cutoff = (now - hours * 3600) if hours > 0 else 0
        where = "timestamp > ?" if hours > 0 else "1=1"
        params = (tenant_id, cutoff) if hours > 0 else (tenant_id,)
        bot_detected = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM failed_attempts WHERE tenant_id = ? AND reason IN ('bad_pow', 'bad_signature') AND " + ("timestamp > ?" if hours > 0 else "1=1"),
            params
        ).fetchone()[0]
        total_failures = conn.execute(
            "SELECT COUNT(*) FROM failed_attempts WHERE tenant_id = ? AND " + ("timestamp > ?" if hours > 0 else "1=1"),
            params
        ).fetchone()[0]
        solves = conn.execute(
            "SELECT COUNT(*) FROM solved_challenges WHERE tenant_id = ? AND " + ("timestamp > ?" if hours > 0 else "1=1"),
            params
        ).fetchone()[0]
        bot_detected_all = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM failed_attempts WHERE tenant_id = ? AND reason IN ('bad_pow', 'bad_signature')",
            (tenant_id,)
        ).fetchone()[0]
        total_failures_all = conn.execute(
            "SELECT COUNT(*) FROM failed_attempts WHERE tenant_id = ?",
            (tenant_id,)
        ).fetchone()[0]
        solves_all = conn.execute(
            "SELECT COUNT(*) FROM solved_challenges WHERE tenant_id = ?",
            (tenant_id,)
        ).fetchone()[0]
        top_ips_raw = conn.execute(
            "SELECT ip, COUNT(*) AS failures, MAX(timestamp) AS last_seen FROM failed_attempts WHERE tenant_id = ? " + ("AND timestamp > ?" if hours > 0 else "") + " GROUP BY ip ORDER BY failures DESC LIMIT 25",
            (tenant_id, cutoff) if hours > 0 else (tenant_id,)
        ).fetchall()
        top_ips = []
        for r in top_ips_raw:
            item = dict(r)
            geo = analytics.geolocate(item["ip"])
            item["country"] = geo["country"]
            item["country_code"] = geo["country_code"]
            item["city"] = geo["city"]
            top_ips.append(item)
        return jsonify({
            "hours": hours,
            "bot_ips": bot_detected,
            "total_failures": total_failures,
            "solves": solves,
            "bot_ips_all": bot_detected_all,
            "total_failures_all": total_failures_all,
            "solves_all": solves_all,
            "sessions_active": conn.execute("SELECT COUNT(*) FROM sessions WHERE tenant_id = ? AND expires > ?", (tenant_id, now)).fetchone()[0],
            "top_ips": top_ips,
            "db_size": os.path.getsize(DB_PATH)
        })


def _analytics_grouped(conn, column, where, params, limit=25):
    """Ejecuta un GROUP BY sobre ``request_log`` y devuelve una lista de dicts."""
    rows = conn.execute(
        "SELECT %s AS label, COUNT(*) AS requests, SUM(bytes) AS bytes, "
        "AVG(duration_ms) AS avg_duration_ms, "
        "SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors "
        "FROM request_log WHERE %s GROUP BY %s ORDER BY requests DESC LIMIT ?" % (column, where, column),
        params + (limit,)
    ).fetchall()
    return [
        {
            "label": row["label"],
            "requests": row["requests"],
            "bytes": row["bytes"] or 0,
            "avg_duration_ms": round(row["avg_duration_ms"] or 0, 2),
            "errors": row["errors"] or 0,
        }
        for row in rows
    ]


@app.route('/admin/analytics', methods=['GET'])
def analytics_data():
    """Metricas de trafico privacy-first agregadas para el tenant autenticado."""
    ok, token_type, setup_required = _admin_authorized(readonly=True)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    _log_admin_access('/admin/analytics', token_type)

    try:
        hours = int(request.args.get('hours', '1'))
    except (TypeError, ValueError):
        hours = 1
    if hours < 0:
        hours = 0

    scope = request.args.get('scope', 'tenant')
    if scope not in ('tenant', 'shield'):
        scope = 'tenant'

    bucket = request.args.get('bucket', 'auto')
    if bucket not in ('auto', 'hour', 'day'):
        bucket = 'auto'
    if bucket == 'auto':
        bucket = 'day' if hours == 0 or hours > 48 else 'hour'

    tenant_id = SHIELD_TENANT if scope == 'shield' else current_tenant()

    with get_db() as conn:
        now = time.time()
        cutoff = (now - hours * 3600) if hours > 0 else 0
        where = "tenant_id = ?" + (" AND timestamp > ?" if hours > 0 else "")
        params = (tenant_id, cutoff) if hours > 0 else (tenant_id,)

        totals_row = conn.execute(
            "SELECT COUNT(*) AS requests, COUNT(DISTINCT ip_hash) AS visitors, "
            "SUM(bytes) AS bytes, AVG(duration_ms) AS avg_duration_ms, "
            "SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS server_errors, "
            "SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors, "
            "SUM(CASE WHEN status < 400 THEN 1 ELSE 0 END) AS successes, "
            "SUM(CASE WHEN cache_status IN ('HIT','REVALIDATED','STALE') THEN 1 ELSE 0 END) AS cache_hits "
            "FROM request_log WHERE " + where, params
        ).fetchone()

        durations = [r[0] for r in conn.execute(
            "SELECT duration_ms FROM request_log WHERE " + where, params).fetchall() if r[0] is not None]
        durations.sort()
        p95 = durations[min(len(durations) - 1, int(len(durations) * 0.95))] if durations else 0

        requests_total = totals_row["requests"] or 0
        cache_hits = totals_row["cache_hits"] or 0
        errors_total = totals_row["errors"] or 0

        if bucket == 'hour':
            bucket_expr = "CAST(timestamp / 3600 AS INTEGER) * 3600"
        else:
            bucket_expr = "CAST(strftime('%s', timestamp, 'unixepoch') AS INTEGER) / 86400 * 86400"

        timeline_rows = conn.execute(
            "SELECT %s AS bucket, COUNT(*) AS requests, SUM(bytes) AS bytes, "
            "AVG(duration_ms) AS avg_duration_ms, "
            "SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors "
            "FROM request_log WHERE %s GROUP BY bucket ORDER BY bucket" % (bucket_expr, where), params
        ).fetchall()
        timeline = [
            {
                "bucket": row["bucket"],
                "label": time.strftime('%Y-%m-%d %H:00' if bucket == 'hour' else '%Y-%m-%d', time.localtime(row["bucket"])),
                "requests": row["requests"],
                "bytes": row["bytes"] or 0,
                "avg_duration_ms": round(row["avg_duration_ms"] or 0, 2),
                "errors": row["errors"] or 0,
            }
            for row in timeline_rows
        ]

        endpoints = _analytics_grouped(conn, "endpoint", where, params)
        paths = _analytics_grouped(conn, "path", where, params)
        statuses = [
            {"status": r["status"], "count": r["requests"]}
            for r in conn.execute(
                "SELECT status, COUNT(*) AS requests FROM request_log WHERE " + where +
                " GROUP BY status ORDER BY requests DESC", params).fetchall()
        ]
        outcomes = _analytics_grouped(conn, "outcome", where, params)
        cache = _analytics_grouped(conn, "cache_status", where, params)
        browsers = _analytics_grouped(conn, "browser", where, params)
        os_list = _analytics_grouped(conn, "os", where, params)
        devices = _analytics_grouped(conn, "device", where, params)
        http_versions = _analytics_grouped(conn, "http_version", where, params)
        hosts = _analytics_grouped(conn, "host", where, params)
        colos = _analytics_grouped(conn, "colo", where, params)

        geo_rows = conn.execute(
            "SELECT country, country_code, COUNT(*) AS requests FROM request_log WHERE " + where +
            " GROUP BY country, country_code ORDER BY requests DESC LIMIT 25", params
        ).fetchall()
        geo = [
            {"country": r["country"], "country_code": r["country_code"], "requests": r["requests"]}
            for r in geo_rows
        ]

        city_rows = conn.execute(
            "SELECT city, country, country_code, COUNT(*) AS requests FROM request_log WHERE " + where +
            " GROUP BY city, country, country_code ORDER BY requests DESC LIMIT 25", params
        ).fetchall()
        cities = [
            {"city": r["city"], "country": r["country"], "country_code": r["country_code"], "requests": r["requests"]}
            for r in city_rows
        ]

        ua_rows = conn.execute(
            "SELECT user_agent, COUNT(*) AS requests FROM request_log WHERE " + where +
            " GROUP BY user_agent ORDER BY requests DESC LIMIT 25", params
        ).fetchall()
        user_agents = [
            {"user_agent": r["user_agent"] or "Unknown", "requests": r["requests"]}
            for r in ua_rows
        ]

        visitor_rows = conn.execute(
            "SELECT ip_hash, COUNT(*) AS requests FROM request_log WHERE " + where +
            " GROUP BY ip_hash ORDER BY requests DESC LIMIT 25", params
        ).fetchall()
        visitors = [
            {"label": analytics.pseudonym_label(r["ip_hash"]), "requests": r["requests"]}
            for r in visitor_rows
        ]

        return jsonify({
            "hours": hours,
            "scope": scope,
            "bucket": bucket,
            "tenant_id": tenant_id,
            "geoip_available": analytics.geoip_available(),
            "totals": {
                "requests": requests_total,
                "visitors": totals_row["visitors"] or 0,
                "bytes": totals_row["bytes"] or 0,
                "avg_duration_ms": round(totals_row["avg_duration_ms"] or 0, 2),
                "p95_duration_ms": round(p95 or 0, 2),
                "cache_hit_rate": round(cache_hits / requests_total, 4) if requests_total else 0.0,
                "error_rate": round(errors_total / requests_total, 4) if requests_total else 0.0,
                "success_rate": round((totals_row["successes"] or 0) / requests_total, 4) if requests_total else 0.0,
                "server_errors": totals_row["server_errors"] or 0,
            },
            "timeline": timeline,
            "endpoints": endpoints,
            "paths": paths,
            "statuses": statuses,
            "outcomes": outcomes,
            "cache": cache,
            "geo": geo,
            "cities": cities,
            "browsers": browsers,
            "os": os_list,
            "devices": devices,
            "http": http_versions,
            "hosts": hosts,
            "colos": colos,
            "user_agents": user_agents,
            "visitors": visitors,
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
    """Devuelve el secret TOTP pendiente o genera uno nuevo y lo guarda como pendiente hasta verificar."""
    ok, _, _ = _admin_authorized(readonly=False, skip_totp=True)
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    if _get_admin_totp_secret():
        return jsonify({"error": "2FA already configured"}), 400
    secret = _get_admin_pending_secret()
    if not secret:
        secret = pyotp.random_base32()
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO admin_2fa (id, secret, created_at, confirmed) VALUES (1, ?, ?, 0)",
                (secret, time.time())
            )
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
    pending = _get_admin_pending_secret()
    if pending and pending != secret:
        return jsonify({"error": "secret does not match pending setup; call setup again"}), 409
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        codes = _generate_recovery_codes('__admin__')
        with get_db() as conn:
            conn.execute(
                "INSERT INTO admin_2fa (id, secret, created_at, confirmed) VALUES (1, ?, ?, 1) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, created_at=excluded.created_at, confirmed=1",
                (secret, time.time())
            )
        remember = request.headers.get('X-Remember-Me', 'false').lower() == 'true'
        _refresh_admin_session('full', remember)
        return jsonify({"success": True, "valid": True, "recovery_codes": codes})
    if _consume_recovery_code('__admin__', code):
        remember = request.headers.get('X-Remember-Me', 'false').lower() == 'true'
        _refresh_admin_session('full', remember)
        return jsonify({"success": True, "valid": True, "recovery": True})
    return jsonify({"success": False, "valid": False}), 400


@app.route('/admin/access-log', methods=['GET'])
def admin_access_log():
    """Devuelve el log de accesos de administración para auditoría."""
    ok, _, setup_required = _admin_authorized(readonly=True)
    if not ok:
        if setup_required:
            return jsonify({"error": "Admin 2FA setup required", "setup_required": True}), 403
        return jsonify({"error": "Unauthorized"}), 401
    try:
        limit = int(request.args.get('limit', '100'))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 1000))
    with get_db() as conn:
        rows = conn.execute(
            "SELECT endpoint, token_type, ip, timestamp FROM admin_access_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        log_items = []
        for r in rows:
            item = dict(r)
            geo = analytics.geolocate(item["ip"])
            item["country"] = geo["country"]
            item["country_code"] = geo["country_code"]
            item["city"] = geo["city"]
            log_items.append(item)
    return jsonify({"success": True, "log": log_items})


@app.route('/menta-captcha.js')
def widget_js():
    return WIDGET_JS, 200, {'Content-Type': 'application/javascript'}

@app.route('/menta-shield.js')
def shield_js():
    return SHIELD_JS, 200, {'Content-Type': 'application/javascript'}

@app.route('/menta-challenge.js')
def challenge_js():
    with open(os.path.join(os.path.dirname(__file__), 'menta-challenge.js')) as f:
        return f.read(), 200, {'Content-Type': 'application/javascript'}

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
            console.warn('[Menta protection] This website is not registered or authorized by Menta.', { status, endpoint, origin, error: data.error });
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
        const ep = this.getAttribute('data-cap-api-endpoint') || '';
        const logoUrl = ep.replace(/\/*$/, '') + '/menta-logo.svg';
        this.shadowRoot.innerHTML = `
<style>
:host { display: inline-block; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.container { display:flex; align-items:center; width:300px; height:70px; background:#fff; border:1px solid #e0e0e0; border-radius:20px; padding:0 15px; position:relative; box-shadow:0 2px 4px rgba(0,0,0,0.05); cursor:pointer; user-select:none; }
.container:hover { border-color:#bdbdbd; }
.container:focus-visible { outline: 2px solid #333; outline-offset: 2px; }
.checkbox { width:24px; height:24px; border:2px solid #d1d1d1; border-radius:6px; margin-right:15px; display:flex; align-items:center; justify-content:center; }
.label { font-size:16px; color:#333; flex-grow:1; }
.brand { position:absolute; right:20px; bottom:12px; font-size:12px; color:#757575; text-decoration:underline; text-underline-offset:3px; }
.logo { position:absolute; right:20px; bottom:12px; width:24px; height:24px; }
.spinner { display:none; width:18px; height:18px; border:2px solid #f3f3f3; border-top:2px solid #333; border-radius:50%; animation:spin 1s linear infinite; }
@media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
@keyframes spin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }
.solved .checkbox { background:#f0f0f0; border-color:#22c45e; }
.solved .checkbox::after { content:'\u2713'; color:#22c45e; font-weight:bold; }
.mint-accent { fill: #22c45e; color: #22c45e; }
.message { display:none; margin-top:6px; font-size:11px; color:#757575; max-width:300px; line-height:1.4; }
.message.protected { color:#22c45e; }
</style>
<div class="container" id="box" role="button" tabindex="0" aria-label="${initialLabel}" aria-live="polite" aria-atomic="true" dir="${dir}">
  <div class="checkbox" id="check" aria-hidden="true"><div class="spinner" id="spin"></div></div>
  <span class="label" id="label">${initialLabel}</span>
  <span class="brand">Menta<span class="mint-accent">.</span></span>
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

SHIELD_JS = r"""(function () {
    'use strict';
    // Menta Shield: protección universal contra bots basada en bot_shield.
    // Uso: <script src="https://<host>/menta-shield.js" data-menta-api="https://<host>"></script>
    // No requiere <menta-widget> ni registro de dominio.
    var script = document.currentScript || (function () {
        var all = document.getElementsByTagName('script');
        return all[all.length - 1];
    })();

    function attr(name, fallback) {
        var v = script ? script.getAttribute(name) : null;
        return v !== null && v !== '' ? v : fallback;
    }

    var api = (attr('data-menta-api', '') || location.origin).replace(/\/+$/, '');
    var TOKEN_KEY = 'menta_shield_clearance';
    var TTL = parseInt(attr('data-menta-ttl', '86400'), 10) * 1000;
    var hideUntilPass = attr('data-menta-hide-until-pass', 'false') !== 'false';
    var blockMsg = attr('data-menta-i18n-blocked-title', 'Access denied');
    var blockDetail = attr('data-menta-i18n-blocked-detail', 'Your request looks automated and has been blocked.');
    var checkingMsg = attr('data-menta-i18n-checking', 'Checking your browser before you enter.');

    window.MentaShield = { passed: false, token: null };

    // --- Overlay / ocultado de contenido ---
    var css = document.createElement('style');
    css.textContent =
        'html.menta-shield-pending .menta-shield-hide{filter:blur(6px);pointer-events:none;user-select:none}' +
        '#menta-shield-overlay{position:fixed;inset:0;background:#fff;z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}' +
        '.ms-card{text-align:center;padding:2rem 2.5rem;border-radius:12px;border:1px solid #e0e0e0;background:#fff;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:320px}' +
        '.ms-spin{width:28px;height:28px;border:3px solid #f0f0f0;border-top-color:#22c45e;border-radius:50%;margin:0 auto 1rem;animation:ms-spin 1s linear infinite}' +
        '@keyframes ms-spin{to{transform:rotate(360deg)}}' +
        '@media (prefers-reduced-motion:reduce){.ms-spin{animation:none}}' +
        '.ms-title{font-size:15px;font-weight:600;color:#333;margin:0 0 .4rem}.ms-msg{font-size:12px;color:#757575;margin:0;line-height:1.5}';
    document.head.appendChild(css);

    if (hideUntilPass) document.documentElement.classList.add('menta-shield-pending');

    function showOverlay(title, msg, spinner) {
        var ov = document.getElementById('menta-shield-overlay') || document.createElement('div');
        ov.id = 'menta-shield-overlay';
        ov.innerHTML = '<div class="ms-card">' +
            (spinner ? '<div class="ms-spin"></div>' : '') +
            '<p class="ms-title"></p><p class="ms-msg"></p></div>';
        ov.querySelector('.ms-title').textContent = title;
        ov.querySelector('.ms-msg').textContent = msg;
        if (!ov.parentNode) document.body.appendChild(ov);
        return ov;
    }

    function removeOverlay() {
        var ov = document.getElementById('menta-shield-overlay');
        if (ov && ov.parentNode) ov.parentNode.removeChild(ov);
        document.documentElement.classList.remove('menta-shield-pending');
    }

    function pass(token) {
        window.MentaShield.passed = true;
        window.MentaShield.token = token || null;
        removeOverlay();
        document.dispatchEvent(new CustomEvent('mentashield:pass', { detail: { token: token } }));
    }

    function block() {
        showOverlay(blockMsg, blockDetail, false);
        document.dispatchEvent(new CustomEvent('mentashield:block'));
    }

    // --- PoW ---
    async function sha256(m) {
        const b = new TextEncoder().encode(m);
        const d = await crypto.subtle.digest('SHA-256', b);
        return Array.from(new Uint8Array(d)).map(x => x.toString(16).padStart(2, '0')).join('');
    }

    async function solvePoW(challenge) {
        let nonce = 0;
        while (true) {
            const h = await sha256(challenge.salt + nonce);
            if (h.startsWith(challenge.target)) return nonce;
            nonce++;
        }
    }

    // --- Flujo principal ---
    async function run() {
        var verdict;
        try {
            const r = await fetch(api + '/shield/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: location.pathname })
            });
            if (r.status === 403) { block(); return; }
            if (!r.ok) throw new Error('check failed');
            verdict = await r.json();
        } catch (e) {
            // Fail-open: si el shield no está disponible, no rompemos la página.
            pass(null);
            return;
        }

        if (verdict.action === 'shield' && verdict.challenge) {
            showOverlay(checkingMsg.replace('.', '...'), '', true);
            try {
                const nonce = await solvePoW(verdict.challenge);
                const v = await fetch(api + '/shield/redeem', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        token: verdict.token,
                        solutions: nonce,
                        challenge_signature: verdict.challenge.challenge_signature
                    })
                });
                const d = await v.json().catch(() => ({}));
                if (!v.ok || !d.success) { block(); return; }
                pass(d.clearance_token);
            } catch (e) {
                block();
            }
            return;
        }
        pass(null);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();"""


if __name__ == '__main__':
    app.run(debug=True, port=5000)
