"""Helpers privacy-first para las analiticas de trafico del dashboard.

Reglas de diseno:
  * Las IPs crudas nunca se persisten. La identidad del visitante es un
    pseudonimo HMAC truncado, estable por sal pero no reversible.
  * La geolocalizacion se resuelve en memoria (MaxMind GeoLite2 City / Country) y
    solo se guardan los campos gruesos (pais, region, ciudad).
  * Todo degrada de forma segura si falta la dependencia opcional ``geoip2``
    o las bases de datos GeoLite2.
"""

import hashlib
import hmac
import ipaddress
import os
import random
import re

TRUTHY = ('1', 'true', 'yes', 'on')
UNKNOWN = 'Unknown'

# Nota: la configuracion se lee siempre en caliente (y no al importar el modulo)
# para que ``load_dotenv()`` pueda ejecutarse despues de la importacion.


def is_enabled():
    """Indica si la captura de analiticas esta habilitada."""
    return _truthy(os.environ.get('ANALYTICS_ENABLED', 'true'), True)


def sample_rate():
    """Probabilidad de muestreo por peticion (0.0 - 1.0)."""
    try:
        rate = float(os.environ.get('ANALYTICS_LOG_SAMPLE_RATE', '1.0'))
    except (TypeError, ValueError):
        return 1.0
    return min(1.0, max(0.0, rate))


def should_sample():
    """True si esta peticion debe registrarse segun el rate de muestreo."""
    rate = sample_rate()
    if rate >= 1.0:
        return True
    if rate <= 0.0:
        return False
    return random.random() < rate


# Expresiones regulares de deteccion.
_BOT_RE = re.compile(
    r'(bot\b|crawler|spider|crawling|slurp|scrapy|semrush|ahrefs|mj12|dotbot|'
    r'bingpreview|facebookexternalhit|uptimerobot|headless|phantomjs|puppeteer|'
    r'playwright|lighthouse|gtmetrix|pingdom|datadog|monitoring|checker)',
    re.I,
)
_CLIENT_RE = re.compile(
    r'(curl/|wget/|python-requests|python-urllib|go-http-client|java/|okhttp|'
    r'axios|node-fetch|guzzle|libwww|httpunit|postmanruntime|insomnia|'
    r'http_request|apache-httpclient|powershell|winhttp)',
    re.I,
)


def _truthy(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in TRUTHY


def get_salt():
    """Devuelve la sal usada para pseudonimizar IPs.

    Prioriza ``ANALYTICS_IP_SALT`` y, si no existe, deriva de ``SECRET_KEY``.
    La sal nunca se expone al cliente: sin ella el pseudonimo es irreversible.
    """
    salt = os.environ.get('ANALYTICS_IP_SALT', '').strip() or os.environ.get('SECRET_KEY', '').strip()
    if not salt:
        raise RuntimeError('No salt available: set ANALYTICS_IP_SALT or SECRET_KEY')
    return salt


def pseudonymize_ip(ip):
    """Devuelve el pseudonimo HMAC-SHA256 truncado de una IP (o '' si es desconocida)."""
    if not ip or ip == 'unknown':
        return ''
    digest = hmac.new(get_salt().encode('utf-8'), str(ip).encode('utf-8'), hashlib.sha256)
    return digest.hexdigest()[:32]


def pseudonym_label(ip_hash):
    """Etiqueta legible y no reversible para un pseudonimo (ej. ``anon-1a2b3c4d``)."""
    if not ip_hash:
        return 'anon-unknown'
    return 'anon-' + ip_hash[:12]


# --- GeoIP -----------------------------------------------------------------

_geoip_city_reader = None
_geoip_country_reader = None
_geoip_initialized = False
_city_db_path = ''
_country_db_path = ''


def _resolve_path(path):
    if not path:
        return ''
    path = path.strip()
    if not os.path.isabs(path):
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, path)
    return path if os.path.isfile(path) else ''


def _init_geoip_readers():
    """Inicializa perezosamente los lectores de GeoIP (City y Country)."""
    global _geoip_city_reader, _geoip_country_reader, _geoip_initialized, _city_db_path, _country_db_path
    if _geoip_initialized:
        return
    _geoip_initialized = True

    try:
        import geoip2.database  # type: ignore
    except ImportError:
        return

    base = os.path.dirname(os.path.abspath(__file__))

    # Candidatos para base de datos de ciudad
    city_candidates = [
        os.environ.get('GEOIP_CITY_DB_PATH', ''),
        os.environ.get('GEOIP_DB_PATH', ''),
        os.path.join(base, 'geoip', 'GeoLite2-City.mmdb'),
        os.path.join(base, 'GeoLite2-City.mmdb'),
    ]

    # Candidatos para base de datos de pais
    country_candidates = [
        os.environ.get('GEOIP_COUNTRY_DB_PATH', ''),
        os.path.join(base, 'geoip', 'GeoLite2-Country.mmdb'),
        os.path.join(base, 'GeoLite2-Country.mmdb'),
    ]

    resolved_city = ''
    for cand in city_candidates:
        r = _resolve_path(cand)
        if r:
            resolved_city = r
            break

    resolved_country = ''
    for cand in country_candidates:
        r = _resolve_path(cand)
        if r:
            resolved_country = r
            break

    # Intentar abrir la base de ciudad
    if resolved_city:
        try:
            reader = geoip2.database.Reader(resolved_city)
            db_type = getattr(reader.metadata(), 'database_type', '')
            if 'City' in db_type:
                _geoip_city_reader = reader
                _city_db_path = resolved_city
            elif 'Country' in db_type:
                _geoip_country_reader = reader
                _country_db_path = resolved_city
        except Exception:
            pass

    # Intentar abrir la base de pais si no se abrio antes
    if resolved_country and _geoip_country_reader is None:
        try:
            reader = geoip2.database.Reader(resolved_country)
            db_type = getattr(reader.metadata(), 'database_type', '')
            if 'Country' in db_type:
                _geoip_country_reader = reader
                _country_db_path = resolved_country
            elif 'City' in db_type and _geoip_city_reader is None:
                _geoip_city_reader = reader
                _city_db_path = resolved_country
        except Exception:
            pass


def geoip_db_path():
    """Ruta de la base de datos GeoLite2 (City o Country)."""
    _init_geoip_readers()
    return _city_db_path or _country_db_path or ''


def geoip_city_db_path():
    """Ruta de la base de datos GeoLite2 City."""
    _init_geoip_readers()
    return _city_db_path or ''


def geoip_country_db_path():
    """Ruta de la base de datos GeoLite2 Country."""
    _init_geoip_readers()
    return _country_db_path or ''


def geoip_available():
    """Indica si la resolucion GeoIP esta disponible en este proceso."""
    _init_geoip_readers()
    return _geoip_city_reader is not None or _geoip_country_reader is not None


def _get_geoip_reader():
    """Compatibilidad: devuelve el lector de ciudad o de pais."""
    _init_geoip_readers()
    return _geoip_city_reader or _geoip_country_reader


def geolocate(ip):
    """Resuelve la geografia aproximada de una IP en memoria.

    Devuelve un dict con ``country``, ``country_code``, ``region`` y ``city``.
    Detecta IPs de loopback y redes privadas (LAN/Localhost) para evitar
    mostrar "Unknown" en entornos locales.
    Usa la base de datos de ciudad (GeoLite2-City) y/o pais (GeoLite2-Country).
    """
    result = {
        'country': UNKNOWN,
        'country_code': UNKNOWN,
        'region': UNKNOWN,
        'city': UNKNOWN,
    }
    if not ip or ip == 'unknown':
        return result

    # Deteccion de IPs privadas, loopback o especiales (incluyendo prefijos /XX)
    try:
        ip_str = str(ip).strip()
        # Eliminar puerto (ej. "1.2.3.4:8080")
        if ':' in ip_str and not ip_str.startswith('[') and ip_str.count(':') == 1:
            ip_str = ip_str.split(':')[0]
        # Eliminar prefijo CIDR (ej. "127.0.0.0/24") -> usar la IP de red para clasificar
        if '/' in ip_str:
            ip_str = ip_str.split('/')[0]
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            return {
                'country': 'Localhost',
                'country_code': 'LOCAL',
                'region': 'Loopback',
                'city': 'Localhost',
            }
        if ip_obj.is_private:
            return {
                'country': 'Private Network',
                'country_code': 'LAN',
                'region': 'Private Network',
                'city': 'LAN',
            }
        # Para la consulta GeoIP usar la IP sin prefijo
        ip = ip_str
    except ValueError:
        pass

    _init_geoip_readers()

    # 1. Intentar con la base de datos de ciudad (contiene pais, region y ciudad)
    if _geoip_city_reader is not None:
        try:
            response = _geoip_city_reader.city(str(ip))
            if response.country:
                result['country'] = response.country.name or UNKNOWN
                result['country_code'] = response.country.iso_code or UNKNOWN
            if response.subdivisions:
                subdivision = response.subdivisions.most_specific
                if subdivision and subdivision.name:
                    result['region'] = subdivision.name
            if response.city and response.city.name:
                result['city'] = response.city.name
        except Exception:
            pass

    # 2. Si el pais sigue desconocido, probar con la base de pais
    if result['country'] == UNKNOWN and _geoip_country_reader is not None:
        try:
            response = _geoip_country_reader.country(str(ip))
            if response.country:
                result['country'] = response.country.name or UNKNOWN
                result['country_code'] = response.country.iso_code or UNKNOWN
        except Exception:
            pass

    return result


# --- User agent ------------------------------------------------------------

def parse_user_agent(user_agent):
    """Clasifica el user agent en ``(browser, os, device)`` sin dependencias externas."""
    ua = user_agent or ''

    if _BOT_RE.search(ua):
        browser = 'Bot'
    elif _CLIENT_RE.search(ua):
        browser = 'HTTP Client'
    elif re.search(r'Edg(?:e|A|iOS)?/', ua) or 'Edge/' in ua:
        browser = 'Edge'
    elif 'OPR/' in ua or 'Opera' in ua:
        browser = 'Opera'
    elif 'SamsungBrowser' in ua:
        browser = 'Samsung Internet'
    elif 'CriOS/' in ua:
        browser = 'Chrome'
    elif 'Chrome/' in ua or 'Chromium/' in ua:
        browser = 'Chrome'
    elif 'FxiOS/' in ua:
        browser = 'Firefox'
    elif 'Firefox/' in ua:
        browser = 'Firefox'
    elif 'Safari/' in ua and 'Version/' in ua:
        browser = 'Safari'
    elif 'Trident/' in ua or 'MSIE' in ua:
        browser = 'Internet Explorer'
    else:
        browser = 'Other'

    if 'Windows' in ua:
        os_name = 'Windows'
    elif 'Android' in ua:
        os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua or 'iPod' in ua:
        os_name = 'iOS'
    elif 'CrOS' in ua:
        os_name = 'Chrome OS'
    elif 'Mac OS X' in ua or 'Macintosh' in ua:
        os_name = 'macOS'
    elif 'Ubuntu' in ua:
        os_name = 'Ubuntu'
    elif 'Linux' in ua or 'X11' in ua:
        os_name = 'Linux'
    else:
        os_name = UNKNOWN

    if browser == 'Bot':
        device = 'Bot'
    elif 'iPad' in ua or 'Tablet' in ua:
        device = 'Tablet'
    elif 'Android' in ua and 'Mobile' not in ua:
        device = 'Tablet'
    elif 'Mobi' in ua or 'iPhone' in ua or 'iPod' in ua:
        device = 'Mobile'
    else:
        device = 'Desktop'

    return browser, os_name, device


def http_version(request):
    """Deduce la version HTTP de la peticion (ej. ``HTTP/1.1``, ``HTTP/2``)."""
    header = request.headers.get('HTTP_VERSION', '').strip()
    if header:
        if header.isdigit():
            return 'HTTP/' + header
        if header.upper().startswith('HTTP/'):
            return header.upper()
    protocol = request.environ.get('SERVER_PROTOCOL', '') or ''
    if protocol:
        return protocol
    return UNKNOWN


# --- Cabeceras y resultado -------------------------------------------------

def cache_status(response, request=None):
    """Clasifica el estado de cache de la respuesta (HIT/MISS/BYPASS/DYNAMIC...).

    Primero mira las cabeceras de la respuesta (Cloudflare, Varnish, etc.) y
    despues las de la peticion, por si el CDN las reenvia.
    """
    headers = response.headers

    cf_status = headers.get('CF-Cache-Status')
    if not cf_status and request is not None:
        cf_status = request.headers.get('CF-Cache-Status')
    if cf_status:
        return cf_status.strip().upper()[:20]

    x_cache = headers.get('X-Cache', '').strip().upper()
    if not x_cache and request is not None:
        x_cache = (request.headers.get('X-Cache') or '').strip().upper()
    if x_cache:
        for token in ('HIT', 'MISS', 'BYPASS', 'EXPIRED', 'STALE', 'UPDATING', 'REVALIDATED'):
            if token in x_cache:
                return token
        return x_cache[:20]

    age = headers.get('Age')
    if not age and request is not None:
        age = request.headers.get('Age')
    if age:
        try:
            if float(age) > 0:
                return 'HIT'
        except (TypeError, ValueError):
            pass

    cache_control = (headers.get('Cache-Control') or '').lower()
    if not cache_control and request is not None:
        cache_control = (request.headers.get('Cache-Control') or '').lower()
    if 'no-store' in cache_control or 'no-cache' in cache_control:
        return 'BYPASS'
    if 'public' in cache_control or 'max-age=' in cache_control:
        return 'MISS'

    return 'DYNAMIC'


def colo(response=None, request=None):
    """Devuelve el datacenter/colo del CDN cuando el proveedor lo expone.

    Cloudflare expone CF-Colo y CF-Ray como response headers (el sufijo de
    CF-Ray tras '-' es el codigo del colo), por eso se leen de la respuesta.
    """
    sources = []
    if response is not None:
        sources.append(response.headers)
    if request is not None:
        sources.append(request.headers)
    for source in sources:
        for header in ('CF-Colo', 'X-Colo', 'X-Data-Center', 'X-Served-By'):
            value = source.get(header)
            if value:
                return value.strip()[:64]
        value = source.get('CF-Ray')
        if value and '-' in value:
            return value.rsplit('-', 1)[-1].strip()[:64]
    return UNKNOWN


def referer_host(request):
    """Devuelve solo el host del referer (sin ruta ni query)."""
    referer = request.headers.get('Referer', '').strip()
    if not referer:
        return ''
    try:
        from urllib.parse import urlparse
        parsed = urlparse(referer)
        return parsed.netloc[:128]
    except Exception:
        return ''


def classify_outcome(status_code, response=None):
    """Clasifica el resultado de la peticion para las metricas de exito/error."""
    if status_code == 429:
        return 'rate_limited'
    if status_code == 403:
        return 'blocked'
    if status_code >= 500:
        return 'server_error'
    if status_code >= 400:
        return 'client_error'

    payload = None
    if response is not None:
        try:
            payload = response.get_json(silent=True)
        except Exception:
            payload = None
    if isinstance(payload, dict) and payload.get('success') is False:
        error = str(payload.get('error', '')).lower()
        if 'rate' in error or 'too many' in error:
            return 'rate_limited'
        return 'rejected'
    return 'success'


def normalize_path(path):
    """Elimina query strings y parametros de ruta de una URL de endpoint."""
    if not path:
        return ''
    path = path.split('?', 1)[0]
    if len(path) > 1 and path.endswith('/'):
        path = path.rstrip('/')
    return path[:256]
