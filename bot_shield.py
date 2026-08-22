import ipaddress
import json
import os
import socket
import re
import time
import urllib.request
import urllib.error
from urllib.robotparser import RobotFileParser

KNOWN_BOTS = [
    # --- OpenAI ---
    {"name": "GPTBot", "vendor": "OpenAI", "category": "training",
     "ua_regex": r"GPTBot", "verify": "iprange",
     "ip_ranges_url": "https://openai.com/gptbot.json"},
    {"name": "OAI-SearchBot", "vendor": "OpenAI", "category": "search",
     "ua_regex": r"OAI-SearchBot", "verify": "iprange",
     "ip_ranges_url": "https://openai.com/searchbot.json"},
    {"name": "ChatGPT-User", "vendor": "OpenAI", "category": "user_triggered",
     "ua_regex": r"ChatGPT-User", "verify": "iprange",
     "ip_ranges_url": "https://openai.com/chatgpt-user.json"},

    # --- Anthropic ---
    # Anthropic ha cambiado su política de publicación de rangos IP más de una
    # vez; por robustez verificamos por reverse-DNS en vez de fijar una URL
    # JSON que puede quedar obsoleta. Revisa periódicamente
    # https://support.claude.com/en/articles/8896518 por si publican un feed.
    {"name": "ClaudeBot", "vendor": "Anthropic", "category": "training",
     "ua_regex": r"ClaudeBot", "verify": "rdns", "rdns_suffix": "anthropic.com"},
    {"name": "Claude-SearchBot", "vendor": "Anthropic", "category": "search",
     "ua_regex": r"Claude-SearchBot", "verify": "rdns", "rdns_suffix": "anthropic.com"},
    {"name": "Claude-User", "vendor": "Anthropic", "category": "user_triggered",
     "ua_regex": r"Claude-User", "verify": "rdns", "rdns_suffix": "anthropic.com"},

    # --- Google ---
    {"name": "Google-Extended", "vendor": "Google", "category": "training",
     "ua_regex": r"Google-Extended", "verify": "rdns", "rdns_suffix": "googlebot.com"},

    # --- Perplexity ---
    {"name": "PerplexityBot", "vendor": "Perplexity", "category": "search",
     "ua_regex": r"PerplexityBot", "verify": None},
    {"name": "Perplexity-User", "vendor": "Perplexity", "category": "user_triggered",
     "ua_regex": r"Perplexity-User", "verify": None},

    # --- Apple ---
    {"name": "Applebot-Extended", "vendor": "Apple", "category": "training",
     "ua_regex": r"Applebot-Extended", "verify": "rdns", "rdns_suffix": "applebot.apple.com"},

    # --- Meta ---
    {"name": "meta-externalagent", "vendor": "Meta", "category": "training",
     "ua_regex": r"meta-externalagent", "verify": None},

    # --- Amazon ---
    {"name": "Amazonbot", "vendor": "Amazon", "category": "training", "ua_regex": r"Amazonbot", "verify": None},

    # --- Common Crawl (alimenta a casi todos los modelos open-source) ---
    {"name": "CCBot", "vendor": "Common Crawl", "category": "training",
     "ua_regex": r"CCBot", "verify": "rdns", "rdns_suffix": "commoncrawl.org"},

    # --- ByteDance: historial documentado de no respetar robots.txt ---
    {"name": "Bytespider", "vendor": "ByteDance", "category": "training",
     "ua_regex": r"Bytespider", "verify": None},

    # --- Mistral ---
    {"name": "MistralAI-User", "vendor": "Mistral", "category": "user_triggered",
     "ua_regex": r"MistralAI-User", "verify": None},

    # --- SEO / marketing crawlers agresivos (no son IA, pero scrapean igual) ---
    {"name": "AhrefsBot", "vendor": "Ahrefs", "category": "seo", "ua_regex": r"AhrefsBot", "verify": None},
    {"name": "SemrushBot", "vendor": "Semrush", "category": "seo", "ua_regex": r"SemrushBot", "verify": None},
    {"name": "MJ12bot", "vendor": "Majestic", "category": "seo", "ua_regex": r"MJ12bot", "verify": None},
    {"name": "DotBot", "vendor": "Moz", "category": "seo", "ua_regex": r"DotBot", "verify": None},
]

GENERIC_SCRIPT_PATTERNS = [
    r"python-requests", r"python-urllib", r"aiohttp", r"okhttp", r"Go-http-client",
    r"curl/", r"Wget/", r"libwww-perl", r"axios/", r"node-fetch", r"Java/\d",
    r"^Scrapy", r"HeadlessChrome", r"PhantomJS", r"Puppeteer", r"Playwright",
    r"^$",
]

_BOT_REGEXES = [(b, re.compile(b["ua_regex"], re.I)) for b in KNOWN_BOTS]
_SCRIPT_REGEXES = [re.compile(p, re.I) for p in GENERIC_SCRIPT_PATTERNS]


def classify_ua(user_agent):
    """Devuelve el dict del bot conocido que matchea, o None."""
    ua = user_agent or ""
    for bot, rx in _BOT_REGEXES:
        if rx.search(ua):
            return bot
    return None


def looks_like_generic_script(user_agent):
    ua = user_agent or ""
    return any(rx.search(ua) for rx in _SCRIPT_REGEXES)


_ip_range_cache = {}
_IP_RANGE_TTL = 6 * 3600


def _fetch_ip_ranges(url):
    now = time.time()
    cached = _ip_range_cache.get(url)
    if cached and now - cached[1] < _IP_RANGE_TTL:
        return cached[0]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Menta-BotShield/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode("utf-8"))
        raw = data.get("prefixes") or data.get("ipv4CidrRanges") or data.get("ranges") or data
        cidrs = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    cidrs.append(item)
                elif isinstance(item, dict):
                    cidrs.append(item.get("ipv4Prefix") or item.get("ipv6Prefix") or item.get("cidr") or item.get("prefix"))
        networks = []
        for c in cidrs:
            if not c:
                continue
            try:
                networks.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                continue
        _ip_range_cache[url] = (networks, now)
        return networks
    except Exception:
        return cached[0] if cached else []


def _ip_in_ranges(ip, url):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _fetch_ip_ranges(url):
        if addr in net:
            return True
    return False


def _rdns_confirms(ip, expected_suffix):
    """Forward-confirmed reverse DNS: PTR(ip) debe terminar en expected_suffix,
    y el forward lookup de ese hostname debe volver a resolver a la misma IP."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return False
    if not host.lower().endswith(expected_suffix.lower()):
        return False
    try:
        resolved = socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return False
    return resolved == ip


def verify_bot_ip(bot, ip):
    """True = verificado, False = falló la verificación, None = no verificable."""
    if not bot or not ip or ip == "unknown":
        return None
    method = bot.get("verify")
    if method == "iprange":
        return _ip_in_ranges(ip, bot["ip_ranges_url"])
    if method == "rdns":
        return _rdns_confirms(ip, bot["rdns_suffix"])
    return None


class RobotsPolicy:
    """Envuelve robots.txt (y, de forma best-effort, llms.txt) para responder
    '¿puede este User-Agent pedir esta ruta?' usando el parser estándar."""

    def __init__(self, robots_path=None, llms_path=None, base_url=""):
        self.parser = RobotFileParser()
        self._loaded = False
        self._robots_path = robots_path
        self._llms_disallow = []
        self.base_url = base_url.rstrip("/")
        self.reload()

    def reload(self):
        try:
            if self._robots_path and os.path.exists(self._robots_path):
                with open(self._robots_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.parser.parse(content.splitlines())
                self._loaded = True
        except Exception:
            self._loaded = False

    def can_fetch(self, ua_name, path):
        """Si no hay robots.txt cargado, permitimos por defecto (fail-open para
        no romper el sitio si falta el fichero)."""
        if not self._loaded:
            return True
        try:
            return self.parser.can_fetch(ua_name, path)
        except Exception:
            return True


_policy = None


def get_policy():
    global _policy
    if _policy is None:
        _policy = RobotsPolicy(
            robots_path=os.environ.get("ROBOTS_TXT_PATH"),
            llms_path=os.environ.get("LLMS_TXT_PATH"),
            base_url=os.environ.get("SITE_BASE_URL", ""),
        )
    return _policy



def evaluate_request(user_agent, ip, path):
    bot = classify_ua(user_agent)
    policy = get_policy()

    if bot:
        allowed_by_robots = policy.can_fetch(bot["name"], path)
        verified = verify_bot_ip(bot, ip)

        if allowed_by_robots:
            return {"action": "allow", "reason": "known_bot_compliant", "bot": bot["name"],
                    "verified": verified, "difficulty_hint": None}

        if verified is True:
            return {"action": "block", "reason": "disobeys_robots_verified", "bot": bot["name"],
                    "verified": True, "difficulty_hint": None}
        else:
            return {"action": "shield", "reason": "impersonator_or_unverifiable", "bot": bot["name"],
                    "verified": verified, "difficulty_hint": "max"}

    if looks_like_generic_script(user_agent):
        return {"action": "shield", "reason": "generic_script_ua", "bot": None,
                "verified": None, "difficulty_hint": "max"}

    return {"action": "shield", "reason": "unverified_client", "bot": None,
            "verified": None, "difficulty_hint": None}
