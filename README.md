# Menta CAPTCHA 🍃

**Free, self-hosted, privacy-first CAPTCHA for the modern web.**  
No Google telemetry. No tracking cookies. No endless image puzzles.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://www.python.org/)

---

### Quick Start

Add Menta to your HTML in two lines:

```html
<script src="https://mentacaptchaeu.eu.pythonanywhere.com/menta-captcha.js"></script>
<menta-widget data-cap-api-endpoint="https://mentacaptchaeu.eu.pythonanywhere.com/docs"></menta-widget>

```

The Web Component automatically initializes and manages the challenge flow in the client browser.

---

### Widget Configuration

Customize theme, layout, typography, accents, and internationalization via standard `data-cap-*` HTML attributes.

#### Theme & Dimensions

```html
<menta-widget
  data-cap-api-endpoint="https://mentacaptchaeu.eu.pythonanywhere.com/"
  data-cap-theme="dark"
  data-cap-width="340px"
  data-cap-height="64px"
  data-cap-border-radius="12px">
</menta-widget>

```

| Attribute | Description | Default |
| --- | --- | --- |
| `data-cap-theme` | Color theme (`light`, `dark`, `auto`) | `light` |
| `data-cap-width` | Widget width | `300px` |
| `data-cap-height` | Widget height | `70px` |
| `data-cap-padding` | Inner padding | `0 15px` |
| `data-cap-background` | Background color | `#fff` / `#212121` |
| `data-cap-border-color` | Border color | `#e0e0e0` / `#424242` |
| `data-cap-border-radius` | Corner radius | `20px` |
| `data-cap-box-shadow` | Box shadow | `0 2px 4px rgba(0,0,0,0.05)` |

#### Typography & Colors

| Attribute | Description | Default |
| --- | --- | --- |
| `data-cap-font-family` | Font stack | System sans-serif |
| `data-cap-font-size` | Label font size | `16px` |
| `data-cap-font-weight` | Label font weight | `400` |
| `data-cap-text-color` | Label text color | `#333` / `#e6e6e6` |
| `data-cap-primary-color` | Brand accent color | `#22C45E` |
| `data-cap-checkmark-color` | Checkmark color | Same as primary |
| `data-cap-spinner-color` | Spinner loader color | `#757575` |
| `data-cap-brand-color` | Brand link color | `#757575` |

#### Internationalization (i18n)

| Attribute | Description | Default Text |
| --- | --- | --- |
| `data-cap-i18n-initial-state` | Initial state label | `"I'm not a robot"` |
| `data-cap-i18n-loading` | Loading state | `"Loading..."` |
| `data-cap-i18n-verifying` | Verification state | `"Verifying..."` |
| `data-cap-i18n-success` | Success state | `"Verified"` |
| `data-cap-i18n-error` | Error state | `"Error. Try again."` |

---

### Fully Customized HTML Example

```html
<menta-widget
  data-cap-api-endpoint="https://mentacaptchaeu.eu.pythonanywhere.com/"
  data-cap-i18n-initial-state="I'm not a robot"
  data-cap-theme="dark"
  data-cap-width="340px"
  data-cap-height="64px"
  data-cap-border-radius="12px"
  data-cap-border-color="#22C45E"
  data-cap-primary-color="#22C45E"
  data-cap-background="#121212"
  data-cap-text-color="#f0f0f0"
  data-cap-font-family="'Inter', sans-serif"
  data-cap-font-size="15px"
  data-cap-checkbox-size="26px"
  data-cap-box-shadow="0 4px 12px rgba(0,0,0,0.5)"
  data-cap-css=".container { transition: all .2s ease; }">
</menta-widget>

```

---

### API Endpoints

Menta exposes several endpoints for CAPTCHA flow and verification:

#### Challenge Flow (Widget mode)
- **POST /init** — Initialize session, returns signed session_id and session_signature
- **POST /challenge** — Get a PoW challenge (requires valid session)
- **POST /redeem** — Submit nonce solution, returns JWT token
- **POST /verify** — Backend verification of JWT token

#### Universal Protection (Shield mode)
- **POST /shield/check** — Evaluate request (returns allow/block/shield action)
- **POST /shield/redeem** — Verify PoW and issue clearance token
- **POST /shield/verify** — Server-to-server token validation

#### Interstitial Page
- **GET /verify** or **GET /challenge-page** — Manual PoW challenge page that redirects after completion

### Backend Token Verification

Verify submitted CAPTCHA tokens directly against your self-hosted backend API:

#### HTTP API Call

```http
POST /verify HTTP/1.1
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}

```

**Response:**

```json
{
  "valid": true,
  "tenant_id": "your-tenant"
}

```

---

### Traffic Analytics & Privacy

The self-hosted backend can record aggregate traffic analytics for the dashboard without storing raw IP addresses.

* Raw client IPs are used only in memory to derive a truncated HMAC-SHA-256 (`ip_hash`). The IP and its prefix are never persisted.
* Visitors are displayed as anonymous labels (`anon-<hash prefix>`), never as addresses.
* Referrers are reduced to origin/host, dropping query strings that may contain sensitive data.
* GeoIP lookups are optional and only resolve a country from the in-memory IP.

Configure it with environment variables in your `.env`:

| Variable | Description | Default |
| --- | --- | --- |
| `ANALYTICS_ENABLED` | Enable request logging for analytics | `true` |
| `ANALYTICS_IP_SALT` | Secret used to HMAC client IPs (falls back to `SECRET_KEY`) | `SECRET_KEY` |
| `ANALYTICS_RETENTION_HOURS` | How long analytics rows are kept | `DATA_RETENTION_HOURS` (`24`) |
| `ANALYTICS_LOG_SAMPLE_RATE` | Fraction of requests logged (`0.0`–`1.0`) | `1.0` |
| `GEOIP_DB_PATH` | Path to a MaxMind `GeoLite2-City.mmdb` file | unset (`Unknown`) |
| `TRUSTED_PROXIES` | Comma-separated proxy IPs/CIDRs allowed to set client headers | unset |
| `CORS_ORIGINS` | Comma-separated list of allowed origins for widget requests | empty (permissive) |
| `LOG_IP_FULL` | Store full IPs instead of anonymized /24 (IPv4) or /64 (IPv6) prefixes | `false` |

**Privacy & IP Anonymization:**
- By default, only IP network prefixes are logged (`/24` for IPv4, `/64` for IPv6) to minimize personal data
- All client IPs are pseudonymized using HMAC-SHA-256 in analytics; raw IPs are never persisted
- Set `LOG_IP_FULL=true` only if you need full IP addresses for debugging (not recommended in production)

GeoIP support requires the optional `geoip2` package (included in `requirements.txt`) and a local MaxMind database. Without either, the dashboard reports `Unknown` for geography; every other metric still works.

Analytics views are available in the admin dashboard (`/admin/analytics`) and require an authenticated admin session with 2FA enabled. Results are always scoped to the requesting tenant.

---

### Key Features

* **100% Privacy-First:** Zero external requests, zero third-party tracking, fully GDPR compliant out of the box. IP anonymization by default.
* **No Visual Puzzles:** Protects forms without frustrating your human users with traffic lights and crosswalks.
* **Lightweight & Fast:** Sub-millisecond validation time with zero database setup required. Proof-of-work challenges solved in 1-3 seconds client-side.
* **Self-Hosted:** Own your bot defense end-to-end. No per-request bills, no quotas, no vendor lock-in.
* **Bot Detection:** Detects and blocks known AI crawlers (OpenAI, Anthropic, Perplexity, etc.) using IP verification and reverse-DNS confirmation.
* **Rate Limiting:** Per-IP, per-tenant, and global rate limits prevent automated attacks.
* **Single-Use Tokens:** JWT tokens with consumed jti (unique identifier) prevent replay attacks.
* **Apache 2.0 Licensed:** Free for commercial and open-source projects without AGPL constraints.
