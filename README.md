# Menta CAPTCHA 🍃

> **Free, self-hosted, privacy-first CAPTCHA for the modern web.**  
> No Google telemetry. No tracking cookies. No endless image puzzles.

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

### ⚙️ Widget Configuration

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
| `data-cap-primary-color` | Brand accent color | `#22C55E` |
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

### 🎨 Fully Customized HTML Example

```html
<menta-widget
  data-cap-api-endpoint="https://mentacaptchaeu.eu.pythonanywhere.com/"
  data-cap-i18n-initial-state="I'm not a robot"
  data-cap-theme="dark"
  data-cap-width="340px"
  data-cap-height="64px"
  data-cap-border-radius="12px"
  data-cap-border-color="#22C55E"
  data-cap-primary-color="#22C55E"
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

### 🖥️ Backend Token Verification

Verify submitted CAPTCHA tokens directly against your self-hosted backend API or via Python:

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

#### Python Integration

```python
from mentacaptcha import MentaCaptcha

captcha = MentaCaptcha()

# Verify token from frontend request
is_valid = captcha.verify(challenge_id, user_response)

```

---

### Key Features

* **100% Privacy-First:** Zero external requests, zero third-party tracking, fully GDPR compliant out of the box.
* **No Visual Puzzles:** Protects forms without frustrating your human users with traffic lights and crosswalks.
* **Lightweight & Fast:** Sub-millisecond validation time with zero database setup required.
* **Apache 2.0 Licensed:** Free for commercial and open-source projects without AGPL constraints.
