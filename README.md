# Menta CAPTCHA

Menta CAPTCHA is not trying to compete with reCAPTCHA, hCaptcha, or similar solutions. It is an alternative built for developers who value their users' privacy and want to protect them as much as possible.

## Who is it for

For those who do not trust large corporations to process their users' data. For those who prefer a self-hostable, lightweight, private, anonymous, and bot-safe solution.

## What it offers

- Server-verified proof of work.
- No images, fingerprints, or telemetry.
- No cookies, no localStorage, no third-party dependencies.
- IP anonymization by default.
- At-rest encryption with SQLCipher.
- Data subject rights: export and deletion by IP.
- Accessible widget with keyboard and screen reader support.

## Installation

1. Clone the repository.
2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Create a `.env` file with the required variables.
4. Run:
   ```bash
   python app.py
   ```

The development server will start at `http://localhost:5000`.

> **Note:** `app.run(port=5000)` is for development only. In production use Gunicorn, uWSGI, or another WSGI server with TLS.

## Environment variables

| Variable | Description |
| --- | --- |
| `SECRET_KEY` | Key for signing sessions and tokens. |
| `ADMIN_TOKEN` | Bearer token for accessing the admin dashboard. |
| `DB_ENCRYPTION_KEY` | SQLCipher key for encrypting the database at rest. |
| `DATA_RETENTION_HOURS` | Data retention time in hours. |
| `LOG_IP_FULL` | If `true`, stores the full IP. Defaults to prefix only. |

## Basic usage

1. Register an account at `/account`.
2. Add the domains where you will use the widget.
3. Copy the widget snippet into your site.
4. Verify the token sent from the server.
