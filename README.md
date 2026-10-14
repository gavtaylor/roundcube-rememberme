# rememberme

A [Roundcube](https://roundcube.net/) webmail plugin that adds a **"Keep me
logged in"** checkbox to the login page. It only gives longer sessions to the
browsers where someone ticks it, and everyone else keeps Roundcube's normal
inactivity timeout.

> **This project was built using agentic AI development** (Claude Code).
> Review it accordingly before you install it, especially since it handles
> login credentials.

## Status

Verified on one live instance (Roundcube 1.7.4, Elastic skin, MariaDB, behind
HTTPS):

- **Remembering:** ticking the box created a token. The password was stored
  encrypted, only the validator's hash was stored, and the expiry was 30 days.
  The table was created automatically on first use.
- **Session lifetime:** the remembered browser's session row had a 30-day
  expiry, while every other session, including the same user on another
  browser, kept the normal 10 minutes.
- **Automatic login:** with the remembered session deleted server-side, the
  next page load signed straight back in and landed on the page that was asked
  for.
- **Settings → Remembered devices:** signing out one device and signing out all
  other devices both worked, and the current device was kept. The page fits a
  phone, with Device, Last used and Sign out shown.
- **Forged cookie:** a correct selector with the wrong validator was rejected.
  Its token was deleted, the cookie was cleared (`Secure; HttpOnly`) and the
  login page was shown.
- **Login page:** the toggle is spaced like the inputs above it, and it stays
  ticked when the form comes back after a failed login.

Not yet exercised live: the `password_change` hook (no password plugin is
enabled on the test instance).



Roundcube's `session_lifetime` is one setting for everyone, and the default is
10 minutes of inactivity. Raising it lengthens every session on every computer,
shared ones included. The existing "persistent login" plugins either aren't
maintained (one was archived in 2026, the original's last commit was in 2023)
or store credentials in a way a database leak could expose.

## What it does

- **On the login page,** ticking *Keep me logged in* remembers that browser for
  `rememberme_days` (default 30).
- **A remembered browser's sessions** use that period as their inactivity
  timeout. Plugins load before Roundcube starts the session, so the longer
  lifetime applies to that browser only and the global setting is untouched.
- **If a remembered browser's session ends anyway** (expired, cleaned up,
  server restart), the next page load signs it straight back in from its cookie,
  through Roundcube's own login flow, and returns to the page that was
  requested.
- **Settings → Remembered devices** lists each remembered browser (browser and
  OS, when it was remembered, last used, expiry, IP), with *Sign out* per device
  and *Sign out all other devices*.
- **It ends when:**
  - you log out on that device, so logging out really logs out;
  - you revoke the device;
  - you change your password through the core `password` plugin, which forgets
    every device;
  - the stored password stops working, which forgets that device.

## Security

- The cookie holds a random **selector** (looked up in the database) and a
  random 256-bit **validator**. Only a SHA-256 hash of the validator is stored,
  compared in constant time. A cookie with the right selector but the wrong
  validator deletes that token.
- Roundcube needs the IMAP password for every session, so a remembered login
  has to keep it. It's encrypted with **AES-256-GCM**, using a key derived from
  the cookie's validator *and* the server's `des_key`. A copy of the database
  alone, or the server config alone, can't recover it; it also needs the cookie
  from the user's own device.
- The cookie is `HttpOnly`, uses Roundcube's own cookie path and SameSite
  settings, and is marked `Secure`. The checkbox is only offered, and cookies
  only honoured, over HTTPS.
- Automatic logins only happen on ordinary page loads (`GET`, not AJAX), and go
  through Roundcube's normal login code, including session ID regeneration and
  login logging.
- Revoke requests are covered by Roundcube's normal CSRF protection.
- Tokens per user are capped (`rememberme_max_devices`, default 10), expired
  tokens are purged, and nothing secret is logged.

## Installation

```bash
cd /path/to/roundcube
composer require gavtaylor/rememberme
```

Add `rememberme` to `$config['plugins']`. Optionally copy `config.inc.php.dist`
to `config.inc.php` in the plugin directory to change the defaults. The
database table is created automatically on first use (MySQL/MariaDB only, for
now). Make sure your Roundcube `des_key` is set to your own random value, not
the shipped default.

## Tests

```bash
php tests/crypto_test.php
```

This covers token generation and parsing, validator hashing, and password
encryption, including rejecting a wrong cookie, a wrong server key and tampered
data.

## License

[GPL-3.0-or-later](LICENSE).
