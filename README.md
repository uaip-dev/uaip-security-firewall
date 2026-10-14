# UAIP Security Firewall

A WordPress security plugin: web application firewall, malware scanner with one-click repair,
passkeys and two-step sign-in, hardening with Site Health checks, an activity log and email
alerts. Everything runs on the site itself; the only optional outside service is the
vulnerability check at UAIP Security Cloud, which is off until an administrator turns it on.

Maintained by [UAIP](https://uaip.dev/) (WordPress.org: `uaip`).

## Repository layout

| Folder | What |
|---|---|
| `plugin/` | The WordPress plugin (plain PHP, no build step). |
| `dev/` | Docker setup for a local WordPress test site. |
| `tests/` | Standalone PHP tests: firewall regression set, YARA-lite, passkeys/TOTP, signed rule feed. |
| `scripts/` | Packaging (`make-zip.mjs`). |

## Local WordPress

```sh
cd dev
docker compose up -d
sh setup.sh       # installs WordPress, activates the plugin and Plugin Check
```

The site runs at http://localhost:8097 (user `admin`, password in `dev/.data/admin-password.txt`).
It talks to a local UAIP Security Cloud on port 8082 if one is running; it never talks to
production.

## Tests

```sh
for t in tests/*.php; do docker run --rm -v "$PWD:/app" -w /app php:7.4-cli php "$t"; done
```

They need no WordPress (a few functions are stubbed) and pass on PHP 7.4 and 8.x.

## Packaging

```sh
npm run zip       # dist/uaip-security-firewall.zip
```

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
