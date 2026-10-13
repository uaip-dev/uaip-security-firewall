# UAIP Security Firewall

A WordPress security plugin: web application firewall, malware scanner, login protection,
two-factor authentication, hardening and an activity log. It works on its own; the optional
UAIP Security Cloud adds vulnerability alerts and fleet monitoring.

Maintained by [UAIP](https://uaip.dev/) (WordPress.org: `uaip`).

> Status: being rebuilt from an earlier prototype. See the plan for what changes before the
> first WordPress.org release.

## Repository layout

| Folder | What |
|---|---|
| `plugin/` | The WordPress plugin (plain PHP, no build step). |
| `dev/` | Docker setup for a local WordPress test site. |
| `tests/` | Tests (WAF regression set, engine tests). |
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

## Packaging

```sh
npm run zip       # dist/uaip-security-firewall.zip
```

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
