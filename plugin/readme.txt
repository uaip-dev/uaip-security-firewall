=== UAIP Security Firewall ===
Contributors: uaip
Tags: security, firewall, malware scanner, two-factor, passkeys
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, malware scanner with one-click repair, passkeys and two-step sign-in, activity log and hardening. Runs on your site; no account needed.

== Description ==

UAIP Security Firewall protects a WordPress site from the attacks that actually happen: bots guessing passwords, requests probing for SQL injection and file uploads, and malware hidden in plugin files. Everything runs on your own server. There is no account to create and nothing is locked.

= Firewall =

* Checks every request (including admin-ajax, admin-post and REST API calls from visitors) against rules for SQL injection, cross-site scripting, remote code execution, file inclusion and path traversal.
* Scores each request and blocks it once the score passes a threshold you choose, so one odd-looking word does not block a real visitor.
* Learning mode: log what would be blocked before switching blocking on.
* Exceptions per rule and per path, allow and block lists for IP addresses and ranges.
* Rate limiting for bots that hammer the site.
* Finds the real visitor IP behind Cloudflare or a trusted proxy, so one CDN address never stands in for everyone.

= Malware scanner =

* Compares WordPress core files and plugins from WordPress.org with their official checksums, and finds files that should not be there.
* Scans themes, uploads, drop-ins and the site root for web shells and backdoors with YARA-style rules (pure PHP, works on shared hosting).
* Repairs modified core and plugin files with one click, using the original file from WordPress.org after checking its checksum. Delete or ignore any finding.
* Runs in small resumable steps in the background, so large sites do not time out.

= Sign-in protection =

* Passkeys (fingerprint, face, device PIN or security key), authenticator apps and email codes as a second step after the password, plus one-time recovery codes.
* Require two-step verification for chosen roles, for example administrators and editors.
* Limits password guessing with a check question and then a lockout per IP address.
* Refuses very common passwords for privileged accounts (checked against a list bundled with the plugin).
* Blocks XML-RPC and application passwords for accounts that use two-step verification, because those cannot show a second step.

= Hardening =

* Stops scripts running in the uploads folder (.php, .phtml, .phar and similar, including names like shell.php.jpg) and tests that the rule works.
* Turns off the plugin and theme file editor.
* Sends security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) and optional HSTS.
* Hides usernames from visitors: author scans, the public REST users list, the users sitemap, oEmbed author data, and different errors for a wrong username or password.
* Ten security checks in Tools → Site Health, with a score and a fix link for each.

= Activity log =

* Sign-ins, failed sign-ins, user and role changes, password and email changes, application passwords, plugin and theme installs, updates and deletions, WordPress updates, setting changes, firewall blocks and scan results.
* Filter by category, event, user, IP address, date and text; export to CSV; choose how long to keep entries.

= Alerts =

* Email when an administrator signs in, when a scan finds malware, and when the firewall sees a burst of attacks.
* Optional weekly summary email.
* Optional vulnerability alerts: a daily check of your WordPress, plugin and theme versions against known vulnerabilities. This is the only feature that uses an outside service run by us, and it is off until you turn it on (see External Services).

== External Services ==

This plugin connects to the following services. Nothing is sent to UAIP Security Cloud unless an administrator turns on vulnerability alerts.

= WordPress.org =

Used by the malware scanner to verify files and repair them.

* When a scan runs, the plugin downloads the official checksums for your WordPress version (through WordPress's own `get_core_checksums()`, from api.wordpress.org) and for each installed plugin from WordPress.org (https://downloads.wordpress.org/plugin-checksums/). The request contains the WordPress version, or the plugin's folder name and version.
* When an administrator clicks Repair on a finding, the plugin downloads that one original file from core.svn.wordpress.org or plugins.svn.wordpress.org. The request contains the WordPress version or plugin name and version, and the file's path.

WordPress.org privacy policy: https://wordpress.org/about/privacy/

= UAIP Security Cloud (security.uaip.dev) =

Used only for vulnerability alerts, which are off by default. An administrator turns them on under UAIP Security → Vulnerabilities, where the same information is shown before anything is sent.

* When turned on, the site registers once. Sent: the site address, the WordPress version and this plugin's version. No email address.
* Once a day, and shortly after plugins, themes or WordPress are installed, updated or deleted, the plugin sends the WordPress version and the folder name (slug) and version of each installed plugin and theme. Nothing else: no users, email addresses, content, visitor IP addresses or settings.
* The service matches the list against public vulnerability data from WPVulnerability.net (CC0) and Wordfence Intelligence, and returns the matches with their source credits, which the plugin shows.
* Turning alerts off stops all requests and deletes the stored results.

Terms of service: https://security.uaip.dev/terms
Privacy policy: https://security.uaip.dev/privacy

== Installation ==

1. Install the plugin from Plugins → Add New, or upload the zip, and activate it.
2. Open UAIP Security → Dashboard. The firewall, scanner, sign-in protection and activity log are on straight away.
3. Open Users → Two-step verification and add a passkey or an authenticator app for your own account.
4. Open UAIP Security → Hardening and go through the checks that are not yet passing.
5. Behind Cloudflare or another proxy, set the visitor IP source under UAIP Security → Firewall.

== Frequently Asked Questions ==

= Do I need an account? =

No. Every feature works on your own site without an account. Vulnerability alerts use our free cloud service, only if you turn them on, and still need no account.

= Will the firewall block real visitors? =

Rules add up a score, and a request is blocked only when the total passes the threshold. Administrators and editors are not inspected by default. If something legitimate is blocked, add an exception for that rule and path on the Firewall page, or use learning mode first to see what would be blocked.

= My site is behind Cloudflare. Does that matter? =

Yes. Choose Cloudflare as the visitor IP source on the Firewall page. Otherwise every visitor appears to come from a Cloudflare address, and rate limits and lockouts would apply to all of them at once.

= Does the scanner change my files on its own? =

No. It only reports. Files are repaired or deleted when you click the button, and a repair uses the original from WordPress.org only after its checksum matches.

= I lost my phone. How do I sign in? =

Use one of the recovery codes you saved when you set up two-step verification, or a passkey or email code if you added one. An administrator can also remove your methods from your user profile.

= Does it work with page caching? =

Yes. The firewall runs inside WordPress, so cached pages served directly by your web server or CDN are not inspected; requests that reach WordPress (forms, logins, the admin area, the REST API) are.

= What happens to my data when I delete the plugin? =

By default your settings and logs are kept, so reinstalling restores them. To remove everything on deletion, turn on "Delete all data when the plugin is removed" under UAIP Security → Settings.

== Screenshots ==

1. Dashboard: security score, recent activity and next steps.
2. Firewall: status, blocking mode, threshold, rate limit and visitor IP source.
3. Malware scan with findings and one-click repair.
4. Two-step sign-in with a passkey after the password.
5. Vulnerability alerts with fix versions and source credits.
6. Hardening checks and options.
7. Activity log with filters and CSV export.

== Changelog ==

= 1.0.0 =
* First release on WordPress.org.
