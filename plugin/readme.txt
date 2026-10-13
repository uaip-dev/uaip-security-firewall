=== UAIP Security Firewall ===
Contributors: uaip
Tags: security, firewall, malware scanner, login security, 2fa
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Endpoint firewall, YARA malware scanner, login protection, 2FA, hardening and audit log - fully standalone. Optional cloud monitoring.

== Description ==

UAIP Security combines a local Web Application Firewall, a YARA-based malware
scanner (with a pure-PHP fallback for shared hosting), brute-force login
protection, 2FA, site hardening and an activity audit log — all working
**standalone** in the Free tier, with no cloud dependency required.

= Free (fully standalone — no account or cloud required) =
* Endpoint WAF — blocks SQLi, RCE, XSS, LFI, traversal (bundled ruleset)
* Rate limiting & bot throttling
* YARA malware/webshell scanning (binary or PHP-lite fallback)
* Core/plugin/theme integrity vs WordPress.org
* Brute-force lockouts + CAPTCHA
* Two-factor authentication (TOTP)
* Breached-password blocking (local list)
* Site hardening (.htaccess, disable editor, block PHP in uploads)
* Custom login page — logo & colours (brand your wp-login.php)
* Activity audit log (local, 30-day)
* Traffic-anomaly email alerts (local)

= Pro (subscription) =
Pro is a **separate package** downloaded from your UAIP Security account and
activated with a license key. It adds:

* UAIP Security Cloud connectivity — account dashboard, site monitoring & threat intelligence (the Free tier is fully standalone and never contacts the cloud)
* Extended protection mode (auto_prepend, runs the firewall before WordPress)
* ClamAV antivirus (local clamd)
* Cloud threat intelligence — flag known malware by file hash (only hashes leave your site)
* Real-time traffic anomaly detection with email alerts + cloud activity log
* One-click automatic & unlimited malware cleanup
* Full malware-sample sandboxing
* Country / geo blocking
* WAF rules every 5 minutes + virtual patching
* Real-time CVE alerts & auto virtual patch
* Premium firewall rule feed (Threat Defense Feed)
* Centralized cloud activity log (unlimited retention)
* Multi-site dashboard, reports & white-label
* Self-service billing & invoices (Stripe customer portal)
* Uptime & performance monitoring

== External Services ==

The Free tier runs **fully standalone** and does not send any data to
UAIP Security Cloud. The only external request it makes is to WordPress.org's
checksum API (https://api.wordpress.org) to verify core/plugin/theme integrity.

UAIP Security Cloud connectivity is a **Pro** feature. If you purchase Pro and
enter a license key, the plugin contacts UAIP Security Cloud at
https://security.uaip.dev over HTTPS to validate the key and, once activated, to
provide licensing, monitoring and threat intelligence. Depending on the feature
in use, it may then send:

* Site registration & licence checks: your site URL, admin email, and WordPress/PHP/plugin versions.
* Heartbeats (monitoring & rule updates): counts of blocked requests and failed logins, your plugin inventory and versions, and the last scan summary.
* File reputation: SHA-256 hashes of scanned files only - never file contents.
* Activity log sync: the plugin's own security events, to your cloud account.

No information about your site's visitors is ever collected.

Use of UAIP Security Cloud is governed by its Terms of Service
(https://security.uaip.dev/terms) and Privacy Policy (https://security.uaip.dev/privacy).

== Installation ==

1. Upload the `uaip-security-firewall` folder to `/wp-content/plugins/`.
2. Activate through the 'Plugins' menu in WordPress. The Free tier is fully
   standalone — no account or configuration required.
3. For Pro: install the Pro package from your account and enter your license
   key under UAIP Security → License (this enables UAIP Security Cloud).

== Frequently Asked Questions ==

= Does the Free plugin work without an account or the cloud? =

Yes — completely. Every Free feature runs entirely on your own server and the
Free tier never contacts UAIP Security Cloud. Cloud connectivity is a Pro feature.

= What data is sent to UAIP Security Cloud, and when? =

On the Free tier, nothing — it is fully standalone. UAIP Security Cloud is a Pro
feature: only after you enter a Pro license key does the plugin contact the
cloud (see External Services for exactly what each feature sends). File contents
are never uploaded — only SHA-256 hashes are used for reputation checks.

= Do I need Pro to use it? =

No. Pro is an optional paid upgrade. The Free plugin is fully functional on its own.

== Screenshots ==

1. Security dashboard — protection status, attacks blocked and the latest scan at a glance.
2. Endpoint firewall — WAF status, recent blocks and rate-limiting controls.
3. Malware scan — YARA + integrity results with file-change tracking and one-click remediation.
4. Two-factor authentication setup with QR code and recovery codes.
5. License & cloud connection — connect your site to UAIP Security Cloud.

== Changelog ==

= 0.1.22 =
* Renamed the plugin's internal PHP classes to a 4+ character prefix
  (Uaip_Sfw_) to avoid naming collisions, per WordPress.org guidelines.
* Removed file quarantine/restore; detected malware is now reported and can be
  permanently deleted (the plugin no longer moves files into uploads/wp-content).
* Stored firewall request data is now sanitized (sanitize_text_field) before it
  is saved, in addition to being escaped on output.
* Renamed the bundled YARA rule file to a .txt extension and the firewall block
  page now uses inline style attributes instead of a <style> block.

= 0.1.21 =
* Removed the free-form Custom CSS field from the login page customiser; login
  branding is now built entirely from the structured logo/colour settings.
* Login styles and the scan-page auto-refresh are now enqueued via
  wp_add_inline_style() / wp_add_inline_script() instead of inline tags.
* Extended protection (the auto_prepend firewall loader) is now a Pro-only
  feature and no longer ships in the WordPress.org build.
* Malware scanner now resolves plugin/mu-plugin/uploads/theme roots via the
  proper WordPress functions and stages working files under uploads.
* Hardened request-data handling and phpcs annotations in the firewall engine.
* The firewall block / rate-limit pages no longer call translation functions
  before the init hook, resolving a WordPress 6.7 "textdomain loaded too early"
  notice.

= 0.1.20 =
* Packaging: removed the duplicate Author URI plugin header (it matched the
  Plugin URI) for WordPress.org compliance. No functional changes.

= 0.1.19 =
* Fixed a WordPress 6.7 "translation loading triggered too early" notice (and
  the resulting "headers already sent" warnings) on activation and admin pages.
  Translations now load on the init hook.

= 0.1.18 =
* Plans page: corrected the Free vs Pro comparison to match the standalone Free
  tier (cloud threat intelligence, CVE alerts, cloud account and sample upload
  are shown as Pro; the audit log and WAF notes no longer imply cloud on Free).

= 0.1.17 =
* UAIP Security Cloud is now a Pro-only feature; the Free tier is fully standalone
  and never contacts the cloud. Cloud monitoring, the account dashboard,
  file-hash threat intelligence and cloud rule updates now require an active Pro
  license. Entering a Pro license key connects and activates in one step.

= 0.1.16 =
* Fixed: the "Rate limiting & bot throttling" toggle on the Settings page now
  actually enables/disables rate limiting (previously it had no effect; the
  per-IP threshold on the Firewall page still controls the limit).

= 0.1.15 =
* Fixed: the Settings page and dashboard now show your real two-factor status.
  Disabling 2FA on the Two-Factor page is reflected everywhere (previously a
  separate, unused setting could still read "enabled"). 2FA is managed per user
  account from the Two-Factor page.

= 0.1.14 =
* Security hardening: 2FA is now enforced for Application Passwords (they can no
  longer bypass the second factor); quarantined files use unguessable IDs and
  restore is re-validated to stay inside wp-content; custom login CSS sanitizer
  hardened; WAF rejects malformed/oversized rule patterns.

= 0.1.13 =
* Code quality: resolved all WordPress.org Plugin Check issues in the Free
  package (internationalization comments, output escaping and direct-file-access
  guards). No functional changes.

= 0.1.12 =
* Docs: WordPress.org readme compliance — added an External Services
  disclosure and FAQ, and shortened the summary.

= 0.1.11 =
* "Scan now" runs in the background (no timeout on big sites). The first scan
  shows a "building baseline" notice and the page auto-refreshes when done.

= 0.1.10 =
* File-integrity baseline: scans now only re-check NEW or CHANGED files against
  cloud threat intel (unchanged files are skipped), and track added/changed/
  removed code files on the Scan page.

= 0.1.9 =
* Performance: cloud hash reputation now reuses the scanner's existing file
  read (no extra disk I/O) and looks up in batches.

= 0.1.8 =
* Cloud threat intelligence: the scanner now checks file SHA-256 hashes against
  UAIP Security Cloud and flags known malware (only hashes leave your site).
* Corrected feature wording (removed unbuilt "cloud deep-scan" claims).

= 0.1.7 =
* UI: the scanner status now reads "Malware scanner: Active" instead of the
  internal engine codename (e.g. php-lite).

= 0.1.6 =
* Added a "Clear log" button to the Audit Log page (synced events remain in
  your cloud activity log).

= 0.1.5 =
* Fixed: a license key entered before connecting to the cloud now activates
  immediately on connect (was stuck on Free until the next daily check).

= 0.1.4 =
* Added opt-in "Delete all data on uninstall" setting (off by default).
* Deleting the plugin now fully removes all options, 2FA data, transients and
  scheduled tasks when opted in; deactivation always preserves your settings.

= 0.1.3 =
* Pro pricing updated to $9/mo, with a 10% discount on annual (yearly) billing.

= 0.1.0 =
* Initial scaffold: tier system, WAF, scanner (YARA), login guard, 2FA,
  hardening, audit log, cloud client, admin UI.

== Upgrade Notice ==

= 0.1.20 =
Packaging/header compliance fix for WordPress.org. No functional changes.

= 0.1.19 =
Fixes a WordPress 6.7 textdomain notice and related warnings. Recommended.

= 0.1.18 =
Corrects the Free vs Pro feature comparison. Safe update.

= 0.1.17 =
UAIP Security Cloud is now Pro-only; the Free tier runs fully standalone. Existing
free sites simply stop contacting the cloud.

= 0.1.16 =
The Settings-page rate-limiting toggle now works as expected. Safe update.

= 0.1.15 =
Fixes the two-factor status shown on the Settings page and dashboard. Safe
update.

= 0.1.14 =
Security hardening for two-factor authentication and the malware quarantine.
Recommended update.

= 0.1.13 =
Code-quality and WordPress.org compliance pass. No functional changes; safe
update.

= 0.1.12 =
Adds a file-integrity baseline scanner (only re-checks changed files) and
background scanning. Recommended update.
