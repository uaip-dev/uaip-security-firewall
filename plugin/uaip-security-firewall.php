<?php
/**
 * Plugin Name:       UAIP Security Firewall
 * Plugin URI:        https://github.com/uaip-dev/uaip-security-firewall
 * Description:       Web application firewall, malware scanner, login protection and two-factor authentication for WordPress. Works on its own; the optional UAIP Security Cloud adds vulnerability alerts and fleet monitoring.
 * Version:           0.2.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            UAIP
 * Author URI:        https://uaip.dev/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       uaip-security-firewall
 * Domain Path:       /languages
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // No direct access.
}

// ---------------------------------------------------------------------------
// Plugin constants
// ---------------------------------------------------------------------------
define( 'UAIP_SFW_VERSION', '0.2.0' );
define( 'UAIP_SFW_FILE', __FILE__ );
define( 'UAIP_SFW_DIR', plugin_dir_path( __FILE__ ) );
define( 'UAIP_SFW_URL', plugin_dir_url( __FILE__ ) );
define( 'UAIP_SFW_BASENAME', plugin_basename( __FILE__ ) );

/**
 * UAIP Security Cloud base URL. The plugin only contacts it after the site owner
 * connects the site (see readme "External services").
 */
if ( ! defined( 'UAIP_SFW_CLOUD_URL' ) ) {
	define( 'UAIP_SFW_CLOUD_URL', 'https://security.uaip.dev/api/v1' );
}

/**
 * Browser-reachable cloud site URL (for the pricing/upgrade link). Defaults to
 * the API URL with the /api/... suffix stripped.
 */
if ( ! defined( 'UAIP_SFW_CLOUD_SITE' ) ) {
	define( 'UAIP_SFW_CLOUD_SITE', preg_replace( '#/api/.*$#', '', UAIP_SFW_CLOUD_URL ) );
}

/**
 * Whether the Pro package is present. Pro is distributed as a SEPARATE
 * downloadable package (not on WordPress.org) that ships the /pro folder.
 * The Free build from the .org repo does not contain it.
 */
define( 'UAIP_SFW_HAS_PRO_PACKAGE', file_exists( UAIP_SFW_DIR . 'pro/class-uaip-sfw-pro-loader.php' ) );

// ---------------------------------------------------------------------------
// Lightweight autoloader for Uaip_Sfw_* classes
// ---------------------------------------------------------------------------
spl_autoload_register(
	function ( $class ) {
		if ( strpos( $class, 'Uaip_Sfw_' ) !== 0 ) {
			return;
		}
		// Uaip_Sfw_WAF_Rules -> class-uaip-sfw-waf-rules.php
		$file = 'class-' . str_replace( '_', '-', strtolower( $class ) ) . '.php';

		$paths = array(
			UAIP_SFW_DIR . 'includes/' . $file,
			UAIP_SFW_DIR . 'includes/lib/' . $file,
			UAIP_SFW_DIR . 'includes/modules/' . $file,
			UAIP_SFW_DIR . 'includes/admin/' . $file,
			UAIP_SFW_DIR . 'includes/cloud/' . $file,
			UAIP_SFW_DIR . 'pro/' . $file,
			UAIP_SFW_DIR . 'pro/modules/' . $file,
		);
		foreach ( $paths as $path ) {
			if ( file_exists( $path ) ) {
				require_once $path;
				return;
			}
		}
	}
);

// ---------------------------------------------------------------------------
// Activation / deactivation
// ---------------------------------------------------------------------------
register_activation_hook(
	__FILE__,
	function () {
		require_once UAIP_SFW_DIR . 'includes/class-uaip-sfw-settings.php';
		Uaip_Sfw_Settings::install_defaults();
		Uaip_Sfw_DB::install();
		// Schedule the cloud heartbeat (every 15 min).
		if ( ! wp_next_scheduled( 'uaip_sfw_heartbeat' ) ) {
			wp_schedule_event( time() + 60, 'uaip_sfw_quarter_hour', 'uaip_sfw_heartbeat' );
		}
		set_transient( 'uaip_sfw_activation_redirect', 1, 30 );
	}
);

register_deactivation_hook(
	__FILE__,
	function () {
		// Deactivation is temporary (updates, troubleshooting): stop background
		// work but PRESERVE all settings/data. Data is only removed on delete,
		// and only if the admin opted in (see uninstall.php).
		wp_clear_scheduled_hook( 'uaip_sfw_heartbeat' );
		wp_clear_scheduled_hook( 'uaip_sfw_scan' );
		wp_clear_scheduled_hook( 'uaip_sfw_scan_step' );
	}
);

// Custom cron schedule used by the heartbeat.
add_filter(
	'cron_schedules',
	function ( $schedules ) {
		$schedules['uaip_sfw_quarter_hour'] = array(
			'interval' => 15 * MINUTE_IN_SECONDS,
			// Plain string (not __()): cron_schedules fires on activation before
			// the init hook, and translating here would load the textdomain too
			// early (WordPress 6.7+). This label is internal (cron tools only).
			'display'  => 'Every 15 minutes (UAIP Security)',
		);
		return $schedules;
	}
);

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
add_action(
	'plugins_loaded',
	function () {
		Uaip_Sfw_Plugin::instance()->boot();
	}
);
