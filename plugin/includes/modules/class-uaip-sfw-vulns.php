<?php
/**
 * Vulnerability alerts (opt-in): once a day, and after updates, send the
 * WordPress version and the slugs and versions of installed plugins and
 * themes to UAIP Security Cloud, which matches them against known
 * vulnerabilities (WPVulnerability.net and Wordfence Intelligence data).
 *
 * Nothing is sent until an administrator turns this on. Turning it on
 * registers the site with the cloud (site address and versions, no email).
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Vulns {

	const HOOK    = 'uaip_sfw_vuln_check';
	const RESULTS = 'uaip_sfw_vuln_results';
	const SEEN    = 'uaip_sfw_vuln_seen';

	public function register_hooks() {
		add_action( self::HOOK, array( $this, 'run' ) );
		add_action( self::HOOK . '_once', array( $this, 'run' ) );
		add_action( 'init', array( $this, 'sync_schedule' ) );
		if ( self::enabled() ) {
			// Re-check soon after anything is installed or updated.
			add_action( 'upgrader_process_complete', array( $this, 'check_soon' ), 20 );
			add_action( '_core_updated_successfully', array( $this, 'check_soon' ) );
			add_action( 'deleted_plugin', array( $this, 'check_soon' ) );
		}
	}

	/** @return bool Alerts switched on. */
	public static function enabled() {
		return (bool) Uaip_Sfw_Settings::get( 'vuln_alerts' );
	}

	/** Daily cron while enabled, none otherwise. */
	public function sync_schedule() {
		$next = wp_next_scheduled( self::HOOK );
		if ( self::enabled() && ! $next ) {
			wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'daily', self::HOOK );
		} elseif ( ! self::enabled() && $next ) {
			wp_clear_scheduled_hook( self::HOOK );
		}
	}

	public function check_soon() {
		if ( ! wp_next_scheduled( self::HOOK . '_once' ) ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::HOOK . '_once' );
		}
	}

	/**
	 * Turn alerts on: register with the cloud if needed, then check now.
	 *
	 * @return true|WP_Error
	 */
	public function enable() {
		$api = Uaip_Sfw_Cloud_API::instance();
		if ( ! $api->is_connected() ) {
			$res = $api->register_site( '' );
			if ( is_wp_error( $res ) ) {
				return $res;
			}
			if ( ! $api->is_connected() ) {
				return new WP_Error( 'uaip_sfw_register', __( 'UAIP Security Cloud did not accept the registration.', 'uaip-security-firewall' ) );
			}
		}
		Uaip_Sfw_Settings::update( array( 'vuln_alerts' => true ) );
		$this->sync_schedule();
		$res = $this->run();
		return is_wp_error( $res ) ? $res : true;
	}

	/** Turn alerts off and forget the results. */
	public function disable() {
		Uaip_Sfw_Settings::update( array( 'vuln_alerts' => false ) );
		wp_clear_scheduled_hook( self::HOOK );
		wp_clear_scheduled_hook( self::HOOK . '_once' );
		delete_option( self::RESULTS );
		delete_option( self::SEEN );
	}

	/**
	 * What is sent: core version, plugin and theme slugs with versions.
	 *
	 * @return array
	 */
	public function inventory() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = false !== strpos( $file, '/' ) ? dirname( $file ) : basename( $file, '.php' );
			if ( '' !== (string) $data['Version'] ) {
				$plugins[] = array(
					'slug'    => strtolower( $slug ),
					'version' => (string) $data['Version'],
					'name'    => (string) $data['Name'],
					'file'    => $file,
				);
			}
		}
		$themes = array();
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			if ( '' !== (string) $theme->get( 'Version' ) ) {
				$themes[] = array(
					'slug'    => strtolower( $stylesheet ),
					'version' => (string) $theme->get( 'Version' ),
					'name'    => (string) $theme->get( 'Name' ),
				);
			}
		}
		return array(
			'core'    => get_bloginfo( 'version' ),
			'plugins' => $plugins,
			'themes'  => $themes,
		);
	}

	/**
	 * Ask the cloud and store the results.
	 *
	 * @return array|WP_Error Stored results.
	 */
	public function run() {
		if ( ! self::enabled() ) {
			return new WP_Error( 'uaip_sfw_vulns_off', __( 'Vulnerability alerts are off.', 'uaip-security-firewall' ) );
		}
		$inv  = $this->inventory();
		$body = array(
			'core'    => $inv['core'],
			'plugins' => array_map( array( $this, 'wire_item' ), $inv['plugins'] ),
			'themes'  => array_map( array( $this, 'wire_item' ), $inv['themes'] ),
		);
		$res = Uaip_Sfw_Cloud_API::instance()->check_vulns( $body );
		if ( is_wp_error( $res ) ) {
			$stored          = (array) get_option( self::RESULTS, array() );
			$stored['error'] = $res->get_error_message();
			$stored['tried'] = time();
			update_option( self::RESULTS, $stored, false );
			return $res;
		}

		$names = array( 'core:wordpress' => 'WordPress' );
		foreach ( $inv['plugins'] as $p ) {
			$names[ 'plugin:' . $p['slug'] ] = $p['name'];
		}
		foreach ( $inv['themes'] as $t ) {
			$names[ 'theme:' . $t['slug'] ] = $t['name'];
		}
		$items = array();
		foreach ( (array) ( $res['results'] ?? array() ) as $r ) {
			$key = ( $r['type'] ?? '' ) . ':' . ( $r['slug'] ?? '' );
			if ( ! isset( $names[ $key ] ) ) {
				continue; // only software this site reported
			}
			$vulns = array();
			foreach ( (array) ( $r['vulns'] ?? array() ) as $v ) {
				$vulns[] = array(
					'id'       => sanitize_text_field( (string) ( $v['id'] ?? '' ) ),
					'title'    => sanitize_text_field( (string) ( $v['title'] ?? '' ) ),
					'cve'      => preg_match( '/^CVE-\d{4}-\d+$/', (string) ( $v['cve'] ?? '' ) ) ? $v['cve'] : '',
					'cvss'     => isset( $v['cvss'] ) && is_numeric( $v['cvss'] ) ? (float) $v['cvss'] : null,
					'severity' => in_array( $v['severity'] ?? '', array( 'critical', 'high', 'medium', 'low' ), true ) ? $v['severity'] : 'unknown',
					'fixed_in' => sanitize_text_field( (string) ( $v['fixed_in'] ?? '' ) ),
					'link'     => esc_url_raw( (string) ( $v['link'] ?? '' ), array( 'https' ) ),
				);
			}
			if ( $vulns ) {
				$items[] = array(
					'type'    => $r['type'],
					'slug'    => sanitize_key( $r['slug'] ),
					'name'    => $names[ $key ],
					'version' => sanitize_text_field( (string) $r['version'] ),
					'vulns'   => $vulns,
				);
			}
		}
		$stored = array(
			'checked_at' => time(),
			'checked'    => (int) ( $res['checked'] ?? 0 ),
			'items'      => $items,
			'credits'    => array_map( 'sanitize_text_field', (array) ( $res['credits'] ?? array() ) ),
			'error'      => '',
		);
		update_option( self::RESULTS, $stored, false );
		$this->alert_new( $items );
		return $stored;
	}

	/** @param array $p Inventory item. */
	public function wire_item( $p ) {
		return array(
			'slug'    => $p['slug'],
			'version' => $p['version'],
		);
	}

	/**
	 * Email and log only issues not seen before.
	 *
	 * @param array $items Results.
	 */
	private function alert_new( array $items ) {
		$seen  = (array) get_option( self::SEEN, array() );
		$now   = array();
		$fresh = array();
		foreach ( $items as $it ) {
			foreach ( $it['vulns'] as $v ) {
				$key         = $it['type'] . ':' . $it['slug'] . ':' . $it['version'] . ':' . $v['id'];
				$now[ $key ] = true;
				if ( ! isset( $seen[ $key ] ) ) {
					$fresh[] = array( $it, $v );
				}
			}
		}
		update_option( self::SEEN, $now, false );
		if ( ! $fresh ) {
			return;
		}
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		$lines = array();
		foreach ( $fresh as list( $it, $v ) ) {
			if ( $audit ) {
				$audit->record( 'vuln_found', array( 'title' => $v['title'], 'severity' => $v['severity'], 'fixed_in' => $v['fixed_in'] ), $it['name'] . ' ' . $it['version'] );
			}
			$lines[] = sprintf( '• %s %s: %s [%s]%s', $it['name'], $it['version'], $v['title'], strtoupper( $v['severity'] ), '' !== $v['fixed_in'] ? ' — ' . sprintf( /* translators: %s: version */ __( 'fixed in %s', 'uaip-security-firewall' ), $v['fixed_in'] ) : '' );
		}
		Uaip_Sfw_Notifier::vulnerabilities( $lines );
	}

	/** @return array Stored results (empty array when never checked). */
	public static function results() {
		$r = get_option( self::RESULTS, array() );
		return is_array( $r ) ? $r : array();
	}
}
