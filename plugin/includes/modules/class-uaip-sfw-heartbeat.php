<?php
/**
 * Cloud heartbeat — periodic check-in that powers anomaly detection, uptime
 * monitoring and rule freshness. Free sends a light payload; the cloud decides
 * what to alert on.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Heartbeat {

	public function register_hooks() {
		add_action( 'uaip_sfw_heartbeat', array( $this, 'run' ) );
	}

	public function run() {
		// Cloud monitoring is Pro-only; the Free tier runs fully standalone and
		// never contacts the cloud.
		if ( ! Uaip_Sfw_Plugin::instance()->license->is_pro() || ! Uaip_Sfw_Cloud_API::instance()->is_connected() ) {
			return;
		}

		$waf   = Uaip_Sfw_Plugin::instance()->module( 'waf' );
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );

		// New audit-log entries since the last successful sync (batched).
		$last_audit  = (int) get_option( 'uaip_sfw_audit_sync_id', 0 );
		$audit_batch = $audit ? $audit->since_id( $last_audit, 50 ) : array();

		$payload = array(
			'ts'           => time(),
			'wp'           => get_bloginfo( 'version' ),
			'php'          => PHP_VERSION,
			'tier'         => Uaip_Sfw_Plugin::instance()->license->tier(),
			'blocks_15m'   => $waf && method_exists( $waf, 'recent_block_count' ) ? $waf->recent_block_count() : 0,
			'failed_logins_15m' => $this->failed_logins_recent(),
			'last_scan'    => get_option( 'uaip_sfw_last_scan_summary', array() ),
			'waf_rules_version' => (int) get_option( 'uaip_sfw_waf_rules_version', 0 ),
			'plugins'      => $this->plugin_inventory(),
			'audit'        => $audit_batch,
		);

		$result = Uaip_Sfw_Cloud_API::instance()->heartbeat( $payload );
		if ( is_wp_error( $result ) ) {
			update_option( 'uaip_sfw_last_heartbeat_error', time() );
			return;
		}

		// Stamp a successful sync — drives the "Connected / live" indicator.
		update_option( 'uaip_sfw_last_heartbeat', time() );

		// Advance the audit-sync pointer only after a successful send.
		if ( ! empty( $audit_batch ) ) {
			$last = end( $audit_batch );
			update_option( 'uaip_sfw_audit_sync_id', (int) $last['id'], false );
		}

		// The cloud may push back rule updates or anomaly verdicts.
		if ( ! empty( $result['rules_stale'] ) ) {
			do_action( 'uaip_sfw_pull_rules' );
		}

		// Near-instant licence enforcement: refresh the cached state from the
		// cloud's pushed status, then reconcile the tier (halts Pro on
		// revocation / expiry / seat-release without waiting for the daily check).
		if ( isset( $result['license'] ) && is_array( $result['license'] ) ) {
			$this->sync_license_state( $result['license'] );
		}

		// Track which dashboard account this site is bound to.
		if ( array_key_exists( 'account', $result ) ) {
			update_option( 'uaip_sfw_account_email', (string) $result['account'] );
		}
	}

	/**
	 * Merge the cloud-pushed license status into the cached state and enforce.
	 *
	 * @param array $license
	 */
	private function sync_license_state( $license ) {
		$state               = get_option( Uaip_Sfw_License::OPT_STATE, array() );
		$state               = is_array( $state ) ? $state : array();
		$state['active']     = ! empty( $license['active'] );
		$state['plan']       = isset( $license['plan'] ) ? $license['plan'] : ( $state['plan'] ?? 'free' );
		$state['expires']    = array_key_exists( 'expires', $license ) ? $license['expires'] : ( $state['expires'] ?? null );
		$state['reason']     = isset( $license['reason'] ) ? $license['reason'] : ( $state['reason'] ?? null );
		$state['checked_at'] = time();
		update_option( Uaip_Sfw_License::OPT_STATE, $state );

		Uaip_Sfw_Plugin::instance()->license->enforce_tier();
	}

	/** @return int */
	private function failed_logins_recent() {
		return (int) get_transient( 'uaip_sfw_failed_logins_15m' );
	}

	/** @return array Lightweight inventory for CVE matching. */
	private function plugin_inventory() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array();
		foreach ( get_plugins() as $file => $data ) {
			$out[ dirname( $file ) ] = isset( $data['Version'] ) ? $data['Version'] : '';
		}
		return $out;
	}
}
