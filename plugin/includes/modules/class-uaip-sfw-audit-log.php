<?php
/**
 * Security activity audit log.
 *
 * Free: local storage, 30-day retention.
 * Pro:  also mirrored to tamper-proof cloud storage (via the send_event hook).
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Audit_Log {

	const OPTION = 'uaip_sfw_audit_events';
	const MAX    = 1000; // local ring buffer

	public function register_hooks() {
		if ( ! Uaip_Sfw_Settings::get( 'audit_log_enabled' ) ) {
			return;
		}
		// Track core security-sensitive events.
		add_action( 'wp_login', function ( $login, $user = null ) {
			$this->record( 'login_success', array( 'user' => $login ) );
			// Alert on administrator logins.
			if ( $user instanceof WP_User && user_can( $user, 'manage_options' ) ) {
				Uaip_Sfw_Notifier::admin_login( $user, Uaip_Sfw_Settings::visitor_ip() );
			}
		}, 10, 2 );
		add_action( 'activated_plugin', function ( $plugin ) { $this->record( 'plugin_activated', array( 'plugin' => $plugin ) ); } );
		add_action( 'deactivated_plugin', function ( $plugin ) { $this->record( 'plugin_deactivated', array( 'plugin' => $plugin ) ); } );
		add_action( 'switch_theme', function ( $name ) { $this->record( 'theme_switched', array( 'theme' => $name ) ); } );
	}

	/**
	 * Record an event locally and, for Pro, mirror it to the cloud.
	 *
	 * @param string $type
	 * @param array  $data
	 */
	public function record( $type, array $data = array() ) {
		$event = array(
			'ts'   => time(),
			'type' => $type,
			'ip'   => Uaip_Sfw_Settings::visitor_ip(),
			'user' => get_current_user_id(),
			'data' => $data,
		);

		$events   = get_option( self::OPTION, array() );
		$events[] = $event;
		if ( count( $events ) > self::MAX ) {
			$events = array_slice( $events, -self::MAX );
		}
		update_option( self::OPTION, $events, false );

		// Pro: tamper-proof cloud mirror + drives cloud anomaly detection. Free
		// keeps the local log only and never contacts the cloud.
		if ( Uaip_Sfw_Plugin::instance()->license->is_pro() && Uaip_Sfw_Cloud_API::instance()->is_connected() ) {
			Uaip_Sfw_Cloud_API::instance()->send_event( $type, $event );
		}
	}

	/**
	 * @param int $limit
	 * @return array Most-recent events first.
	 */
	public function recent( $limit = 50 ) {
		$events = get_option( self::OPTION, array() );
		return array_slice( array_reverse( $events ), 0, $limit );
	}

	/**
	 * Events newer than a timestamp (oldest-first), for batched cloud sync.
	 *
	 * @param int $ts
	 * @param int $limit
	 * @return array
	 */
	public function since( $ts, $limit = 50 ) {
		$events = get_option( self::OPTION, array() );
		$out    = array();
		foreach ( $events as $e ) {
			if ( isset( $e['ts'] ) && (int) $e['ts'] > (int) $ts ) {
				$out[] = $e;
			}
		}
		return array_slice( $out, -$limit );
	}

	/**
	 * Clear the local audit log. Already-synced events remain in your cloud
	 * activity log; this only empties the local copy shown on this site.
	 *
	 * @return int Number of events removed.
	 */
	public function clear() {
		$count = count( (array) get_option( self::OPTION, array() ) );
		delete_option( self::OPTION );
		return $count;
	}
}
