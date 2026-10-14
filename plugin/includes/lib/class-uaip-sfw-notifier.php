<?php
/**
 * Uaip_Sfw_Notifier — security email alerts (Free).
 *
 * Sends throttled wp_mail notifications for important events. Throttling
 * prevents alert storms (e.g. one email per event type per hour).
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Notifier {

	/** Minimum seconds between emails of the same type. */
	const THROTTLE = HOUR_IN_SECONDS;

	/**
	 * Send an alert if alerts are enabled and not throttled.
	 *
	 * @param string $type    Event type slug (used for throttling).
	 * @param string $subject
	 * @param string $body
	 * @return bool Whether an email was sent.
	 */
	public static function notify( $type, $subject, $body ) {
		if ( ! Uaip_Sfw_Settings::get( 'anomaly_alerts' ) ) {
			return false;
		}

		$lock = 'uaip_sfw_alert_' . $type;
		if ( get_transient( $lock ) ) {
			return false; // throttled
		}

		$to = Uaip_Sfw_Settings::get( 'alert_email' );
		if ( empty( $to ) || ! is_email( $to ) ) {
			$to = get_option( 'admin_email' );
		}
		if ( empty( $to ) ) {
			return false;
		}

		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$subject = sprintf( '[UAIP Security] %s — %s', $subject, $site );
		$footer  = "\n\n—\n" . sprintf(
			/* translators: %s: site url */
			__( 'Sent by UAIP Security Firewall on %s', 'uaip-security-firewall' ),
			home_url()
		);

		$sent = wp_mail( $to, $subject, $body . $footer );
		if ( $sent ) {
			set_transient( $lock, 1, self::THROTTLE );
		}
		return $sent;
	}

	/**
	 * Convenience: alert about malware findings.
	 *
	 * @param array $findings
	 */
	public static function malware( $findings ) {
		$count = count( $findings );
		$lines = array();
		foreach ( array_slice( $findings, 0, 10 ) as $f ) {
			$lines[] = sprintf( '• [%s] %s — %s', strtoupper( $f['severity'] ), $f['file'], $f['rule'] );
		}
		$body = sprintf(
			/* translators: %d: number of issues */
			_n( 'UAIP Security found %d potential security issue:', 'UAIP Security found %d potential security issues:', $count, 'uaip-security-firewall' ),
			$count
		) . "\n\n" . implode( "\n", $lines );
		/* translators: %s: admin page URL */
		$body .= "\n\n" . sprintf( __( 'Review them here: %s', 'uaip-security-firewall' ), admin_url( 'admin.php?page=uaip-sfw-scan' ) );
		self::notify( 'malware', __( 'Malware detected', 'uaip-security-firewall' ), $body );
	}

	/**
	 * Alert about newly found vulnerabilities in installed software.
	 *
	 * @param string[] $lines One line per issue.
	 */
	public static function vulnerabilities( array $lines ) {
		$count = count( $lines );
		$body  = sprintf(
			/* translators: %d: number of vulnerabilities */
			_n( 'UAIP Security found %d known vulnerability in software installed on this site:', 'UAIP Security found %d known vulnerabilities in software installed on this site:', $count, 'uaip-security-firewall' ),
			$count
		) . "\n\n" . implode( "\n", array_slice( $lines, 0, 20 ) );
		/* translators: %s: admin page URL */
		$body .= "\n\n" . sprintf( __( 'Details and updates: %s', 'uaip-security-firewall' ), admin_url( 'admin.php?page=uaip-sfw-vulns' ) );
		self::notify( 'vulns', __( 'Vulnerable software found', 'uaip-security-firewall' ), $body );
	}

	/** @return string Where security email goes (alert email, else the admin email). */
	public static function recipient() {
		$to = (string) Uaip_Sfw_Settings::get( 'alert_email' );
		return is_email( $to ) ? $to : (string) get_option( 'admin_email' );
	}

	/**
	 * Convenience: alert about an attack surge.
	 *
	 * @param int $count Blocks in the recent window.
	 */
	public static function attack_surge( $count ) {
		$body = sprintf(
			/* translators: %d: number of blocked attacks */
			__( 'UAIP Security blocked %d attacks in the last 15 minutes — your site may be under attack.', 'uaip-security-firewall' ),
			$count
		);
		/* translators: %s: admin page URL */
		$body .= "\n\n" . sprintf( __( 'Firewall activity: %s', 'uaip-security-firewall' ), admin_url( 'admin.php?page=uaip-sfw-firewall' ) );
		self::notify( 'attack_surge', __( 'Attack surge detected', 'uaip-security-firewall' ), $body );
	}

	/**
	 * Convenience: alert about an administrator login.
	 *
	 * @param WP_User $user
	 * @param string  $ip
	 */
	public static function admin_login( $user, $ip ) {
		$body = sprintf(
			/* translators: 1: username, 2: ip */
			__( 'Administrator "%1$s" just signed in from IP %2$s.', 'uaip-security-firewall' ),
			$user->user_login,
			$ip
		);
		// Per-user throttle so multiple admins each alert.
		self::notify( 'admin_login_' . $user->ID, __( 'Administrator login', 'uaip-security-firewall' ), $body );
	}
}
