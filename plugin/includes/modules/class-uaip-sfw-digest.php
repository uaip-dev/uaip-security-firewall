<?php
/**
 * Weekly security summary email (opt-in): attacks blocked, sign-in failures,
 * notable changes, the latest scan, known vulnerabilities, waiting updates
 * and the security checks. Built entirely on this site; nothing is sent to
 * the cloud.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Digest {

	const HOOK = 'uaip_sfw_digest';

	public function register_hooks() {
		add_action( self::HOOK, array( $this, 'send' ) );
		add_action( 'init', array( $this, 'sync_schedule' ) );
	}

	public function sync_schedule() {
		$on   = (bool) Uaip_Sfw_Settings::get( 'digest_weekly' );
		$next = wp_next_scheduled( self::HOOK );
		if ( $on && ! $next ) {
			// Monday 08:00 in the site's time zone.
			$when = new DateTimeImmutable( 'next monday 08:00', wp_timezone() );
			wp_schedule_event( $when->getTimestamp(), 'weekly', self::HOOK );
		} elseif ( ! $on && $next ) {
			wp_clear_scheduled_hook( self::HOOK );
		}
	}

	/**
	 * Email the summary.
	 *
	 * @return bool Sent.
	 */
	public function send() {
		$to = Uaip_Sfw_Notifier::recipient();
		if ( '' === $to ) {
			return false;
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name */
		$subject = sprintf( __( '[UAIP Security] Weekly summary for %s', 'uaip-security-firewall' ), $site );
		return wp_mail( $to, $subject, $this->body() );
	}

	/**
	 * The summary text.
	 *
	 * @return string
	 */
	public function body() {
		$since  = time() - WEEK_IN_SECONDS;
		$audit  = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		$counts = $audit ? $audit->counts_since( $since ) : array();
		$c      = function ( $types ) use ( $counts ) {
			$n = 0;
			foreach ( (array) $types as $t ) {
				$n += isset( $counts[ $t ] ) ? (int) $counts[ $t ] : 0;
			}
			return $n;
		};
		$out = array();

		/* translators: %s: site address */
		$out[] = sprintf( __( 'Security summary for %s, last 7 days.', 'uaip-security-firewall' ), home_url() );
		$out[] = '';

		$out[] = __( 'FIREWALL AND SIGN-IN', 'uaip-security-firewall' );
		/* translators: %d: count */
		$out[] = '• ' . sprintf( __( 'Attacks blocked: %d', 'uaip-security-firewall' ), $c( 'attack_blocked' ) );
		/* translators: %d: count */
		$out[] = '• ' . sprintf( __( 'Failed sign-ins: %d', 'uaip-security-firewall' ), $c( array( 'login_failed', 'twofa_failed' ) ) );
		/* translators: %d: count */
		$out[] = '• ' . sprintf( __( 'Successful sign-ins: %d', 'uaip-security-firewall' ), $c( 'login_success' ) );
		$out[] = '';

		$changes = array(
			'user_created'      => __( 'Users created', 'uaip-security-firewall' ),
			'user_deleted'      => __( 'Users deleted', 'uaip-security-firewall' ),
			'user_role_changed' => __( 'Role changes', 'uaip-security-firewall' ),
			'plugin_installed'  => __( 'Plugins installed', 'uaip-security-firewall' ),
			'plugin_deleted'    => __( 'Plugins deleted', 'uaip-security-firewall' ),
			'option_changed'    => __( 'Site settings changed', 'uaip-security-firewall' ),
		);
		$lines = array();
		foreach ( $changes as $type => $label ) {
			if ( $c( $type ) ) {
				$lines[] = '• ' . $label . ': ' . $c( $type );
			}
		}
		$out[] = __( 'CHANGES', 'uaip-security-firewall' );
		$out   = array_merge( $out, $lines ? $lines : array( '• ' . __( 'No user, plugin or setting changes.', 'uaip-security-firewall' ) ) );
		$out[] = '';

		$out[]   = __( 'MALWARE SCAN', 'uaip-security-firewall' );
		$summary = get_option( Uaip_Sfw_Scanner::SUMMARY_OPTION, array() );
		$scanner = Uaip_Sfw_Plugin::instance()->module( 'scanner' );
		$open    = $scanner ? count( $scanner->findings( 'open', 100 ) ) : 0;
		if ( empty( $summary['ts'] ) ) {
			$out[] = '• ' . __( 'No scan has run yet.', 'uaip-security-firewall' );
		} else {
			/* translators: %s: date and time */
			$out[] = '• ' . sprintf( __( 'Last scan: %s', 'uaip-security-firewall' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $summary['ts'] ) );
			/* translators: %d: count */
			$out[] = '• ' . sprintf( __( 'Open findings: %d', 'uaip-security-firewall' ), $open );
		}
		$out[] = '';

		$out[] = __( 'KNOWN VULNERABILITIES', 'uaip-security-firewall' );
		if ( ! Uaip_Sfw_Vulns::enabled() ) {
			$out[] = '• ' . __( 'Vulnerability alerts are off.', 'uaip-security-firewall' );
		} else {
			$res   = Uaip_Sfw_Vulns::results();
			$items = isset( $res['items'] ) ? $res['items'] : array();
			if ( ! $items ) {
				$out[] = '• ' . __( 'None found in installed software.', 'uaip-security-firewall' );
			}
			foreach ( $items as $it ) {
				/* translators: 1: software name, 2: version, 3: number of issues */
				$out[] = '• ' . sprintf( _n( '%1$s %2$s: %3$d issue', '%1$s %2$s: %3$d issues', count( $it['vulns'] ), 'uaip-security-firewall' ), $it['name'], $it['version'], count( $it['vulns'] ) );
			}
		}
		$out[] = '';

		$out[] = __( 'UPDATES WAITING', 'uaip-security-firewall' );
		$up    = $this->updates();
		$out[] = $up ? '• ' . implode( ', ', $up ) : '• ' . __( 'Everything is up to date.', 'uaip-security-firewall' );
		$out[] = '';

		$health = Uaip_Sfw_Plugin::instance()->module( 'site_health' );
		if ( $health ) {
			$score = Uaip_Sfw_Site_Health::score( $health->results() );
			$out[] = __( 'SECURITY CHECKS', 'uaip-security-firewall' );
			/* translators: 1: checks passed, 2: total */
			$out[] = '• ' . sprintf( __( '%1$d of %2$d pass', 'uaip-security-firewall' ), $score['passed'], $score['total'] );
			$out[] = '';
		}

		/* translators: %s: admin URL */
		$out[] = sprintf( __( 'Dashboard: %s', 'uaip-security-firewall' ), admin_url( 'admin.php?page=uaip-sfw' ) );
		/* translators: %s: settings URL */
		$out[] = sprintf( __( 'Stop these emails: %s', 'uaip-security-firewall' ), admin_url( 'admin.php?page=uaip-sfw-settings' ) );
		return implode( "\n", $out );
	}

	/** @return string[] Waiting updates, e.g. "3 plugins". */
	private function updates() {
		$out     = array();
		$core    = get_site_transient( 'update_core' );
		$plugins = get_site_transient( 'update_plugins' );
		$themes  = get_site_transient( 'update_themes' );
		if ( is_object( $core ) && ! empty( $core->updates ) && 'upgrade' === ( $core->updates[0]->response ?? '' ) ) {
			/* translators: %s: version */
			$out[] = sprintf( __( 'WordPress %s', 'uaip-security-firewall' ), $core->updates[0]->current );
		}
		$np = is_object( $plugins ) && ! empty( $plugins->response ) ? count( $plugins->response ) : 0;
		$nt = is_object( $themes ) && ! empty( $themes->response ) ? count( $themes->response ) : 0;
		if ( $np ) {
			/* translators: %d: count */
			$out[] = sprintf( _n( '%d plugin', '%d plugins', $np, 'uaip-security-firewall' ), $np );
		}
		if ( $nt ) {
			/* translators: %d: count */
			$out[] = sprintf( _n( '%d theme', '%d themes', $nt, 'uaip-security-firewall' ), $nt );
		}
		return $out;
	}
}
