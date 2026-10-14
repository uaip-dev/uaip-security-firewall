<?php
/**
 * Login protection (Free): brute-force lockouts, CAPTCHA challenge after
 * repeated failures, and compromised-password blocking.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Login_Guard {

	/** @var array<string,bool>|null Lazy-loaded common-password set. */
	private static $common;

	public function register_hooks() {
		if ( ! Uaip_Sfw_Settings::get( 'login_protection' ) ) {
			return;
		}
		add_filter( 'authenticate', array( $this, 'check_gate' ), 30, 3 );
		add_filter( 'wp_authenticate_user', array( $this, 'check_breached' ), 10, 2 );
		add_action( 'login_form', array( $this, 'captcha_field' ) );
		add_action( 'wp_login_failed', array( $this, 'on_failed_login' ) );
		add_action( 'wp_login', array( $this, 'on_success' ), 10, 1 );
	}

	// ------------------------------------------------------------------
	// Lockout + CAPTCHA gate
	// ------------------------------------------------------------------

	/**
	 * Gate authentication: hard lockout, then CAPTCHA requirement.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed|WP_Error
	 */
	public function check_gate( $user, $username, $password ) {
		if ( '' === (string) $username ) {
			return $user; // nothing being submitted
		}
		$ip   = $this->client_ip();
		$fail = (int) get_transient( $this->key( $ip ) );
		$cap  = (int) Uaip_Sfw_Settings::get( 'login_captcha_after', 3 );

		// Hard lockout well beyond the CAPTCHA threshold.
		if ( $fail >= $cap + 5 ) {
			return new WP_Error( 'uaip_sfw_locked', __( '<strong>Locked out.</strong> Too many failed attempts. Try again later.', 'uaip-security-firewall' ) );
		}

		// CAPTCHA required once failures reach the threshold. These reads happen
		// during wp_authenticate (the core login form), which carries no nonce —
		// this brute-force/CAPTCHA gate is itself the protection for that form.
		if ( $fail >= $cap ) {
			// phpcs:disable WordPress.Security.NonceVerification.Missing -- core login form has no nonce; this is the login guard.
			$token  = isset( $_POST['uaip_sfw_captcha_token'] ) ? sanitize_text_field( wp_unslash( $_POST['uaip_sfw_captcha_token'] ) ) : '';
			$answer = isset( $_POST['uaip_sfw_captcha'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['uaip_sfw_captcha'] ) ) ) : '';
			// phpcs:enable WordPress.Security.NonceVerification.Missing
			$expect = '' !== $token ? get_transient( 'uaip_sfw_cap_' . $token ) : false;

			if ( false === $expect || (string) $answer !== (string) $expect ) {
				return new WP_Error( 'uaip_sfw_captcha', __( '<strong>Verification needed.</strong> Please answer the security question correctly.', 'uaip-security-firewall' ) );
			}
			delete_transient( 'uaip_sfw_cap_' . $token );
		}
		return $user;
	}

	/**
	 * Render a simple math CAPTCHA on the login form when the IP is over the
	 * failure threshold. Self-contained — no external service.
	 */
	public function captcha_field() {
		$ip   = $this->client_ip();
		$fail = (int) get_transient( $this->key( $ip ) );
		$cap  = (int) Uaip_Sfw_Settings::get( 'login_captcha_after', 3 );
		if ( $fail < $cap ) {
			return;
		}
		$a     = wp_rand( 1, 9 );
		$b     = wp_rand( 1, 9 );
		$token = wp_generate_password( 16, false );
		set_transient( 'uaip_sfw_cap_' . $token, (string) ( $a + $b ), 10 * MINUTE_IN_SECONDS );

		echo '<p class="uaip-sfw-captcha"><label for="uaip_sfw_captcha">' .
			sprintf(
				/* translators: 1: first number, 2: second number */
				esc_html__( 'Security check: what is %1$d + %2$d?', 'uaip-security-firewall' ),
				(int) $a,
				(int) $b
			) . '</label>';
		echo '<input type="text" name="uaip_sfw_captcha" id="uaip_sfw_captcha" class="input" inputmode="numeric" autocomplete="off" />';
		echo '<input type="hidden" name="uaip_sfw_captcha_token" value="' . esc_attr( $token ) . '" /></p>';
	}

	// ------------------------------------------------------------------
	// Compromised-password blocking
	// ------------------------------------------------------------------

	/**
	 * Block sign-in for privileged users whose password is on the common /
	 * breached list. Forces them to reset to something stronger.
	 *
	 * @param WP_User|WP_Error $user
	 * @param string           $password
	 * @return WP_User|WP_Error
	 */
	public function check_breached( $user, $password ) {
		if ( ! ( $user instanceof WP_User ) || ! Uaip_Sfw_Settings::get( 'login_breached_pw' ) ) {
			return $user;
		}
		// Only enforce for users who can change site content/config.
		if ( ! user_can( $user, 'edit_posts' ) ) {
			return $user;
		}
		if ( $this->is_common_password( $password ) ) {
			$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
			if ( $audit ) {
				$audit->record( 'breached_password_block', array( 'user' => $user->ID ) );
			}
			return new WP_Error(
				'uaip_sfw_breached_pw',
				sprintf(
					/* translators: %s: lost password url */
					__( '<strong>Password change required.</strong> Your password appears on a list of compromised passwords. Please <a href="%s">reset it</a> before signing in.', 'uaip-security-firewall' ),
					esc_url( wp_lostpassword_url() )
				)
			);
		}
		return $user;
	}

	/**
	 * @param string $password
	 * @return bool
	 */
	private function is_common_password( $password ) {
		if ( '' === (string) $password ) {
			return false;
		}
		if ( null === self::$common ) {
			self::$common = array();
			$file = UAIP_SFW_DIR . 'assets/data/common-passwords.txt';
			$raw  = @file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
			if ( is_array( $raw ) ) {
				foreach ( $raw as $pw ) {
					self::$common[ $pw ] = true;
				}
			}
		}
		return isset( self::$common[ $password ] );
	}

	// ------------------------------------------------------------------
	// Failure tracking
	// ------------------------------------------------------------------

	public function on_failed_login() {
		$ip   = $this->client_ip();
		$fail = (int) get_transient( $this->key( $ip ) ) + 1;
		set_transient( $this->key( $ip ), $fail, 15 * MINUTE_IN_SECONDS );
		set_transient( 'uaip_sfw_failed_logins_15m', (int) get_transient( 'uaip_sfw_failed_logins_15m' ) + 1, 15 * MINUTE_IN_SECONDS );
	}

	/** @param string $user_login */
	public function on_success( $user_login ) {
		delete_transient( $this->key( $this->client_ip() ) );
	}

	private function key( $ip ) {
		return 'uaip_sfw_lf_' . md5( $ip );
	}

	private function client_ip() {
		return Uaip_Sfw_Settings::visitor_ip();
	}
}
