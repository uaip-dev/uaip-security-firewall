<?php
/**
 * Two-factor authentication — TOTP (Free).
 *
 * Per-user enrollment with recovery codes, enforced at login. Pro can require
 * 2FA per-role via the `uaip_sfw_2fa_required` filter.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Twofa {

	const META_SECRET   = 'uaip_sfw_2fa_secret';
	const META_ENABLED  = 'uaip_sfw_2fa_enabled';
	const META_PENDING  = 'uaip_sfw_2fa_pending';
	const META_RECOVERY = 'uaip_sfw_2fa_recovery';

	public function register_hooks() {
		// Login enforcement is always wired; it only acts on enrolled users.
		add_filter( 'wp_authenticate_user', array( $this, 'enforce_login' ), 30, 2 );
		add_action( 'login_form', array( $this, 'login_field' ) );
		// Application Passwords authenticate over REST/Basic auth WITHOUT going
		// through wp_authenticate_user, so they would bypass the second factor.
		// Disable them for enrolled users (also blocks authenticating with any
		// already-issued application password).
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'block_app_passwords' ), 10, 2 );
	}

	// ------------------------------------------------------------------
	// State
	// ------------------------------------------------------------------

	/** @return bool */
	public function is_enabled( $user_id ) {
		return '1' === get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/** @return string Base32 secret of the active enrollment (decrypted). */
	public function secret( $user_id ) {
		return Uaip_Sfw_Crypto::decrypt( get_user_meta( $user_id, self::META_SECRET, true ) );
	}

	/**
	 * Whether 2FA is required for a user (Pro can force by role).
	 *
	 * @param WP_User $user
	 * @return bool
	 */
	public function required_for( $user ) {
		return (bool) apply_filters( 'uaip_sfw_2fa_required', false, $user );
	}

	// ------------------------------------------------------------------
	// Enrollment
	// ------------------------------------------------------------------

	/**
	 * Begin setup: create (or reuse) a pending secret for this user.
	 *
	 * @param int $user_id
	 * @return string Base32 pending secret.
	 */
	public function start_setup( $user_id ) {
		$pending = $this->pending_secret( $user_id );
		if ( '' === $pending ) {
			$pending = Uaip_Sfw_TOTP::generate_secret();
			update_user_meta( $user_id, self::META_PENDING, Uaip_Sfw_Crypto::encrypt( $pending ) );
		}
		return $pending;
	}

	/** @return string Decrypted pending secret. */
	public function pending_secret( $user_id ) {
		return Uaip_Sfw_Crypto::decrypt( get_user_meta( $user_id, self::META_PENDING, true ) );
	}

	/**
	 * Generate a fresh pending secret (used on each new visit to the setup
	 * screen so the QR/key are randomized on refresh).
	 *
	 * @param int $user_id
	 * @return string New Base32 secret.
	 */
	public function rotate_setup( $user_id ) {
		$secret = Uaip_Sfw_TOTP::generate_secret();
		update_user_meta( $user_id, self::META_PENDING, Uaip_Sfw_Crypto::encrypt( $secret ) );
		return $secret;
	}

	/**
	 * Confirm setup with a code. On success, activate 2FA and return fresh
	 * recovery codes (shown once).
	 *
	 * @param int    $user_id
	 * @param string $code
	 * @return array|WP_Error Recovery codes on success.
	 */
	public function confirm_setup( $user_id, $code ) {
		$pending = $this->pending_secret( $user_id );
		if ( '' === $pending ) {
			return new WP_Error( 'no_pending', __( 'Start the setup again.', 'uaip-security-firewall' ) );
		}
		if ( ! Uaip_Sfw_TOTP::verify( $pending, $code ) ) {
			return new WP_Error( 'bad_code', __( 'That code is not correct. Check your authenticator app and try again.', 'uaip-security-firewall' ) );
		}
		update_user_meta( $user_id, self::META_SECRET, Uaip_Sfw_Crypto::encrypt( $pending ) );
		update_user_meta( $user_id, self::META_ENABLED, '1' );
		delete_user_meta( $user_id, self::META_PENDING );

		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'twofa_enabled', array( 'user' => $user_id ) );
		}
		return $this->regenerate_recovery( $user_id );
	}

	/**
	 * Disable 2FA for a user.
	 *
	 * @param int $user_id
	 */
	public function disable( $user_id ) {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_RECOVERY );
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'twofa_disabled', array( 'user' => $user_id ) );
		}
	}

	/**
	 * Generate and store fresh recovery codes (stored hashed). Returns the
	 * plaintext codes so they can be shown to the user once.
	 *
	 * @param int $user_id
	 * @return array<int,string>
	 */
	public function regenerate_recovery( $user_id ) {
		$plain  = array();
		$hashed = array();
		for ( $i = 0; $i < 8; $i++ ) {
			$code     = sprintf( '%s-%s', $this->random_block(), $this->random_block() );
			$plain[]  = $code;
			$hashed[] = hash( 'sha256', $code );
		}
		update_user_meta( $user_id, self::META_RECOVERY, $hashed );
		return $plain;
	}

	/** @return int Count of remaining unused recovery codes. */
	public function recovery_remaining( $user_id ) {
		$codes = get_user_meta( $user_id, self::META_RECOVERY, true );
		return is_array( $codes ) ? count( $codes ) : 0;
	}

	/** @return string A 5-char A-Z0-9 block. */
	private function random_block() {
		$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
		$out   = '';
		for ( $i = 0; $i < 5; $i++ ) {
			$out .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}
		return $out;
	}

	/**
	 * Consume a recovery code if it matches; returns true on success.
	 *
	 * @param int    $user_id
	 * @param string $input
	 * @return bool
	 */
	private function consume_recovery( $user_id, $input ) {
		$input  = strtoupper( trim( $input ) );
		$hash   = hash( 'sha256', $input );
		$codes  = get_user_meta( $user_id, self::META_RECOVERY, true );
		$codes  = is_array( $codes ) ? $codes : array();
		$index  = array_search( $hash, $codes, true );
		if ( false === $index ) {
			return false;
		}
		unset( $codes[ $index ] );
		update_user_meta( $user_id, self::META_RECOVERY, array_values( $codes ) );
		return true;
	}

	// ------------------------------------------------------------------
	// Login enforcement
	// ------------------------------------------------------------------

	/**
	 * After a valid username/password, require the second factor for enrolled
	 * users. Accepts a TOTP code or a recovery code.
	 *
	 * @param WP_User|WP_Error $user
	 * @param string           $password
	 * @return WP_User|WP_Error
	 */
	public function enforce_login( $user, $password ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}
		if ( ! $this->is_enabled( $user->ID ) ) {
			return $user;
		}

		// Read during wp_authenticate (core login flow) — that form has no nonce;
		// the TOTP code itself is the second factor being verified here.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core login form has no nonce; the code is the second factor.
		$input = isset( $_POST['uaip_sfw_totp'] ) ? sanitize_text_field( wp_unslash( $_POST['uaip_sfw_totp'] ) ) : '';
		if ( '' === $input ) {
			return new WP_Error(
				'uaip_sfw_2fa_required',
				__( '<strong>Two-factor required.</strong> Enter the 6-digit code from your authenticator app.', 'uaip-security-firewall' )
			);
		}

		// TOTP first, then recovery code.
		if ( Uaip_Sfw_TOTP::verify( $this->secret( $user->ID ), $input ) ) {
			return $user;
		}
		if ( $this->consume_recovery( $user->ID, $input ) ) {
			return $user;
		}

		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'twofa_failed', array( 'user' => $user->ID ) );
		}
		return new WP_Error(
			'uaip_sfw_2fa_invalid',
			__( '<strong>Invalid code.</strong> Try the current code from your app, or a recovery code.', 'uaip-security-firewall' )
		);
	}

	/**
	 * Disable Application Passwords for users who have 2FA enabled, so the
	 * second factor cannot be bypassed via REST/Basic-auth. Overridable via the
	 * `uaip_sfw_block_app_passwords` filter for advanced setups.
	 *
	 * @param bool    $available
	 * @param WP_User $user
	 * @return bool
	 */
	public function block_app_passwords( $available, $user ) {
		if ( $user instanceof WP_User && $this->is_enabled( $user->ID )
			&& apply_filters( 'uaip_sfw_block_app_passwords', true, $user ) ) {
			return false;
		}
		return $available;
	}

	/**
	 * Render the 2FA input on the login form.
	 */
	public function login_field() {
		echo '<p class="uaip-sfw-2fa-field"><label for="uaip_sfw_totp">' .
			esc_html__( 'Authentication code', 'uaip-security-firewall' ) .
			' <span style="font-weight:400;color:#646970;">(' . esc_html__( 'if enabled', 'uaip-security-firewall' ) . ')</span></label>' .
			'<input type="text" name="uaip_sfw_totp" id="uaip_sfw_totp" class="input" value="" size="20" autocomplete="one-time-code" inputmode="numeric" placeholder="123456" /></p>';
	}
}
