<?php
/**
 * Two-factor authentication (Free): authenticator apps (TOTP), passkeys
 * (WebAuthn), email codes and recovery codes.
 *
 * Sign-in is two steps. WordPress checks the password as usual; for users with
 * a second factor the session WordPress just created is cancelled and a
 * separate "second step" screen is shown, linked to the first step by a
 * short-lived one-time token. XML-RPC logins and application passwords, which
 * cannot show that screen, are refused for these users.
 *
 * Site owners can require two-factor for roles; required users who have not
 * set anything up get email codes automatically.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Twofa {

	const META_SECRET    = 'uaip_sfw_2fa_secret';
	const META_ENABLED   = 'uaip_sfw_2fa_enabled';
	const META_PENDING   = 'uaip_sfw_2fa_pending';
	const META_RECOVERY  = 'uaip_sfw_2fa_recovery';
	const META_LAST_STEP = 'uaip_sfw_2fa_last_step';
	const META_EMAIL     = 'uaip_sfw_2fa_email';
	const META_PASSKEYS  = 'uaip_sfw_passkeys';
	const META_HANDLE    = 'uaip_sfw_passkey_handle';
	const META_LOGIN     = 'uaip_sfw_2fa_login';
	const META_REG       = 'uaip_sfw_passkey_reg';

	/** Second-step tokens expire after this many seconds. */
	const STEP_TTL = 600;

	/** Wrong second-step attempts before the step is cancelled. */
	const MAX_ATTEMPTS = 5;

	/** Email codes sent per sign-in attempt. */
	const MAX_EMAILS = 3;

	/** @var string Session token set during this request (cancelled for 2FA users). */
	private $new_session = '';

	/** @var bool True while finishing a successful second step. */
	private $completing = false;

	public function register_hooks() {
		add_action( 'set_logged_in_cookie', array( $this, 'capture_session' ), 10, 6 );
		add_action( 'wp_login', array( $this, 'intercept_login' ), 1, 2 );
		add_action( 'login_form_uaip_sfw_2fa', array( $this, 'handle_step' ) );
		add_filter( 'login_message', array( $this, 'login_message' ) );
		add_filter( 'authenticate', array( $this, 'block_xmlrpc' ), 100 );
		// Application Passwords authenticate over REST/Basic auth without a login
		// screen, so they would skip the second factor. Disable them for these
		// users (this also refuses already-issued application passwords).
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'block_app_passwords' ), 10, 2 );
		add_action( 'wp_ajax_uaip_sfw_passkey_options', array( $this, 'ajax_passkey_options' ) );
		add_action( 'wp_ajax_uaip_sfw_passkey_register', array( $this, 'ajax_passkey_register' ) );
	}

	// ------------------------------------------------------------------
	// What a user has
	// ------------------------------------------------------------------

	/** @return bool Authenticator app active. */
	public function is_enabled( $user_id ) {
		return '1' === get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/** @return string Decrypted TOTP secret. */
	public function secret( $user_id ) {
		return Uaip_Sfw_Crypto::decrypt( get_user_meta( $user_id, self::META_SECRET, true ) );
	}

	/** @return array<string,array> Passkeys keyed by credential id. */
	public function passkeys( $user_id ) {
		$keys = get_user_meta( $user_id, self::META_PASSKEYS, true );
		return is_array( $keys ) ? $keys : array();
	}

	/** @return bool Email codes switched on by the user (or required). */
	public function email_enabled( $user_id ) {
		if ( ! Uaip_Sfw_Settings::get( 'twofa_email' ) ) {
			return false;
		}
		return '1' === get_user_meta( $user_id, self::META_EMAIL, true );
	}

	/**
	 * Whether the site requires two-factor for this user's role.
	 *
	 * @param WP_User $user User.
	 * @return bool
	 */
	public function required_for( $user ) {
		$roles    = (array) Uaip_Sfw_Settings::get( 'twofa_required_roles', array() );
		$required = $user instanceof WP_User && array_intersect( (array) $user->roles, $roles );
		/**
		 * Filters whether two-factor is required for a user.
		 *
		 * @param bool    $required Required.
		 * @param WP_User $user     User.
		 */
		return (bool) apply_filters( 'uaip_sfw_2fa_required', (bool) $required, $user );
	}

	/**
	 * Second-step methods available to a user.
	 *
	 * @param WP_User $user User.
	 * @return array{totp:bool,passkey:bool,email:bool}
	 */
	public function methods( $user ) {
		$uid     = $user->ID;
		$totp    = $this->is_enabled( $uid );
		$passkey = Uaip_Sfw_Settings::get( 'twofa_passkeys' ) && (bool) $this->passkeys( $uid );
		$email   = $this->email_enabled( $uid );
		// A required user with nothing set up gets email codes, so the
		// requirement works without any setup.
		if ( ! $totp && ! $passkey && ! $email && $this->required_for( $user ) ) {
			$email = true;
		}
		return array(
			'totp'    => $totp,
			'passkey' => $passkey,
			'email'   => $email,
		);
	}

	/**
	 * @param WP_User $user User.
	 * @return bool Whether sign-in needs a second step.
	 */
	public function needs_second_step( $user ) {
		return $user instanceof WP_User && in_array( true, $this->methods( $user ), true );
	}

	// ------------------------------------------------------------------
	// Sign-in: step 2
	// ------------------------------------------------------------------

	/**
	 * Remember the session token WordPress creates on login, so it can be
	 * cancelled when a second step is needed.
	 *
	 * @param string $cookie     Cookie.
	 * @param int    $expire     Expire.
	 * @param int    $expiration Expiration.
	 * @param int    $user_id    User.
	 * @param string $scheme     Scheme.
	 * @param string $token      Session token.
	 */
	public function capture_session( $cookie, $expire, $expiration, $user_id, $scheme, $token ) {
		$this->new_session = (string) $token;
	}

	/**
	 * After a correct password: cancel the session and ask for the second step.
	 *
	 * @param string  $login User login.
	 * @param WP_User $user  User.
	 */
	public function intercept_login( $login, $user ) {
		if ( $this->completing || ! $this->needs_second_step( $user ) ) {
			return;
		}
		if ( '' !== $this->new_session ) {
			WP_Session_Tokens::get_instance( $user->ID )->destroy( $this->new_session );
		}
		wp_clear_auth_cookie();

		// phpcs:disable WordPress.Security.NonceVerification -- this runs inside the core login request; the password was just verified.
		$remember = ! empty( $_POST['rememberme'] );
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification
		$token = $this->start_step( $user->ID, $remember, $redirect );

		if ( function_exists( 'login_header' ) ) {
			$this->render_step( $user, $token );
		} else {
			// Logged in through another form (e.g. a shop account page).
			wp_safe_redirect( $this->step_url( $user->ID, $token ) );
		}
		exit;
	}

	/**
	 * Create the second-step state.
	 *
	 * @param int    $user_id  User.
	 * @param bool   $remember Remember me.
	 * @param string $redirect Requested redirect.
	 * @return string Token (plain).
	 */
	private function start_step( $user_id, $remember, $redirect ) {
		$token = wp_generate_password( 40, false );
		update_user_meta(
			$user_id,
			self::META_LOGIN,
			array(
				'hash'      => hash( 'sha256', $token ),
				'expires'   => time() + self::STEP_TTL,
				'remember'  => (bool) $remember,
				'redirect'  => $redirect,
				'attempts'  => 0,
				'emails'    => 0,
				'email'     => '',
				'email_exp' => 0,
				'challenge' => '',
			)
		);
		return $token;
	}

	/**
	 * Valid second-step state for this user and token, or null.
	 *
	 * @param int    $user_id User.
	 * @param string $token   Token.
	 * @return array|null
	 */
	private function step_state( $user_id, $token ) {
		$state = get_user_meta( $user_id, self::META_LOGIN, true );
		if ( ! is_array( $state ) || empty( $state['hash'] ) || (int) $state['expires'] < time() ) {
			return null;
		}
		return hash_equals( $state['hash'], hash( 'sha256', (string) $token ) ) ? $state : null;
	}

	/**
	 * @param int    $user_id User.
	 * @param string $token   Token.
	 * @return string
	 */
	private function step_url( $user_id, $token ) {
		return add_query_arg(
			array(
				'action' => 'uaip_sfw_2fa',
				'uid'    => (int) $user_id,
				'token'  => rawurlencode( $token ),
			),
			wp_login_url()
		);
	}

	/**
	 * wp-login.php?action=uaip_sfw_2fa — show or check the second step.
	 */
	public function handle_step() {
		// phpcs:disable WordPress.Security.NonceVerification -- the one-time step token (bound to the user, hashed, expiring) is the CSRF protection here.
		$uid   = isset( $_REQUEST['uid'] ) ? absint( wp_unslash( $_REQUEST['uid'] ) ) : 0;
		$token = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		$user  = $uid ? get_userdata( $uid ) : false;
		$state = $user ? $this->step_state( $uid, $token ) : null;
		if ( ! $user || ! $state ) {
			wp_safe_redirect( add_query_arg( 'uaip_sfw_2fa', 'expired', wp_login_url() ) );
			exit;
		}
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET' ) ) {
			$this->render_step( $user, $token );
			exit;
		}
		$methods = $this->methods( $user );

		if ( ! empty( $_POST['uaip_sfw_send_email'] ) && $methods['email'] ) {
			$sent = $this->send_email_code( $user, $state );
			if ( 'sent' === $sent ) {
				$this->render_step( $user, $token, '', __( 'We emailed you a sign-in code.', 'uaip-security-firewall' ) );
			} elseif ( 'limit' === $sent ) {
				$this->render_step( $user, $token, __( 'No more codes can be sent for this sign-in. Start again in a few minutes.', 'uaip-security-firewall' ) );
			} else {
				$this->render_step( $user, $token, __( 'The email could not be sent. Use another method, or ask the site administrator to check that the site can send email.', 'uaip-security-firewall' ) );
			}
			exit;
		}

		$ok = false;
		if ( ! empty( $_POST['uaip_sfw_wa_auth'] ) && $methods['passkey'] ) {
			$ok = $this->check_passkey(
				$user,
				$state,
				sanitize_text_field( wp_unslash( isset( $_POST['uaip_sfw_wa_id'] ) ? $_POST['uaip_sfw_wa_id'] : '' ) ),
				sanitize_text_field( wp_unslash( isset( $_POST['uaip_sfw_wa_client'] ) ? $_POST['uaip_sfw_wa_client'] : '' ) ),
				sanitize_text_field( wp_unslash( $_POST['uaip_sfw_wa_auth'] ) ),
				sanitize_text_field( wp_unslash( isset( $_POST['uaip_sfw_wa_sig'] ) ? $_POST['uaip_sfw_wa_sig'] : '' ) )
			);
		} elseif ( isset( $_POST['uaip_sfw_code'] ) ) {
			$ok = $this->check_code( $user, $state, sanitize_text_field( wp_unslash( $_POST['uaip_sfw_code'] ) ), $methods );
		}
		// phpcs:enable WordPress.Security.NonceVerification

		if ( $ok ) {
			$this->complete( $user, $state );
		}

		$state = get_user_meta( $uid, self::META_LOGIN, true );
		$state['attempts'] = (int) $state['attempts'] + 1;
		update_user_meta( $uid, self::META_LOGIN, $state );
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'twofa_failed', array( 'user' => $uid ) );
		}
		// Counts toward the IP lockout like a wrong password.
		do_action( 'wp_login_failed', $user->user_login, new WP_Error( 'uaip_sfw_2fa_invalid' ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired so lockout plugins see the failure.
		if ( $state['attempts'] >= self::MAX_ATTEMPTS ) {
			delete_user_meta( $uid, self::META_LOGIN );
			wp_safe_redirect( add_query_arg( 'uaip_sfw_2fa', 'locked', wp_login_url() ) );
			exit;
		}
		$this->render_step( $user, $token, __( 'That did not work. Check the code and try again.', 'uaip-security-firewall' ) );
		exit;
	}

	/**
	 * Check a 6-digit app code, an emailed code or a recovery code.
	 *
	 * @param WP_User $user    User.
	 * @param array   $state   Step state.
	 * @param string  $input   Input.
	 * @param array   $methods Methods.
	 * @return bool
	 */
	private function check_code( $user, array $state, $input, array $methods ) {
		$digits = preg_replace( '/\D/', '', $input );
		if ( $methods['totp'] && 6 === strlen( $digits ) ) {
			$step = Uaip_Sfw_TOTP::verify_step( $this->secret( $user->ID ), $digits );
			// Each code works once: refuse the step that was already used.
			if ( false !== $step && $step > (int) get_user_meta( $user->ID, self::META_LAST_STEP, true ) ) {
				update_user_meta( $user->ID, self::META_LAST_STEP, $step );
				return true;
			}
		}
		if ( $methods['email'] && 6 === strlen( $digits ) && '' !== $state['email'] && (int) $state['email_exp'] >= time()
			&& hash_equals( $state['email'], hash( 'sha256', $digits . '|' . $state['hash'] ) ) ) {
			return true;
		}
		return $this->consume_recovery( $user->ID, $input );
	}

	/**
	 * Check a passkey assertion.
	 *
	 * @param WP_User $user   User.
	 * @param array   $state  Step state.
	 * @param string  $id     Credential id (base64url).
	 * @param string  $client clientDataJSON (base64url).
	 * @param string  $auth   authenticatorData (base64url).
	 * @param string  $sig    Signature (base64url).
	 * @return bool
	 */
	private function check_passkey( $user, array $state, $id, $client, $auth, $sig ) {
		$keys = $this->passkeys( $user->ID );
		if ( '' === $state['challenge'] || ! isset( $keys[ $id ] ) ) {
			return false;
		}
		$res = Uaip_Sfw_WebAuthn::for_site()->verify_assertion( $client, $auth, $sig, $state['challenge'], $keys[ $id ] );
		if ( is_wp_error( $res ) ) {
			return false;
		}
		$keys[ $id ]['sign_count'] = $res['sign_count'];
		$keys[ $id ]['last_used']  = time();
		update_user_meta( $user->ID, self::META_PASSKEYS, $keys );
		return true;
	}

	/**
	 * Email a sign-in code (limited per sign-in).
	 *
	 * @param WP_User $user  User.
	 * @param array   $state Step state.
	 * @return string 'sent', 'limit' or 'failed'.
	 */
	private function send_email_code( $user, array $state ) {
		if ( (int) $state['emails'] >= self::MAX_EMAILS ) {
			return 'limit';
		}
		$code               = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		$state['email']     = hash( 'sha256', $code . '|' . $state['hash'] );
		$state['email_exp'] = time() + self::STEP_TTL;
		$state['emails']    = (int) $state['emails'] + 1;
		update_user_meta( $user->ID, self::META_LOGIN, $state );

		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name */
		$subject = sprintf( __( '[%s] Your sign-in code', 'uaip-security-firewall' ), $site );
		$body    = sprintf(
			/* translators: 1: sign-in code, 2: site name */
			__( "Your sign-in code is: %1\$s\n\nIt works for 10 minutes. If you did not just try to sign in to %2\$s, someone knows your password: change it now.", 'uaip-security-firewall' ),
			$code,
			$site
		);
		return wp_mail( $user->user_email, $subject, $body ) ? 'sent' : 'failed';
	}

	/**
	 * Finish sign-in after a correct second step.
	 *
	 * @param WP_User $user  User.
	 * @param array   $state Step state.
	 */
	private function complete( $user, array $state ) {
		delete_user_meta( $user->ID, self::META_LOGIN );
		$this->completing = true;
		wp_set_auth_cookie( $user->ID, ! empty( $state['remember'] ) );
		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, completes the sign-in held back for the second step.

		$requested = (string) $state['redirect'];
		$redirect  = '' !== $requested ? $requested : admin_url();
		/** This filter is documented in wp-login.php */
		$redirect = apply_filters( 'login_redirect', $redirect, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, same as wp-login.php.
		wp_safe_redirect( $redirect ? $redirect : admin_url() );
		exit;
	}

	/**
	 * The second-step screen.
	 *
	 * @param WP_User $user    User.
	 * @param string  $token   Token.
	 * @param string  $error   Error message.
	 * @param string  $notice  Info message.
	 */
	private function render_step( $user, $token, $error = '', $notice = '' ) {
		$methods = $this->methods( $user );
		$state   = get_user_meta( $user->ID, self::META_LOGIN, true );
		$options = '';
		if ( $methods['passkey'] && is_array( $state ) ) {
			$state['challenge'] = Uaip_Sfw_WebAuthn::challenge();
			update_user_meta( $user->ID, self::META_LOGIN, $state );
			$options = (string) wp_json_encode(
				array(
					'challenge' => $state['challenge'],
					'rpId'      => Uaip_Sfw_WebAuthn::for_site()->rp_id(),
					'allow'     => array_keys( $this->passkeys( $user->ID ) ),
					'error'     => __( 'The passkey could not be used. Try again or enter a code.', 'uaip-security-firewall' ),
				)
			);
			wp_enqueue_script( 'uaip-sfw-passkeys', UAIP_SFW_URL . 'assets/js/passkeys.js', array(), UAIP_SFW_VERSION, true );
		}
		wp_enqueue_style( 'uaip-sfw-login', UAIP_SFW_URL . 'assets/css/login.css', array( 'login' ), UAIP_SFW_VERSION );

		$errors = new WP_Error();
		if ( '' !== $error ) {
			$errors->add( 'uaip_sfw_2fa', $error );
		}
		if ( '' !== $notice ) {
			$errors->add( 'uaip_sfw_2fa_notice', $notice, 'message' );
		}
		login_header( __( 'Two-step verification', 'uaip-security-firewall' ), '', $errors );

		echo '<form name="uaip_sfw_2fa" id="uaip-sfw-2fa" class="uaip-sfw-2fa" action="' . esc_url( add_query_arg( 'action', 'uaip_sfw_2fa', wp_login_url() ) ) . '" method="post">';
		echo '<input type="hidden" name="uid" value="' . (int) $user->ID . '">';
		echo '<input type="hidden" name="token" value="' . esc_attr( $token ) . '">';
		echo '<p class="uaip-sfw-2fa-intro">' . esc_html__( 'Your password was accepted. Confirm it is you to finish signing in.', 'uaip-security-firewall' ) . '</p>';

		if ( $methods['passkey'] ) {
			echo '<div class="uaip-sfw-2fa-passkey">';
			echo '<input type="hidden" name="uaip_sfw_wa_id" value=""><input type="hidden" name="uaip_sfw_wa_client" value=""><input type="hidden" name="uaip_sfw_wa_auth" value=""><input type="hidden" name="uaip_sfw_wa_sig" value="">';
			echo '<button type="button" class="button button-primary button-large" id="uaip-sfw-passkey-login" data-options="' . esc_attr( $options ) . '">' . esc_html__( 'Use a passkey', 'uaip-security-firewall' ) . '</button>';
			echo '<p class="uaip-sfw-2fa-or"><span>' . esc_html__( 'or', 'uaip-security-firewall' ) . '</span></p></div>';
		}

		$label = $methods['totp']
			? __( 'Code from your authenticator app', 'uaip-security-firewall' )
			: ( $methods['email'] ? __( 'Code from the email we send you', 'uaip-security-firewall' ) : __( 'Recovery code', 'uaip-security-firewall' ) );
		echo '<p><label for="uaip_sfw_code">' . esc_html( $label ) . '</label>';
		echo '<input type="text" name="uaip_sfw_code" id="uaip_sfw_code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="numeric" autocapitalize="off" spellcheck="false" ' . ( $methods['passkey'] ? '' : 'autofocus' ) . '></p>';
		echo '<p class="submit"><button type="submit" class="button button-primary button-large">' . esc_html__( 'Verify', 'uaip-security-firewall' ) . '</button></p>';

		if ( $methods['email'] ) {
			echo '<p class="uaip-sfw-2fa-email"><button type="submit" name="uaip_sfw_send_email" value="1" class="button-link" formnovalidate>' . esc_html( $methods['totp'] ? __( 'Email me a code instead', 'uaip-security-firewall' ) : __( 'Email me a code', 'uaip-security-firewall' ) ) . '</button></p>';
		}
		echo '<p class="uaip-sfw-2fa-help">' . esc_html__( 'Lost your device? Enter one of your recovery codes in the box above.', 'uaip-security-firewall' ) . '</p>';
		echo '</form>';
		login_footer();
	}

	/**
	 * Messages on the normal login screen after an expired or locked second step.
	 *
	 * @param string $message Message.
	 * @return string
	 */
	public function login_message( $message ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		$state = isset( $_GET['uaip_sfw_2fa'] ) ? sanitize_key( wp_unslash( $_GET['uaip_sfw_2fa'] ) ) : '';
		if ( 'expired' === $state ) {
			$message .= '<div id="login_error" class="notice notice-error"><p>' . esc_html__( 'That sign-in link expired. Please sign in again.', 'uaip-security-firewall' ) . '</p></div>';
		} elseif ( 'locked' === $state ) {
			$message .= '<div id="login_error" class="notice notice-error"><p>' . esc_html__( 'Too many wrong codes. Please sign in again.', 'uaip-security-firewall' ) . '</p></div>';
		}
		return $message;
	}

	/**
	 * XML-RPC cannot show a second step: refuse it for these users.
	 *
	 * @param WP_User|WP_Error|null $user User.
	 * @return WP_User|WP_Error|null
	 */
	public function block_xmlrpc( $user ) {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $user instanceof WP_User && $this->needs_second_step( $user ) ) {
			return new WP_Error( 'uaip_sfw_2fa_xmlrpc', __( 'This account uses two-step verification, which XML-RPC does not support.', 'uaip-security-firewall' ) );
		}
		return $user;
	}

	/**
	 * @param bool    $available Available.
	 * @param WP_User $user      User.
	 * @return bool
	 */
	public function block_app_passwords( $available, $user ) {
		if ( $user instanceof WP_User && $this->needs_second_step( $user )
			&& apply_filters( 'uaip_sfw_block_app_passwords', true, $user ) ) {
			return false;
		}
		return $available;
	}

	// ------------------------------------------------------------------
	// Enrolment: authenticator app
	// ------------------------------------------------------------------

	/** @return string Decrypted pending secret. */
	public function pending_secret( $user_id ) {
		return Uaip_Sfw_Crypto::decrypt( get_user_meta( $user_id, self::META_PENDING, true ) );
	}

	/**
	 * New pending secret for the setup screen.
	 *
	 * @param int $user_id User.
	 * @return string Base32 secret.
	 */
	public function rotate_setup( $user_id ) {
		$secret = Uaip_Sfw_TOTP::generate_secret();
		update_user_meta( $user_id, self::META_PENDING, Uaip_Sfw_Crypto::encrypt( $secret ) );
		return $secret;
	}

	/**
	 * Confirm the app with a code.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 * @return true|WP_Error
	 */
	public function confirm_setup( $user_id, $code ) {
		$pending = $this->pending_secret( $user_id );
		if ( '' === $pending ) {
			return new WP_Error( 'no_pending', __( 'Start the setup again.', 'uaip-security-firewall' ) );
		}
		$step = Uaip_Sfw_TOTP::verify_step( $pending, $code );
		if ( false === $step ) {
			return new WP_Error( 'bad_code', __( 'That code is not correct. Check your authenticator app and try again.', 'uaip-security-firewall' ) );
		}
		update_user_meta( $user_id, self::META_SECRET, Uaip_Sfw_Crypto::encrypt( $pending ) );
		update_user_meta( $user_id, self::META_ENABLED, '1' );
		update_user_meta( $user_id, self::META_LAST_STEP, $step );
		delete_user_meta( $user_id, self::META_PENDING );
		$this->audit( 'twofa_enabled', $user_id, 'app' );
		return true;
	}

	/**
	 * Remove every method and recovery code (an administrator helping a
	 * locked-out user). Required roles fall back to email codes.
	 *
	 * @param int $user_id User.
	 */
	public function reset_user( $user_id ) {
		foreach ( array( self::META_SECRET, self::META_ENABLED, self::META_PENDING, self::META_LAST_STEP, self::META_EMAIL, self::META_PASSKEYS, self::META_RECOVERY, self::META_LOGIN, self::META_REG ) as $key ) {
			delete_user_meta( $user_id, $key );
		}
		$this->audit( 'twofa_disabled', $user_id, 'all (reset by an administrator)' );
	}

	/**
	 * Remove the authenticator app.
	 *
	 * @param int $user_id User.
	 */
	public function remove_app( $user_id ) {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_LAST_STEP );
		$this->audit( 'twofa_disabled', $user_id, 'app' );
	}

	/**
	 * Switch email codes on or off.
	 *
	 * @param int  $user_id User.
	 * @param bool $on      On.
	 */
	public function set_email( $user_id, $on ) {
		if ( $on ) {
			update_user_meta( $user_id, self::META_EMAIL, '1' );
			$this->audit( 'twofa_enabled', $user_id, 'email' );
		} else {
			delete_user_meta( $user_id, self::META_EMAIL );
			$this->audit( 'twofa_disabled', $user_id, 'email' );
		}
	}

	// ------------------------------------------------------------------
	// Enrolment: passkeys
	// ------------------------------------------------------------------

	/**
	 * AJAX: creation options for a new passkey (current user).
	 */
	public function ajax_passkey_options() {
		check_ajax_referer( 'uaip_sfw_passkey' );
		$user = wp_get_current_user();
		if ( ! $user->exists() || ! Uaip_Sfw_Settings::get( 'twofa_passkeys' ) ) {
			wp_send_json_error( null, 403 );
		}
		$handle = (string) get_user_meta( $user->ID, self::META_HANDLE, true );
		if ( '' === $handle ) {
			$handle = Uaip_Sfw_WebAuthn::b64url_encode( random_bytes( 32 ) );
			update_user_meta( $user->ID, self::META_HANDLE, $handle );
		}
		$challenge = Uaip_Sfw_WebAuthn::challenge();
		update_user_meta(
			$user->ID,
			self::META_REG,
			array(
				'challenge' => $challenge,
				'expires'   => time() + 300,
			)
		);
		wp_send_json_success(
			array(
				'challenge' => $challenge,
				'rp'        => array(
					'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
					'id'   => Uaip_Sfw_WebAuthn::for_site()->rp_id(),
				),
				'user'      => array(
					'id'          => $handle,
					'name'        => $user->user_login,
					'displayName' => $user->display_name,
				),
				'exclude'   => array_keys( $this->passkeys( $user->ID ) ), // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- WebAuthn option, not a query.
			)
		);
	}

	/**
	 * AJAX: verify and save a new passkey (current user).
	 */
	public function ajax_passkey_register() {
		check_ajax_referer( 'uaip_sfw_passkey' );
		$user = wp_get_current_user();
		$reg  = get_user_meta( $user->ID, self::META_REG, true );
		delete_user_meta( $user->ID, self::META_REG );
		if ( ! $user->exists() || ! is_array( $reg ) || (int) $reg['expires'] < time() ) {
			wp_send_json_error( array( 'message' => __( 'The request expired. Please try again.', 'uaip-security-firewall' ) ) );
		}
		$client = isset( $_POST['client'] ) ? sanitize_text_field( wp_unslash( $_POST['client'] ) ) : '';
		$att    = isset( $_POST['attestation'] ) ? sanitize_text_field( wp_unslash( $_POST['attestation'] ) ) : '';
		$name   = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
		$res    = Uaip_Sfw_WebAuthn::for_site()->verify_registration( $client, $att, $reg['challenge'] );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error( array( 'message' => $res->get_error_message() ) );
		}
		$keys = $this->passkeys( $user->ID );
		if ( isset( $keys[ $res['id'] ] ) ) {
			wp_send_json_error( array( 'message' => __( 'This passkey is already registered.', 'uaip-security-firewall' ) ) );
		}
		$keys[ $res['id'] ] = array(
			'name'       => '' !== $name ? substr( $name, 0, 60 ) : __( 'Passkey', 'uaip-security-firewall' ),
			'public_key' => $res['public_key'],
			'alg'        => $res['alg'],
			'sign_count' => $res['sign_count'],
			'created'    => time(),
			'last_used'  => 0,
		);
		update_user_meta( $user->ID, self::META_PASSKEYS, $keys );
		$this->audit( 'twofa_enabled', $user->ID, 'passkey' );
		wp_send_json_success();
	}

	/**
	 * Remove a passkey.
	 *
	 * @param int    $user_id User.
	 * @param string $id      Credential id.
	 */
	public function remove_passkey( $user_id, $id ) {
		$keys = $this->passkeys( $user_id );
		if ( isset( $keys[ $id ] ) ) {
			unset( $keys[ $id ] );
			update_user_meta( $user_id, self::META_PASSKEYS, $keys );
			$this->audit( 'twofa_disabled', $user_id, 'passkey' );
		}
	}

	// ------------------------------------------------------------------
	// Recovery codes
	// ------------------------------------------------------------------

	/**
	 * Fresh recovery codes (stored hashed); returns the plain codes once.
	 *
	 * @param int $user_id User.
	 * @return string[]
	 */
	public function regenerate_recovery( $user_id ) {
		$plain  = array();
		$hashed = array();
		for ( $i = 0; $i < 8; $i++ ) {
			$code     = $this->random_block() . '-' . $this->random_block();
			$plain[]  = $code;
			$hashed[] = hash( 'sha256', $code );
		}
		update_user_meta( $user_id, self::META_RECOVERY, $hashed );
		return $plain;
	}

	/** @return int Unused recovery codes. */
	public function recovery_remaining( $user_id ) {
		$codes = get_user_meta( $user_id, self::META_RECOVERY, true );
		return is_array( $codes ) ? count( $codes ) : 0;
	}

	/** @return string 5 characters from an unambiguous alphabet. */
	private function random_block() {
		$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
		$out   = '';
		for ( $i = 0; $i < 5; $i++ ) {
			$out .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}
		return $out;
	}

	/**
	 * Use up a recovery code.
	 *
	 * @param int    $user_id User.
	 * @param string $input   Input.
	 * @return bool
	 */
	private function consume_recovery( $user_id, $input ) {
		$hash  = hash( 'sha256', strtoupper( trim( $input ) ) );
		$codes = get_user_meta( $user_id, self::META_RECOVERY, true );
		$codes = is_array( $codes ) ? $codes : array();
		$index = array_search( $hash, $codes, true );
		if ( false === $index ) {
			return false;
		}
		unset( $codes[ $index ] );
		update_user_meta( $user_id, self::META_RECOVERY, array_values( $codes ) );
		$this->audit( 'recovery_code_used', $user_id, 'recovery' );
		return true;
	}

	/**
	 * @param string $event   Event.
	 * @param int    $user_id User.
	 * @param string $method  Method.
	 */
	private function audit( $event, $user_id, $method ) {
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( $event, array( 'user' => $user_id, 'method' => $method ) );
		}
	}
}
