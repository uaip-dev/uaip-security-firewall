<?php
/**
 * Users → Two-step verification: each user manages their own authenticator
 * app, passkeys, email codes and recovery codes. Administrators also choose
 * which roles must use two-step verification.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Twofa_Page {

	const SLUG = 'uaip-sfw-2fa';

	/** @var Uaip_Sfw_Twofa */
	private $twofa;

	/**
	 * @param Uaip_Sfw_Twofa $twofa Module.
	 */
	public function __construct( $twofa ) {
		$this->twofa = $twofa;
	}

	public function register_hooks() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'show_user_profile', array( $this, 'profile_link' ) );
		add_action( 'admin_notices', array( $this, 'required_notice' ) );
	}

	public function menu() {
		add_users_page(
			__( 'Two-step verification', 'uaip-security-firewall' ),
			__( 'Two-step verification', 'uaip-security-firewall' ),
			'read',
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/** @return string Page URL. */
	public static function url() {
		return admin_url( ( current_user_can( 'list_users' ) ? 'users.php' : 'profile.php' ) . '?page=' . self::SLUG );
	}

	/**
	 * @param string $hook Hook.
	 */
	public function assets( $hook ) {
		if ( false === strpos( (string) $hook, self::SLUG ) ) {
			return;
		}
		wp_enqueue_style( 'uaip-sfw-admin', UAIP_SFW_URL . 'assets/css/admin.css', array(), UAIP_SFW_VERSION );
		wp_enqueue_script( 'uaip-sfw-admin', UAIP_SFW_URL . 'assets/js/admin.js', array(), UAIP_SFW_VERSION, true );
		wp_enqueue_script( 'uaip-sfw-passkeys', UAIP_SFW_URL . 'assets/js/passkeys.js', array(), UAIP_SFW_VERSION, true );
	}

	/** Link from the profile screen. */
	public function profile_link() {
		echo '<h2>' . esc_html__( 'Two-step verification', 'uaip-security-firewall' ) . '</h2><p><a class="button" href="' . esc_url( self::url() ) . '">' . esc_html__( 'Manage two-step verification and passkeys', 'uaip-security-firewall' ) . '</a></p>';
	}

	/** Remind required users who rely on the automatic email codes. */
	public function required_notice() {
		$user = wp_get_current_user();
		if ( ! $user->exists() || ! $this->twofa->required_for( $user ) ) {
			return;
		}
		if ( $this->twofa->is_enabled( $user->ID ) || $this->twofa->passkeys( $user->ID ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false !== strpos( (string) $screen->id, self::SLUG ) ) {
			return;
		}
		echo '<div class="notice notice-info"><p>' . esc_html__( 'This site requires two-step verification for your account. You get sign-in codes by email; a passkey or an authenticator app is faster and safer.', 'uaip-security-firewall' ) . ' <a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Set one up', 'uaip-security-firewall' ) . '</a></p></div>';
	}

	/**
	 * Handle a form post. Returns [error, success, recovery codes].
	 *
	 * @param WP_User $user User.
	 * @return array{0:string,1:string,2:array}
	 */
	private function handle( $user ) {
		if ( ! isset( $_POST['uaip_sfw_2fa_action'] ) || ! check_admin_referer( 'uaip_sfw_2fa' ) ) {
			return array( '', '', array() );
		}
		$action   = sanitize_key( wp_unslash( $_POST['uaip_sfw_2fa_action'] ) );
		$password = isset( $_POST['uaip_sfw_password'] ) ? (string) wp_unslash( $_POST['uaip_sfw_password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- passwords are checked, never stored or shown.
		$uid      = $user->ID;
		$needs_pw = in_array( $action, array( 'remove_app', 'remove_passkey', 'email_off', 'regen' ), true );
		if ( $needs_pw && ! wp_check_password( $password, $user->user_pass, $uid ) ) {
			return array( __( 'Your password was not correct, so nothing was changed.', 'uaip-security-firewall' ), '', array() );
		}
		$codes = array();
		switch ( $action ) {
			case 'confirm_app':
				$code = isset( $_POST['uaip_sfw_code'] ) ? sanitize_text_field( wp_unslash( $_POST['uaip_sfw_code'] ) ) : '';
				$res  = $this->twofa->confirm_setup( $uid, $code );
				if ( is_wp_error( $res ) ) {
					return array( $res->get_error_message(), '', array() );
				}
				$codes = $this->first_codes( $uid );
				return array( '', __( 'Your authenticator app is set up.', 'uaip-security-firewall' ), $codes );
			case 'remove_app':
				$this->twofa->remove_app( $uid );
				return array( '', __( 'Authenticator app removed.', 'uaip-security-firewall' ), array() );
			case 'remove_passkey':
				$id = isset( $_POST['uaip_sfw_passkey'] ) ? sanitize_text_field( wp_unslash( $_POST['uaip_sfw_passkey'] ) ) : '';
				$this->twofa->remove_passkey( $uid, $id );
				return array( '', __( 'Passkey removed.', 'uaip-security-firewall' ), array() );
			case 'email_on':
				$this->twofa->set_email( $uid, true );
				return array( '', __( 'Email codes switched on.', 'uaip-security-firewall' ), $this->first_codes( $uid ) );
			case 'email_off':
				$this->twofa->set_email( $uid, false );
				return array( '', __( 'Email codes switched off.', 'uaip-security-firewall' ), array() );
			case 'regen':
				return array( '', __( 'New recovery codes created. The old ones no longer work.', 'uaip-security-firewall' ), $this->twofa->regenerate_recovery( $uid ) );
			case 'passkey_added':
				return array( '', __( 'Passkey added.', 'uaip-security-firewall' ), $this->first_codes( $uid ) );
			case 'site_settings':
				if ( ! current_user_can( 'manage_options' ) ) {
					return array( '', '', array() );
				}
				$roles = isset( $_POST['uaip_sfw_roles'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['uaip_sfw_roles'] ) ) : array();
				Uaip_Sfw_Settings::update(
					array(
						'twofa_required_roles' => array_values( array_intersect( $roles, array_keys( wp_roles()->get_names() ) ) ),
						'twofa_email'          => ! empty( $_POST['uaip_sfw_allow_email'] ),
						'twofa_passkeys'       => ! empty( $_POST['uaip_sfw_allow_passkeys'] ),
					)
				);
				return array( '', __( 'Site settings saved.', 'uaip-security-firewall' ), array() );
		}
		return array( '', '', array() );
	}

	/**
	 * Recovery codes when the user's first method is added.
	 *
	 * @param int $uid User.
	 * @return string[]
	 */
	private function first_codes( $uid ) {
		return 0 === $this->twofa->recovery_remaining( $uid ) ? $this->twofa->regenerate_recovery( $uid ) : array();
	}

	public function render() {
		$user = wp_get_current_user();
		list( $error, $success, $codes ) = $this->handle( $user );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display flag after the passkey AJAX save.
		if ( '' === $success && isset( $_GET['added'] ) ) {
			$success = __( 'Passkey added.', 'uaip-security-firewall' );
			$codes   = $this->first_codes( $user->ID );
		}
		$uid     = $user->ID;
		$methods = $this->twofa->methods( $user );
		$active  = in_array( true, $methods, true );

		echo '<div class="wrap uaip-sfw-wrap uaip-sfw-2fa-page">';
		echo '<h1>' . esc_html__( 'Two-step verification', 'uaip-security-firewall' ) . '</h1>';
		echo '<p class="uaip-sfw-lead">' . esc_html__( 'After your password, confirm it is you with a second step. Even if someone learns your password, they cannot sign in.', 'uaip-security-firewall' ) . '</p>';
		if ( '' !== $error ) {
			echo '<div class="notice notice-error"><p>' . esc_html( $error ) . '</p></div>';
		}
		if ( '' !== $success ) {
			echo '<div class="notice notice-success"><p>' . esc_html( $success ) . '</p></div>';
		}
		if ( $codes ) {
			$this->render_codes( $codes );
		}
		printf(
			'<p class="uaip-sfw-2fa-state %s"><span class="dashicons %s"></span> %s</p>',
			esc_attr( $active ? 'is-on' : 'is-off' ),
			esc_attr( $active ? 'dashicons-yes-alt' : 'dashicons-warning' ),
			esc_html( $active ? __( 'Two-step verification is on for your account.', 'uaip-security-firewall' ) : __( 'Two-step verification is off. Add a passkey or an authenticator app below.', 'uaip-security-firewall' ) )
		);

		if ( Uaip_Sfw_Settings::get( 'twofa_passkeys' ) ) {
			$this->render_passkeys( $uid );
		}
		$this->render_app( $user );
		if ( Uaip_Sfw_Settings::get( 'twofa_email' ) ) {
			$this->render_email( $user );
		}
		if ( $active ) {
			$this->render_recovery( $uid );
		}
		if ( current_user_can( 'manage_options' ) ) {
			$this->render_site_settings();
		}
		echo '</div>';
	}

	/**
	 * Show new recovery codes once.
	 *
	 * @param string[] $codes Codes.
	 */
	private function render_codes( array $codes ) {
		echo '<div class="uaip-sfw-card uaip-sfw-codes"><h2>' . esc_html__( 'Save your recovery codes', 'uaip-security-firewall' ) . '</h2>';
		echo '<p>' . esc_html__( 'If you lose your phone or passkey, each of these codes signs you in once. Store them somewhere safe, such as a password manager. They are shown only now.', 'uaip-security-firewall' ) . '</p><ul class="uaip-sfw-code-list">';
		foreach ( $codes as $c ) {
			echo '<li><code>' . esc_html( $c ) . '</code></li>';
		}
		echo '</ul><button type="button" class="button uaip-sfw-copy" data-clip="' . esc_attr( implode( "\n", $codes ) ) . '">' . esc_html__( 'Copy codes', 'uaip-security-firewall' ) . '</button></div>';
	}

	/**
	 * A small form posting one action.
	 *
	 * @param string $action   Action.
	 * @param string $label    Button.
	 * @param string $class    Button class.
	 * @param bool   $password Ask for the password.
	 * @param array  $hidden   Extra hidden fields.
	 */
	private function action_form( $action, $label, $class, $password, array $hidden = array() ) {
		echo '<form method="post" class="uaip-sfw-2fa-form">';
		wp_nonce_field( 'uaip_sfw_2fa' );
		echo '<input type="hidden" name="uaip_sfw_2fa_action" value="' . esc_attr( $action ) . '">';
		foreach ( $hidden as $name => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '">';
		}
		if ( $password ) {
			echo '<label class="uaip-sfw-pw"><span class="screen-reader-text">' . esc_html__( 'Your password', 'uaip-security-firewall' ) . '</span><input type="password" name="uaip_sfw_password" autocomplete="current-password" placeholder="' . esc_attr__( 'Your password', 'uaip-security-firewall' ) . '" required></label>';
		}
		echo '<button type="submit" class="button ' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	/**
	 * @param int $uid User.
	 */
	private function render_passkeys( $uid ) {
		$keys = $this->twofa->passkeys( $uid );
		echo '<div class="uaip-sfw-card"><h2><span class="dashicons dashicons-admin-network"></span> ' . esc_html__( 'Passkeys', 'uaip-security-firewall' ) . '</h2>';
		echo '<p>' . esc_html__( 'Use your fingerprint, face, device PIN or a security key. Nothing to type and nothing to steal: the safest option.', 'uaip-security-firewall' ) . '</p>';
		if ( $keys ) {
			echo '<table class="widefat striped uaip-sfw-table"><thead><tr><th>' . esc_html__( 'Name', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Added', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Last used', 'uaip-security-firewall' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $keys as $id => $k ) {
				echo '<tr><td>' . esc_html( $k['name'] ) . '</td><td>' . esc_html( wp_date( get_option( 'date_format' ), (int) $k['created'] ) ) . '</td><td>' . esc_html( $k['last_used'] ? human_time_diff( (int) $k['last_used'] ) . ' ' . __( 'ago', 'uaip-security-firewall' ) : __( 'never', 'uaip-security-firewall' ) ) . '</td><td>';
				$this->action_form( 'remove_passkey', __( 'Remove', 'uaip-security-firewall' ), 'button-small button-link-delete', true, array( 'uaip_sfw_passkey' => $id ) );
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		printf(
			'<div class="uaip-sfw-passkey-add" id="uaip-sfw-passkey-add" data-ajax="%s" data-nonce="%s" data-done="%s" data-unsupported="%s" data-failed="%s"><label>%s <input type="text" id="uaip-sfw-passkey-name" maxlength="60" placeholder="%s"></label> <button type="button" class="button button-primary" id="uaip-sfw-passkey-create">%s</button><p class="uaip-sfw-passkey-msg" role="status"></p></div>',
			esc_url( admin_url( 'admin-ajax.php' ) ),
			esc_attr( wp_create_nonce( 'uaip_sfw_passkey' ) ),
			esc_url( add_query_arg( 'added', '1', self::url() ) ),
			esc_attr__( 'This browser does not support passkeys.', 'uaip-security-firewall' ),
			esc_attr__( 'The passkey was not added.', 'uaip-security-firewall' ),
			esc_html__( 'Name', 'uaip-security-firewall' ),
			esc_attr__( 'e.g. Work laptop', 'uaip-security-firewall' ),
			esc_html__( 'Add a passkey', 'uaip-security-firewall' )
		);
		echo '</div>';
	}

	/**
	 * @param WP_User $user User.
	 */
	private function render_app( $user ) {
		$uid = $user->ID;
		echo '<div class="uaip-sfw-card"><h2><span class="dashicons dashicons-smartphone"></span> ' . esc_html__( 'Authenticator app', 'uaip-security-firewall' ) . '</h2>';
		if ( $this->twofa->is_enabled( $uid ) ) {
			echo '<p>' . esc_html__( 'Your authenticator app is set up. Each code works once.', 'uaip-security-firewall' ) . '</p>';
			$this->action_form( 'remove_app', __( 'Remove authenticator app', 'uaip-security-firewall' ), 'button-link-delete', true );
			echo '</div>';
			return;
		}
		// New key on each fresh visit; keep it across a wrong-code retry.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only check of which form was posted.
		$retry  = isset( $_POST['uaip_sfw_2fa_action'] ) && 'confirm_app' === sanitize_key( wp_unslash( $_POST['uaip_sfw_2fa_action'] ) );
		$secret = $retry ? $this->twofa->pending_secret( $uid ) : '';
		if ( '' === $secret ) {
			$secret = $this->twofa->rotate_setup( $uid );
		}
		$uri = Uaip_Sfw_TOTP::provisioning_uri( $secret, $user->user_login, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
		echo '<p>' . esc_html__( 'Scan this with Google Authenticator, Microsoft Authenticator, 1Password, Authy or a similar app, then enter the 6-digit code it shows.', 'uaip-security-firewall' ) . '</p>';
		echo '<div class="uaip-sfw-qr-layout"><div class="uaip-sfw-qr">';
		try {
			echo Uaip_Sfw_QR::svg( $uri, 5, 4 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SVG generated by the plugin from a fixed alphabet.
		} catch ( Exception $e ) {
			echo '';
		}
		echo '</div><div><p>' . esc_html__( 'Or enter this key:', 'uaip-security-firewall' ) . '<br><code class="uaip-sfw-secret">' . esc_html( Uaip_Sfw_TOTP::format_secret( $secret ) ) . '</code></p>';
		echo '<form method="post" class="uaip-sfw-2fa-form">';
		wp_nonce_field( 'uaip_sfw_2fa' );
		echo '<input type="hidden" name="uaip_sfw_2fa_action" value="confirm_app"><label>' . esc_html__( 'Code', 'uaip-security-firewall' ) . ' <input type="text" name="uaip_sfw_code" class="uaip-sfw-code-input" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required></label> ';
		echo '<button type="submit" class="button button-primary">' . esc_html__( 'Turn on', 'uaip-security-firewall' ) . '</button></form></div></div></div>';
	}

	/**
	 * @param WP_User $user User.
	 */
	private function render_email( $user ) {
		$uid      = $user->ID;
		$on       = $this->twofa->email_enabled( $uid );
		$required = $this->twofa->required_for( $user );
		echo '<div class="uaip-sfw-card"><h2><span class="dashicons dashicons-email"></span> ' . esc_html__( 'Email codes', 'uaip-security-firewall' ) . '</h2>';
		/* translators: %s: email address */
		echo '<p>' . esc_html( sprintf( __( 'Get a sign-in code at %s. Works anywhere, but only as safe as your email account.', 'uaip-security-firewall' ), $user->user_email ) ) . '</p>';
		if ( $on ) {
			$this->action_form( 'email_off', __( 'Switch off email codes', 'uaip-security-firewall' ), 'button-link-delete', true );
		} else {
			if ( $required ) {
				echo '<p class="description">' . esc_html__( 'Your role requires two-step verification, so email codes are used automatically until you add a passkey or app.', 'uaip-security-firewall' ) . '</p>';
			}
			$this->action_form( 'email_on', __( 'Switch on email codes', 'uaip-security-firewall' ), 'button-secondary', false );
		}
		echo '</div>';
	}

	/**
	 * @param int $uid User.
	 */
	private function render_recovery( $uid ) {
		$left = $this->twofa->recovery_remaining( $uid );
		echo '<div class="uaip-sfw-card"><h2><span class="dashicons dashicons-sos"></span> ' . esc_html__( 'Recovery codes', 'uaip-security-firewall' ) . '</h2>';
		/* translators: %d: number of unused recovery codes */
		echo '<p>' . esc_html( sprintf( _n( 'You have %d unused recovery code.', 'You have %d unused recovery codes.', $left, 'uaip-security-firewall' ), $left ) ) . '</p>';
		$this->action_form( 'regen', __( 'Create new recovery codes', 'uaip-security-firewall' ), 'button-secondary', true );
		echo '</div>';
	}

	/** Administrators: required roles and allowed methods. */
	private function render_site_settings() {
		$required = (array) Uaip_Sfw_Settings::get( 'twofa_required_roles', array() );
		echo '<div class="uaip-sfw-card"><h2><span class="dashicons dashicons-admin-site"></span> ' . esc_html__( 'Site settings', 'uaip-security-firewall' ) . '</h2>';
		echo '<form method="post">';
		wp_nonce_field( 'uaip_sfw_2fa' );
		echo '<input type="hidden" name="uaip_sfw_2fa_action" value="site_settings">';
		echo '<fieldset><legend><strong>' . esc_html__( 'Require two-step verification for', 'uaip-security-firewall' ) . '</strong></legend>';
		foreach ( wp_roles()->get_names() as $role => $name ) {
			printf( '<label class="uaip-sfw-role"><input type="checkbox" name="uaip_sfw_roles[]" value="%s" %s> %s</label>', esc_attr( $role ), checked( in_array( $role, $required, true ), true, false ), esc_html( translate_user_role( $name ) ) );
		}
		echo '<p class="description">' . esc_html__( 'Users in these roles who have not set anything up get sign-in codes by email.', 'uaip-security-firewall' ) . '</p></fieldset>';
		echo '<p><label><input type="checkbox" name="uaip_sfw_allow_passkeys" value="1" ' . checked( (bool) Uaip_Sfw_Settings::get( 'twofa_passkeys' ), true, false ) . '> ' . esc_html__( 'Allow passkeys', 'uaip-security-firewall' ) . '</label><br>';
		echo '<label><input type="checkbox" name="uaip_sfw_allow_email" value="1" ' . checked( (bool) Uaip_Sfw_Settings::get( 'twofa_email' ), true, false ) . '> ' . esc_html__( 'Allow email codes', 'uaip-security-firewall' ) . '</label></p>';
		submit_button( __( 'Save site settings', 'uaip-security-firewall' ), 'secondary', 'submit', false );
		echo '</form></div>';
	}
}
