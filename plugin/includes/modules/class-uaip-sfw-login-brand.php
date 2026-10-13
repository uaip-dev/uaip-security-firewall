<?php
/**
 * Login page customization (Free) — let the site owner brand wp-login.php:
 * logo, background, button colour and custom CSS.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Login_Brand {

	public function register_hooks() {
		if ( ! Uaip_Sfw_Settings::get( 'login_brand_enabled' ) ) {
			return;
		}
		add_action( 'login_enqueue_scripts', array( $this, 'login_styles' ) );
		add_filter( 'login_headerurl', array( $this, 'logo_url' ) );
		add_filter( 'login_headertext', array( $this, 'logo_text' ) );
	}

	public function logo_url() {
		return home_url( '/' );
	}

	public function logo_text() {
		return get_bloginfo( 'name' );
	}

	/**
	 * Build the login CSS from the saved (structured, sanitised) settings and
	 * hand it to WordPress via wp_add_inline_style() so it is enqueued the same
	 * way core styles are. Every value is derived from a colour picker or an
	 * uploaded logo URL — there is no free-form CSS input.
	 */
	public function login_styles() {
		$s    = Uaip_Sfw_Settings::all();
		$logo = esc_url( $s['login_logo_url'] );
		$from = $this->hex( $s['login_bg_from'], '#f0f0f1' );
		$to   = $this->hex( $s['login_bg_to'], '' );
		$btn  = $this->hex( $s['login_button_color'], '#2271b1' );
		$bg   = '' !== $to ? "linear-gradient(135deg, {$from}, {$to})" : $from;

		$css  = 'body.login{background:' . $bg . ';}';
		if ( '' !== $logo ) {
			$css .= ".login h1 a{background-image:url('" . $logo . "');background-size:contain;background-position:center;width:100%;height:84px;}";
		}
		$css .= '.login form{border-radius:10px;box-shadow:0 12px 34px rgba(0,0,0,.16);border:0;}';
		$css .= '.login label{color:#1e293b;}';
		$css .= '.wp-core-ui .button-primary{background:' . $btn . ';border-color:' . $btn . ';box-shadow:none;text-shadow:none;}';
		$css .= '.wp-core-ui .button-primary:hover{filter:brightness(1.06);}';
		$css .= 'input[type=text]:focus,input[type=password]:focus{border-color:' . $btn . ';box-shadow:0 0 0 1px ' . $btn . ';}';
		$css .= '.login #nav a,.login #backtoblog a{color:rgba(255,255,255,.92);text-shadow:0 1px 2px rgba(0,0,0,.2);}';

		// A "virtual" (src-less) handle exists solely to carry the inline CSS,
		// the documented way to enqueue programmatically generated styles.
		wp_register_style( 'uaip-sfw-login-brand', false, array(), UAIP_SFW_VERSION );
		wp_enqueue_style( 'uaip-sfw-login-brand' );
		wp_add_inline_style( 'uaip-sfw-login-brand', $css );
	}

	/**
	 * @param string $value
	 * @param string $fallback
	 * @return string
	 */
	private function hex( $value, $fallback ) {
		$c = sanitize_hex_color( (string) $value );
		return $c ? $c : $fallback;
	}
}
