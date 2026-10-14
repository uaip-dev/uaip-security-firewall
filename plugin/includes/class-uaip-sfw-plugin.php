<?php
/**
 * Core plugin orchestrator. Loads modules according to the active tier.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Uaip_Sfw_Plugin {

	/** @var Uaip_Sfw_Plugin */
	private static $instance;

	/** @var Uaip_Sfw_License */
	public $license;

	/** @var array<string,object> Loaded feature modules keyed by slug. */
	private $modules = array();

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Boot the plugin: resolve tier, load shared (Free) modules, then Pro.
	 */
	public function boot() {
		// Translations are loaded automatically. WordPress.org-hosted plugins get
		// their language packs from translate.wordpress.org, and since WP 4.6 any
		// bundled .mo in /languages is loaded just-in-time on first use — so an
		// explicit load_plugin_textdomain() call is unnecessary (and discouraged).

		// Create/upgrade the scanner tables after an update (cheap version check).
		Uaip_Sfw_DB::maybe_upgrade();

		$this->license = new Uaip_Sfw_License();
		// Reconcile tier first so a lapsed license halts Pro before modules load.
		$this->license->enforce_tier();

		// ---- Free / shared modules (always loaded, run standalone) ----
		$this->register( 'waf', new Uaip_Sfw_WAF() );
		$this->register( 'scanner', new Uaip_Sfw_Scanner() );
		$this->register( 'login_guard', new Uaip_Sfw_Login_Guard() );
		$twofa = new Uaip_Sfw_Twofa();
		$this->register( 'twofa', $twofa );
		$this->register( 'hardening', new Uaip_Sfw_Hardening() );
		$this->register( 'site_health', new Uaip_Sfw_Site_Health() );
		$this->register( 'audit_log', new Uaip_Sfw_Audit_Log() );
		$this->register( 'heartbeat', new Uaip_Sfw_Heartbeat() );

		// ---- Pro modules: only when the Pro package is present AND licensed ----
		if ( UAIP_SFW_HAS_PRO_PACKAGE && $this->license->is_pro() ) {
			Uaip_Sfw_Pro_Loader::load( $this );
		}

		// Boot every registered module.
		foreach ( $this->modules as $module ) {
			if ( method_exists( $module, 'register_hooks' ) ) {
				$module->register_hooks();
			}
		}

		// Respond to cloud URL-ownership verification callbacks.
		add_action( 'init', array( $this, 'maybe_respond_verification' ), 1 );

		// REST: live cloud-connection status (polled by the License page).
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );

		// Admin UI.
		if ( is_admin() ) {
			( new Uaip_Sfw_Admin( $this ) )->register_hooks();
			( new Uaip_Sfw_Twofa_Page( $twofa ) )->register_hooks();
			( new Uaip_Sfw_Activity_Page( $this->module( 'audit_log' ) ) )->register_hooks();
		}
	}

	/**
	 * Answer a UAIP Security Cloud ownership check: GET ?uaip_sfw_verify=TOKEN
	 * returns an HMAC of the token keyed by this site's API secret. Only the
	 * genuine install (which holds the secret) can produce the right value, so
	 * the cloud can confirm a claimed URL really serves this license.
	 */
	public function maybe_respond_verification() {
		if ( ! isset( $_GET['uaip_sfw_verify'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return;
		}
		$token = sanitize_text_field( wp_unslash( $_GET['uaip_sfw_verify'] ) ); // phpcs:ignore WordPress.Security.NonceVerification
		if ( '' === $token || strlen( $token ) > 128 ) {
			return;
		}
		$secret = Uaip_Sfw_Crypto::decrypt( get_option( Uaip_Sfw_Cloud_API::OPT_SECRET, '' ) );
		if ( '' === $secret ) {
			return; // not connected — behave like a normal request
		}
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo 'UAIP-VERIFY:' . hash_hmac( 'sha256', $token, $secret ); // phpcs:ignore
		exit;
	}

	/**
	 * Register read-only REST routes. Currently exposes the live cloud-connection
	 * status that the License page polls so the "Connected / live" indicator and
	 * "Last sync" update without a full page reload. Admin-only.
	 */
	public function register_rest_routes() {
		register_rest_route(
			'uaip-sfw/v1',
			'/connection',
			array(
				'methods'             => 'GET',
				'permission_callback' => function () {
					return current_user_can( 'manage_options' );
				},
				'callback'            => array( $this, 'rest_connection_status' ),
			)
		);
	}

	/**
	 * Build the connection-status payload consumed by the License page poller.
	 *
	 * @return array
	 */
	public function rest_connection_status() {
		$last = (int) get_option( 'uaip_sfw_last_heartbeat', 0 );
		$live = $last && ( time() - $last ) < 2 * HOUR_IN_SECONDS;

		return array(
			'connected'       => Uaip_Sfw_Cloud_API::instance()->is_connected(),
			'account'         => (string) get_option( 'uaip_sfw_account_email', '' ),
			'last_sync'       => $last,
			'last_sync_human' => $last
				? sprintf(
					/* translators: %s: human-readable time difference, e.g. "2 minutes" */
					__( '%s ago', 'uaip-security-firewall' ),
					human_time_diff( $last )
				)
				: __( 'never', 'uaip-security-firewall' ),
			'live'            => $live,
			'error'           => (int) get_option( 'uaip_sfw_last_heartbeat_error', 0 ),
		);
	}

	/**
	 * Register a feature module by slug (Pro modules may override Free ones).
	 *
	 * @param string $slug
	 * @param object $module
	 */
	public function register( $slug, $module ) {
		$this->modules[ $slug ] = $module;
	}

	/** @return object|null */
	public function module( $slug ) {
		return isset( $this->modules[ $slug ] ) ? $this->modules[ $slug ] : null;
	}

	/** @return array<string,object> */
	public function modules() {
		return $this->modules;
	}
}
