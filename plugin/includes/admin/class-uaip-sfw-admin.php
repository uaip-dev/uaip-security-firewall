<?php
/**
 * Admin UI: menu, dashboard, plans/upgrade screen, license activation.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Admin {

	/** @var Uaip_Sfw_Plugin */
	private $plugin;

	public function __construct( Uaip_Sfw_Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function register_hooks() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_post_uaip_sfw_license', array( $this, 'handle_license' ) );
		add_action( 'wp_ajax_uaip_sfw_scan_step', array( $this, 'ajax_scan_step' ) );
		add_action( 'admin_post_uaip_sfw_connect', array( $this, 'handle_connect' ) );
		add_action( 'admin_post_uaip_sfw_connect_account', array( $this, 'handle_connect_account' ) );
		add_action( 'admin_post_uaip_sfw_sync_cloud', array( $this, 'handle_sync_cloud' ) );
		add_action( 'admin_post_uaip_sfw_disconnect_cloud', array( $this, 'handle_disconnect_cloud' ) );

		if ( $this->plugin->license->is_dev_pro() ) {
			add_action( 'admin_notices', array( $this, 'dev_pro_notice' ) );
		}
		if ( get_option( 'uaip_sfw_downgraded_notice' ) && ! $this->plugin->license->is_pro() ) {
			add_action( 'admin_notices', array( $this, 'downgraded_notice' ) );
		}
	}

	/** Banner shown after a Pro license lapses — prompts renewal. */
	public function downgraded_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false === strpos( (string) $screen->id, 'uaip-sfw' ) ) {
			return; // only on UAIP Security screens
		}
		printf(
			'<div class="notice notice-warning"><p><strong>UAIP Security:</strong> %s <a class="button button-small button-primary" href="%s" target="_blank">%s</a> <a href="%s">%s</a></p></div>',
			esc_html__( 'Your Pro subscription has lapsed — Pro features are now disabled and your site is on the Free plan.', 'uaip-security-firewall' ),
			esc_url( $this->cloud_renew_url() ),
			esc_html__( 'Renew subscription', 'uaip-security-firewall' ),
			esc_url( admin_url( 'admin.php?page=uaip-sfw-license' ) ),
			esc_html__( 'License settings', 'uaip-security-firewall' )
		);
	}

	/** Persistent banner while the Pro simulation flag is active. */
	public function dev_pro_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false === strpos( (string) $screen->id, 'uaip-sfw' ) ) {
			return; // only on UAIP Security screens
		}
		echo '<div class="notice notice-warning"><p><strong>UAIP Security:</strong> ' .
			esc_html__( 'Developer Pro simulation is active (UAIP_SFW_DEV_PRO). All Pro features are unlocked locally — disable this before production.', 'uaip-security-firewall' ) .
			'</p></div>';
	}

	/**
	 * Load the dashboard stylesheet only on UAIP Security screens.
	 *
	 * @param string $hook
	 */
	public function enqueue_assets( $hook ) {
		if ( false === strpos( (string) $hook, 'uaip-sfw' ) ) {
			return;
		}
		wp_enqueue_style(
			'uaip-sfw-admin',
			UAIP_SFW_URL . 'assets/css/admin.css',
			array(),
			UAIP_SFW_VERSION
		);
		wp_enqueue_script(
			'uaip-sfw-admin',
			UAIP_SFW_URL . 'assets/js/admin.js',
			array(),
			UAIP_SFW_VERSION,
			true
		);

		// Live cloud-connection poller for the License page (no full reload).
		if ( false !== strpos( (string) $hook, 'uaip-sfw-license' ) ) {
			$cfg = wp_json_encode(
				array(
					'url'    => esc_url_raw( rest_url( 'uaip-sfw/v1/connection' ) ),
					'nonce'  => wp_create_nonce( 'wp_rest' ),
					'labels' => array(
						'connected' => __( 'Connected', 'uaip-security-firewall' ),
						'idle'      => __( 'Connected (idle)', 'uaip-security-firewall' ),
					),
				)
			);
			wp_add_inline_script( 'uaip-sfw-admin', 'window.uaipSfwConn=' . $cfg . ';' . $this->connection_poll_js() );
		}

		// Color picker + media uploader for the Login Page customizer.
		if ( false !== strpos( (string) $hook, 'uaip-sfw-login' ) ) {
			wp_enqueue_style( 'wp-color-picker' );
			wp_enqueue_script( 'wp-color-picker' );
			wp_enqueue_media();
			wp_add_inline_script(
				'wp-color-picker',
				"jQuery(function($){"
				. "$('.uaip-sfw-color').wpColorPicker();"
				. "$('#uaip-sfw-logo-upload').on('click',function(e){e.preventDefault();"
				. "var f=wp.media({title:'Select a logo',button:{text:'Use this logo'},multiple:false});"
				. "f.on('select',function(){var a=f.state().get('selection').first().toJSON();"
				. "$('#login_logo_url').val(a.url);$('#uaip-sfw-logo-preview').attr('src',a.url).css('display','block');});f.open();});"
				. "$('#uaip-sfw-logo-remove').on('click',function(e){e.preventDefault();$('#login_logo_url').val('');$('#uaip-sfw-logo-preview').hide();});"
				. "});"
			);
		}
	}

	public function menu() {
		$cap = 'manage_options';
		add_menu_page( 'UAIP Security', 'UAIP Security', $cap, 'uaip-sfw', array( $this, 'page_dashboard' ), 'dashicons-shield', 80 );
		add_submenu_page( 'uaip-sfw', __( 'Dashboard', 'uaip-security-firewall' ), __( 'Dashboard', 'uaip-security-firewall' ), $cap, 'uaip-sfw', array( $this, 'page_dashboard' ) );
		add_submenu_page( 'uaip-sfw', __( 'Firewall', 'uaip-security-firewall' ), __( 'Firewall', 'uaip-security-firewall' ), $cap, 'uaip-sfw-firewall', array( $this, 'page_firewall' ) );
		add_submenu_page( 'uaip-sfw', __( 'Scan', 'uaip-security-firewall' ), __( 'Scan', 'uaip-security-firewall' ), $cap, 'uaip-sfw-scan', array( $this, 'page_scan' ) );
		add_submenu_page( 'uaip-sfw', __( 'Audit Log', 'uaip-security-firewall' ), __( 'Audit Log', 'uaip-security-firewall' ), $cap, 'uaip-sfw-audit', array( $this, 'page_audit' ) );
		add_submenu_page( 'uaip-sfw', __( 'Hardening', 'uaip-security-firewall' ), __( 'Hardening', 'uaip-security-firewall' ), $cap, 'uaip-sfw-hardening', array( $this, 'page_hardening' ) );
		add_submenu_page( 'uaip-sfw', __( 'Login Page', 'uaip-security-firewall' ), __( 'Login Page', 'uaip-security-firewall' ), $cap, 'uaip-sfw-login', array( $this, 'page_login_brand' ) );
		add_submenu_page( 'uaip-sfw', __( 'Settings', 'uaip-security-firewall' ), __( 'Settings', 'uaip-security-firewall' ), $cap, 'uaip-sfw-settings', array( $this, 'page_settings' ) );
		add_submenu_page( 'uaip-sfw', __( 'Plans & Upgrade', 'uaip-security-firewall' ), __( 'Plans & Upgrade', 'uaip-security-firewall' ), $cap, 'uaip-sfw-plans', array( $this, 'page_plans' ) );
		add_submenu_page( 'uaip-sfw', __( 'License', 'uaip-security-firewall' ), __( 'License', 'uaip-security-firewall' ), $cap, 'uaip-sfw-license', array( $this, 'page_license' ) );
	}

	// -----------------------------------------------------------------
	// Scan / Audit / Settings pages
	// -----------------------------------------------------------------

	/**
	 * Reusable gradient page header with the tier badge.
	 *
	 * @param string $title
	 * @param string $subtitle
	 * @param string $icon Dashicon class.
	 */
	/**
	 * Public UAIP Security Cloud pricing URL, pre-filled with this site's context
	 * so checkout can bind the purchase to the right install/email.
	 *
	 * @return string
	 */
	private function cloud_pricing_url() {
		return add_query_arg(
			array(
				'site'  => rawurlencode( home_url() ),
				'email' => rawurlencode( get_option( 'admin_email' ) ),
			),
			UAIP_SFW_CLOUD_SITE . '/pricing'
		);
	}

	/**
	 * Renew / manage subscription — the cloud account (Stripe billing portal +
	 * invoices live there).
	 *
	 * @return string
	 */
	private function cloud_renew_url() {
		return UAIP_SFW_CLOUD_SITE . '/account/invoices';
	}

	private function header( $title, $subtitle = '', $icon = 'dashicons-shield' ) {
		$tier = $this->plugin->license->tier();
		echo '<div class="uaip-sfw-header uaip-sfw-header-sm">';
		printf( '<div class="uaip-sfw-header-title"><span class="dashicons %s"></span><div><h1>%s</h1>', esc_attr( $icon ), esc_html( $title ) );
		if ( $subtitle ) {
			echo '<p class="uaip-sfw-sub">' . esc_html( $subtitle ) . '</p>';
		}
		echo '</div></div>';
		printf( '<span class="uaip-sfw-tier uaip-sfw-tier-%1$s">%2$s</span>', esc_attr( $tier ), esc_html( strtoupper( $tier ) ) );
		echo '</div>';
	}

	/**
	 * Firewall: mode, stats, recent blocks, IP allowlist.
	 */
	public function page_firewall() {
		/** @var Uaip_Sfw_WAF $waf */
		$waf = $this->plugin->module( 'waf' );

		if ( isset( $_POST['uaip_sfw_fw_save'] ) && check_admin_referer( 'uaip_sfw_firewall' ) && current_user_can( 'manage_options' ) ) {
			$text = array();
			foreach ( array( 'waf_allowlist_ips', 'waf_blocklist_ips', 'trusted_proxies', 'waf_exceptions' ) as $key ) {
				$text[ $key ] = isset( $_POST[ $key ] ) ? sanitize_textarea_field( wp_unslash( $_POST[ $key ] ) ) : '';
			}
			$source  = isset( $_POST['ip_source'] ) ? sanitize_key( wp_unslash( $_POST['ip_source'] ) ) : 'remote_addr';
			$invalid = array();
			$lists   = array();
			foreach ( array( 'waf_allowlist_ips', 'waf_blocklist_ips', 'trusted_proxies' ) as $key ) {
				$parsed        = Uaip_Sfw_IP::parse_list( $text[ $key ] );
				$lists[ $key ] = implode( "\n", $parsed['valid'] );
				$invalid       = array_merge( $invalid, $parsed['invalid'] );
			}
			$exceptions = Uaip_Sfw_WAF_Engine::parse_exceptions( $text['waf_exceptions'] );
			$invalid    = array_merge( $invalid, $exceptions['invalid'] );
			$ex_lines   = array();
			foreach ( $exceptions['valid'] as $ex ) {
				$ex_lines[] = trim( $ex['rule'] . ' ' . $ex['path'] );
			}
			Uaip_Sfw_Settings::update( array(
				'waf_enabled'         => ! empty( $_POST['waf_enabled'] ),
				'waf_action'          => ( isset( $_POST['waf_action'] ) && 'learn' === sanitize_key( wp_unslash( $_POST['waf_action'] ) ) ) ? 'learn' : 'block',
				'waf_threshold'       => isset( $_POST['waf_threshold'] ) ? min( 50, max( 1, absint( wp_unslash( $_POST['waf_threshold'] ) ) ) ) : 5,
				'rate_limit_rpm'      => isset( $_POST['rate_limit_rpm'] ) ? max( 0, absint( wp_unslash( $_POST['rate_limit_rpm'] ) ) ) : 240,
				'waf_inspect_trusted' => ! empty( $_POST['waf_inspect_trusted'] ),
				'ip_source'           => in_array( $source, Uaip_Sfw_IP::SOURCES, true ) ? $source : 'remote_addr',
				'waf_allowlist_ips'   => $lists['waf_allowlist_ips'],
				'waf_blocklist_ips'   => $lists['waf_blocklist_ips'],
				'trusted_proxies'     => $lists['trusted_proxies'],
				'waf_exceptions'      => implode( "\n", $ex_lines ),
			) );
			if ( $invalid ) {
				$codes = array();
				foreach ( array_slice( $invalid, 0, 20 ) as $bad ) {
					$codes[] = '<code>' . esc_html( $bad ) . '</code>';
				}
				echo '<div class="notice notice-warning"><p>' . esc_html__( 'These entries were not valid and were left out:', 'uaip-security-firewall' ) . ' ' . wp_kses( implode( ' ', $codes ), array( 'code' => array() ) ) . '</p></div>';
			}
			// Keep the extended-protection config in sync (Pro-only feature).
			if ( class_exists( 'Uaip_Sfw_WAF_Installer' ) && Uaip_Sfw_WAF_Installer::is_installed() ) {
				Uaip_Sfw_WAF_Installer::write_config();
			}
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Firewall settings saved.', 'uaip-security-firewall' ) . '</p></div>';
		}
		if ( isset( $_POST['uaip_sfw_fw_clear'] ) && check_admin_referer( 'uaip_sfw_firewall' ) && $waf ) {
			$waf->clear_stats();
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Firewall log cleared.', 'uaip-security-firewall' ) . '</p></div>';
		}
		if ( isset( $_POST['uaip_sfw_fw_extended'] ) && class_exists( 'Uaip_Sfw_WAF_Installer' ) && check_admin_referer( 'uaip_sfw_firewall' ) && current_user_can( 'manage_options' ) ) {
			if ( ! empty( $_POST['extended_on'] ) ) {
				$res = Uaip_Sfw_WAF_Installer::install();
				echo is_wp_error( $res )
					? '<div class="notice notice-error"><p>' . esc_html( $res->get_error_message() ) . '</p></div>'
					: '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Extended protection enabled.', 'uaip-security-firewall' ) . '</p></div>';
			} else {
				Uaip_Sfw_WAF_Installer::uninstall();
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Extended protection disabled.', 'uaip-security-firewall' ) . '</p></div>';
			}
		}

		$s        = Uaip_Sfw_Settings::all();
		$stats    = $waf ? $waf->stats() : array( 'classes' => array(), 'recent' => array() );
		$rules    = $waf ? $waf->rule_count() : 0;
		$learning = 'learn' === $s['waf_action'];
		$top_class = '—';
		if ( ! empty( $stats['classes'] ) ) {
			arsort( $stats['classes'] );
			$top_class = strtoupper( (string) key( $stats['classes'] ) );
		}

		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'Firewall', 'uaip-security-firewall' ), __( 'Endpoint Web Application Firewall', 'uaip-security-firewall' ), 'dashicons-shield' );

		// Mode banner.
		if ( ! $s['waf_enabled'] ) {
			echo '<div class="uaip-sfw-card uaip-sfw-fw-mode uaip-sfw-fw-off"><span class="dashicons dashicons-dismiss"></span><div><strong>' . esc_html__( 'Firewall is off', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Your site is not being protected from web attacks.', 'uaip-security-firewall' ) . '</p></div></div>';
		} elseif ( $learning ) {
			echo '<div class="uaip-sfw-card uaip-sfw-fw-mode uaip-sfw-fw-learn"><span class="dashicons dashicons-visibility"></span><div><strong>' . esc_html__( 'Learning mode', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Attacks are detected and logged but not blocked. Switch to Active once you have confirmed there are no false positives.', 'uaip-security-firewall' ) . '</p></div></div>';
		} else {
			echo '<div class="uaip-sfw-card uaip-sfw-fw-mode uaip-sfw-fw-active"><span class="dashicons dashicons-yes-alt"></span><div><strong>' . esc_html__( 'Active protection', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Malicious requests are being blocked in real time.', 'uaip-security-firewall' ) . '</p></div></div>';
		}

		// Stat tiles.
		echo '<div class="uaip-sfw-modules uaip-sfw-scan-meta">';
		$this->stat( 'dashicons-shield-alt', __( 'Blocks (15m)', 'uaip-security-firewall' ), $waf ? (int) $waf->recent_block_count() : 0 );
		$this->stat( 'dashicons-list-view', __( 'Active rules', 'uaip-security-firewall' ), $rules );
		$this->stat( 'dashicons-warning', __( 'Top attack type', 'uaip-security-firewall' ), $top_class );
		$this->stat( 'dashicons-filter', __( 'Block threshold', 'uaip-security-firewall' ), (int) $s['waf_threshold'] );
		echo '</div>';

		// Settings + allowlist.
		echo '<form method="post"><div class="uaip-sfw-card uaip-sfw-set-group">';
		wp_nonce_field( 'uaip_sfw_firewall' );
		echo '<h2><span class="dashicons dashicons-admin-generic"></span> ' . esc_html__( 'Firewall settings', 'uaip-security-firewall' ) . '</h2>';
		$this->switch_field( 'waf_enabled', __( 'Enable firewall', 'uaip-security-firewall' ), __( 'Inspect and filter incoming requests.', 'uaip-security-firewall' ), $s['waf_enabled'] );

		// Mode radio.
		echo '<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Enforcement mode', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Block attacks, or only detect them while you tune the rules.', 'uaip-security-firewall' ) . '</p></div><div>';
		printf( '<label style="margin-right:16px;"><input type="radio" name="waf_action" value="block" %s /> %s</label>', checked( ! $learning, true, false ), esc_html__( 'Active (block)', 'uaip-security-firewall' ) );
		printf( '<label><input type="radio" name="waf_action" value="learn" %s /> %s</label>', checked( $learning, true, false ), esc_html__( 'Learning (detect only)', 'uaip-security-firewall' ) );
		echo '</div></div>';

		// Threshold.
		echo '<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Anomaly score threshold', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Block when matched rule scores reach this total. Lower = stricter.', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<input type="number" name="waf_threshold" min="1" max="50" value="%d" class="small-text" /></div>', (int) $s['waf_threshold'] );

		// Rate limit.
		echo '<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Rate limit (requests/min per IP)', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Throttle abusive clients and bots. 0 disables rate limiting.', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<input type="number" name="rate_limit_rpm" min="0" max="100000" value="%d" class="small-text" /></div>', (int) $s['rate_limit_rpm'] );

		// Inspect trusted users.
		$this->switch_field( 'waf_inspect_trusted', __( 'Also inspect editors and administrators', 'uaip-security-firewall' ), __( 'Off by default: users who may post unfiltered HTML often send code that looks like an attack. Everyone else is always inspected, including AJAX, REST API and form submissions.', 'uaip-security-firewall' ), $s['waf_inspect_trusted'] );

		// Visitor IP source.
		$sources = array(
			'remote_addr'     => __( 'Direct connection (REMOTE_ADDR)', 'uaip-security-firewall' ),
			'cloudflare'      => __( 'Cloudflare (CF-Connecting-IP, only from Cloudflare)', 'uaip-security-firewall' ),
			'x_forwarded_for' => __( 'Reverse proxy or load balancer (X-Forwarded-For)', 'uaip-security-firewall' ),
			'x_real_ip'       => __( 'Reverse proxy (X-Real-IP)', 'uaip-security-firewall' ),
		);
		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Visitor IP source', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Where the real visitor address comes from. If your site is behind Cloudflare or a proxy and this is wrong, every visitor appears to share one IP, and blocking or rate limiting one blocks them all.', 'uaip-security-firewall' ) . '</p>';
		$hint = $this->ip_source_hint();
		if ( '' !== $hint ) {
			echo '<p class="uaip-sfw-hint"><span class="dashicons dashicons-lightbulb"></span> ' . esc_html( $hint ) . '</p>';
		}
		echo '</div><div><select name="ip_source">';
		foreach ( $sources as $value => $label ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $value ), selected( $s['ip_source'], $value, false ), esc_html( $label ) );
		}
		echo '</select>';
		/* translators: %s: the visitor IP address the plugin currently sees */
		echo '<p class="description">' . esc_html( sprintf( __( 'Your IP as seen now: %s', 'uaip-security-firewall' ), Uaip_Sfw_Settings::visitor_ip() ) ) . '</p></div></div>';

		// Trusted proxies.
		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Trusted proxies', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'For the two reverse-proxy options: the IPs or ranges of your own proxies. Headers from anywhere else are ignored, so visitors cannot fake their address.', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<textarea name="trusted_proxies" rows="2" class="large-text code" placeholder="10.0.0.0/8">%s</textarea></div>', esc_textarea( $s['trusted_proxies'] ) );

		// Allowlist.
		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'IP allowlist', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'These IPs or ranges bypass the firewall. One per line; CIDR ranges such as 192.0.2.0/24 work.', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<textarea name="waf_allowlist_ips" rows="3" class="large-text code" placeholder="203.0.113.5">%s</textarea></div>', esc_textarea( $s['waf_allowlist_ips'] ) );

		// Blocklist.
		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'IP blocklist', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'These IPs or ranges are always blocked. The allowlist wins if an address is on both.', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<textarea name="waf_blocklist_ips" rows="3" class="large-text code" placeholder="198.51.100.0/24">%s</textarea></div>', esc_textarea( $s['waf_blocklist_ips'] ) );

		// Rule exceptions.
		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Rule exceptions', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Turn a rule off for a path when it blocks something legitimate. One per line: a rule ID (shown in the events table below) and an optional path prefix. Use * for every rule.', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<textarea name="waf_exceptions" rows="3" class="large-text code" placeholder="sfw-xss-003 /wp-json/contact-form-7/">%s</textarea></div>', esc_textarea( $s['waf_exceptions'] ) );

		echo '<p>';
		submit_button( __( 'Save firewall settings', 'uaip-security-firewall' ), 'primary', 'uaip_sfw_fw_save', false );
		echo '</p></div></form>';

		// Extended protection (auto_prepend) — Pro-only; the installer class only
		// ships in the Pro package, so the whole card is hidden in the free build.
		if ( class_exists( 'Uaip_Sfw_WAF_Installer' ) ) {
		$installed = Uaip_Sfw_WAF_Installer::is_installed();
		$running   = Uaip_Sfw_WAF_Installer::is_running();
		echo '<div class="uaip-sfw-card uaip-sfw-set-group">';
		echo '<h2><span class="dashicons dashicons-superhero"></span> ' . esc_html__( 'Extended Protection', 'uaip-security-firewall' ) . '</h2>';
		echo '<p>' . esc_html__( 'Run the firewall before WordPress loads (via auto_prepend) so attacks are blocked even on requests that bypass WordPress. Recommended once you have confirmed there are no false positives.', 'uaip-security-firewall' ) . '</p>';
		if ( $installed ) {
			printf(
				'<p><span class="uaip-sfw-sev %s">%s</span> %s</p>',
				esc_attr( $running ? 'uaip-sfw-sev-low' : 'uaip-sfw-sev-medium' ),
				esc_html( $running ? __( 'Active', 'uaip-security-firewall' ) : __( 'Installed', 'uaip-security-firewall' ) ),
				esc_html( $running ? __( 'The early firewall is running on this request.', 'uaip-security-firewall' ) : __( 'Installed — may need a few seconds, or a PHP reload, to take effect.', 'uaip-security-firewall' ) )
			);
		}
		echo '<form method="post">';
		wp_nonce_field( 'uaip_sfw_firewall' );
		if ( $installed ) {
			echo '<input type="hidden" name="extended_on" value="" />';
			submit_button( __( 'Disable extended protection', 'uaip-security-firewall' ), 'delete', 'uaip_sfw_fw_extended', false );
		} else {
			echo '<input type="hidden" name="extended_on" value="1" />';
			submit_button( __( 'Enable extended protection', 'uaip-security-firewall' ), 'secondary', 'uaip_sfw_fw_extended', false );
		}
		echo '</form></div>';
		} // end Extended Protection (Pro-only)

		// Recent events.
		echo '<div class="uaip-sfw-card"><h2 style="display:flex;justify-content:space-between;align-items:center;">' . esc_html__( 'Recent firewall events', 'uaip-security-firewall' );
		echo '<form method="post" style="margin:0;">';
		wp_nonce_field( 'uaip_sfw_firewall' );
		submit_button( __( 'Clear log', 'uaip-security-firewall' ), 'link-delete small', 'uaip_sfw_fw_clear', false );
		echo '</form></h2>';

		if ( empty( $stats['recent'] ) ) {
			echo '<p class="uaip-sfw-empty">' . esc_html__( 'No attacks detected yet.', 'uaip-security-firewall' ) . '</p>';
		} else {
			echo '<table class="widefat striped uaip-sfw-table"><thead><tr><th>' . esc_html__( 'When', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Action', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Type', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Rule', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Score', 'uaip-security-firewall' ) . '</th><th>IP</th><th>' . esc_html__( 'Request', 'uaip-security-firewall' ) . '</th></tr></thead><tbody>';
			foreach ( $stats['recent'] as $e ) {
				$badge = ( 'block' === $e['action'] ) ? 'uaip-sfw-sev-critical' : 'uaip-sfw-sev-medium';
				printf(
					'<tr><td>%s</td><td><span class="uaip-sfw-sev %s">%s</span></td><td>%s</td><td>%s</td><td>%d</td><td><code>%s</code></td><td><code class="uaip-sfw-uri">%s</code></td></tr>',
					esc_html( human_time_diff( (int) $e['ts'] ) . ' ' . __( 'ago', 'uaip-security-firewall' ) ),
					esc_attr( $badge ),
					esc_html( ucfirst( $e['action'] ) ),
					esc_html( strtoupper( $e['class'] ) ),
					esc_html( $e['rule'] ),
					(int) $e['score'],
					esc_html( $e['ip'] ),
					esc_html( $e['uri'] )
				);
			}
			echo '</tbody></table>';
		}
		echo '</div>';

		// Geo-blocking (Pro).
		$this->render_geo_card();

		echo '</div>';
	}

	/**
	 * Suggest an IP source from what this request looks like.
	 *
	 * @return string Translated hint, or ''.
	 */
	private function ip_source_hint() {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated by Uaip_Sfw_IP::valid().
		$remote = Uaip_Sfw_IP::valid( isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '' );
		$cf     = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && '' !== Uaip_Sfw_IP::valid( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
		$xff    = ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		$real   = ! empty( $_SERVER['HTTP_X_REAL_IP'] );
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$source = (string) Uaip_Sfw_Settings::get( 'ip_source', 'remote_addr' );

		if ( $cf && Uaip_Sfw_IP::in_list( $remote, Uaip_Sfw_IP::CLOUDFLARE ) && 'cloudflare' !== $source ) {
			return __( 'This request came through Cloudflare. Choose "Cloudflare" so the firewall sees real visitor IPs.', 'uaip-security-firewall' );
		}
		if ( ( $xff || $real ) && 'remote_addr' === $source ) {
			/* translators: %s: proxy IP address */
			return sprintf( __( 'This request came through a proxy at %s. If that is your own proxy or load balancer, choose a reverse-proxy option and add it to the trusted proxies.', 'uaip-security-firewall' ), $remote );
		}
		return '';
	}

	/**
	 * Country / geo-blocking card (Pro), with resolver guidance.
	 */
	private function render_geo_card() {
		$is_pro = $this->plugin->license->is_pro();
		$geo    = $this->plugin->module( 'geo_blocking' );

		if ( $geo && isset( $_POST['uaip_sfw_geo_save'] ) && check_admin_referer( 'uaip_sfw_geo' ) ) {
			Uaip_Sfw_Settings::update( array(
				'geo_enabled'       => ! empty( $_POST['geo_enabled'] ),
				'geo_mode'          => ( isset( $_POST['geo_mode'] ) && 'allow' === $_POST['geo_mode'] ) ? 'allow' : 'block',
				'geo_countries'     => isset( $_POST['geo_countries'] ) ? sanitize_text_field( wp_unslash( $_POST['geo_countries'] ) ) : '',
				'geo_block_unknown' => ! empty( $_POST['geo_block_unknown'] ),
				'geo_bypass_ips'    => isset( $_POST['geo_bypass_ips'] ) ? sanitize_textarea_field( wp_unslash( $_POST['geo_bypass_ips'] ) ) : '',
			) );
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Geo-blocking settings saved.', 'uaip-security-firewall' ) . '</p></div>';
		}

		if ( ! $is_pro || ! $geo ) {
			echo '<div class="uaip-sfw-card uaip-sfw-mod-locked" style="border-left:4px solid #f0b429;margin-top:18px;">';
			echo '<h2 style="display:flex;align-items:center;gap:8px;"><span class="dashicons dashicons-admin-site"></span> ' . esc_html__( 'Country / Geo Blocking', 'uaip-security-firewall' ) . ' <span class="uaip-sfw-badge uaip-sfw-badge-locked">' . esc_html__( 'Pro', 'uaip-security-firewall' ) . '</span></h2>';
			echo '<p>' . esc_html__( 'Block or allow visitors by country. UAIP Security resolves the visitor\'s country from your CDN headers (e.g. Cloudflare) or the UAIP Security Cloud — no database to install.', 'uaip-security-firewall' ) . '</p>';
			printf( '<a class="button button-primary" href="%s">%s</a>', esc_url( admin_url( 'admin.php?page=uaip-sfw-plans' ) ), esc_html__( 'Upgrade to Pro', 'uaip-security-firewall' ) );
			echo '</div>';
			return;
		}

		$s        = Uaip_Sfw_Settings::all();
		$detected = method_exists( $geo, 'current_country' ) ? $geo->current_country() : null;
		$stats    = $geo->stats();

		echo '<div class="uaip-sfw-card" style="margin-top:18px;">';
		echo '<h2 style="display:flex;align-items:center;gap:8px;"><span class="dashicons dashicons-admin-site"></span> ' . esc_html__( 'Country / Geo Blocking', 'uaip-security-firewall' ) . '</h2>';
		printf(
			'<p>%s <strong>%s</strong> &nbsp;·&nbsp; %s <strong>%d</strong></p>',
			esc_html__( 'Your detected country:', 'uaip-security-firewall' ),
			esc_html( $detected ? $detected : __( 'unknown (no CDN header / cloud)', 'uaip-security-firewall' ) ),
			esc_html__( 'Blocked (15m):', 'uaip-security-firewall' ),
			(int) $geo->recent_block_count()
		);

		echo '<form method="post">';
		wp_nonce_field( 'uaip_sfw_geo' );
		$this->switch_field( 'geo_enabled', __( 'Enable geo-blocking', 'uaip-security-firewall' ), __( 'Filter visitors by country.', 'uaip-security-firewall' ), $s['geo_enabled'] );

		echo '<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Mode', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Block the listed countries, or allow only the listed countries.', 'uaip-security-firewall' ) . '</p></div><div>';
		printf( '<label style="margin-right:16px;"><input type="radio" name="geo_mode" value="block" %s /> %s</label>', checked( 'allow' !== $s['geo_mode'], true, false ), esc_html__( 'Blocklist', 'uaip-security-firewall' ) );
		printf( '<label><input type="radio" name="geo_mode" value="allow" %s /> %s</label>', checked( 'allow' === $s['geo_mode'], true, false ), esc_html__( 'Allowlist', 'uaip-security-firewall' ) );
		echo '</div></div>';

		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Countries', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'ISO-3166 two-letter codes, comma separated (e.g. RU, CN, KP).', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<input type="text" name="geo_countries" class="regular-text code" value="%s" placeholder="RU, CN, KP" /></div>', esc_attr( $s['geo_countries'] ) );

		$this->switch_field( 'geo_block_unknown', __( 'Block unknown locations', 'uaip-security-firewall' ), __( 'Block requests whose country cannot be determined.', 'uaip-security-firewall' ), $s['geo_block_unknown'] );

		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Bypass IPs', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'These IPs are never geo-blocked (one per line).', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<textarea name="geo_bypass_ips" rows="2" class="large-text code">%s</textarea></div>', esc_textarea( $s['geo_bypass_ips'] ) );

		echo '<p>';
		submit_button( __( 'Save geo-blocking', 'uaip-security-firewall' ), 'primary', 'uaip_sfw_geo_save', false );
		echo '</p></form>';

		if ( ! empty( $stats['countries'] ) ) {
			arsort( $stats['countries'] );
			echo '<p><strong>' . esc_html__( 'Top blocked countries:', 'uaip-security-firewall' ) . '</strong> ';
			$bits = array();
			foreach ( array_slice( $stats['countries'], 0, 8, true ) as $cc => $n ) {
				$bits[] = esc_html( $cc . ' (' . (int) $n . ')' );
			}
			echo implode( ', ', $bits ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- each $bits item is esc_html'd above.
		}
		echo '</div>';
	}

	/** User-friendly label for the active scan engine (hides internal codenames). */
	private function scan_engine_label( $engine ) {
		switch ( (string) $engine ) {
			case 'binary':
				return __( 'Active (native YARA)', 'uaip-security-firewall' );
			case 'php-lite':
				return __( 'Active (built-in)', 'uaip-security-firewall' );
			case 'none':
				return __( 'No rules loaded', 'uaip-security-firewall' );
			default:
				return __( 'pending', 'uaip-security-firewall' );
		}
	}

	public function page_scan() {
		/** @var Uaip_Sfw_Scanner $scanner */
		$scanner = $this->plugin->module( 'scanner' );
		if ( ! $scanner ) {
			return;
		}

		if ( isset( $_POST['uaip_sfw_scan_now'] ) && check_admin_referer( 'uaip_sfw_scan_now' ) && current_user_can( 'manage_options' ) ) {
			$full = ! empty( $_POST['uaip_sfw_full'] );
			if ( $scanner->start( $full ? true : null ) ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Scan started. You can leave this page; it carries on in the background.', 'uaip-security-firewall' ) . '</p></div>';
			} else {
				echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__( 'A scan is already running.', 'uaip-security-firewall' ) . '</p></div>';
			}
		}
		if ( isset( $_POST['uaip_sfw_finding_action'], $_POST['uaip_sfw_finding'] ) && check_admin_referer( 'uaip_sfw_finding' ) && current_user_can( 'manage_options' ) ) {
			$action = sanitize_key( wp_unslash( $_POST['uaip_sfw_finding_action'] ) );
			$res    = $scanner->act( absint( wp_unslash( $_POST['uaip_sfw_finding'] ) ), $action );
			$done   = array(
				'repair'   => __( 'File restored from the official copy.', 'uaip-security-firewall' ),
				'delete'   => __( 'File deleted.', 'uaip-security-firewall' ),
				'ignore'   => __( 'Finding ignored. It comes back if the file changes.', 'uaip-security-firewall' ),
				'unignore' => __( 'Finding restored.', 'uaip-security-firewall' ),
			);
			echo is_wp_error( $res )
				? '<div class="notice notice-error"><p>' . esc_html( $res->get_error_message() ) . '</p></div>'
				: '<div class="notice notice-success is-dismissible"><p>' . esc_html( isset( $done[ $action ] ) ? $done[ $action ] : __( 'Done.', 'uaip-security-firewall' ) ) . '</p></div>';
		}

		$progress = $scanner->progress();
		$scan     = get_option( Uaip_Sfw_Scanner::SUMMARY_OPTION, array() );
		$has_scan = ! empty( $scan );
		$open     = $scanner->findings( 'open' );
		$ignored  = $scanner->findings( 'ignored', 200 );
		$clean    = $has_scan && ! $open;

		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'Malware Scan', 'uaip-security-firewall' ), __( 'Integrity and malware scanning of the whole site', 'uaip-security-firewall' ), 'dashicons-search' );

		// Hero card.
		$state = $progress['running'] ? 'idle' : ( ! $has_scan ? 'idle' : ( $clean ? 'good' : 'bad' ) );
		echo '<div class="uaip-sfw-card uaip-sfw-scan-hero uaip-sfw-scan-' . esc_attr( $state ) . '"><div class="uaip-sfw-scan-hero-main">';
		$icon = $progress['running'] ? 'dashicons-update' : ( 'idle' === $state ? 'dashicons-shield' : ( $clean ? 'dashicons-yes-alt' : 'dashicons-warning' ) );
		printf( '<span class="dashicons %s uaip-sfw-scan-icon"></span><div>', esc_attr( $icon ) );
		if ( $progress['running'] ) {
			echo '<h2>' . esc_html__( 'Scanning…', 'uaip-security-firewall' ) . '</h2>';
			printf(
				'<div id="uaip-sfw-scan-progress" class="uaip-sfw-progress" data-ajax="%s" data-nonce="%s"><div class="uaip-sfw-progress-track"><div class="uaip-sfw-progress-fill" style="width:%d%%"></div></div><p class="uaip-sfw-progress-label">%s</p></div>',
				esc_url( admin_url( 'admin-ajax.php' ) ),
				esc_attr( wp_create_nonce( 'uaip_sfw_scan_step' ) ),
				(int) $progress['percent'],
				esc_html( $this->scan_progress_text( $progress ) )
			);
		} elseif ( ! $has_scan ) {
			echo '<h2>' . esc_html__( 'No scan has run yet', 'uaip-security-firewall' ) . '</h2>';
			echo '<p>' . esc_html__( 'The first scan records every PHP file of your site so later scans only need to check what changed.', 'uaip-security-firewall' ) . '</p>';
		} elseif ( $clean ) {
			echo '<h2>' . esc_html__( 'No problems found', 'uaip-security-firewall' ) . '</h2>';
			printf( '<p>%s</p>', esc_html( $this->scan_when( $scan ) ) );
		} else {
			/* translators: %d: number of findings */
			printf( '<h2>%s</h2>', esc_html( sprintf( _n( '%d issue needs attention', '%d issues need attention', count( $open ), 'uaip-security-firewall' ), count( $open ) ) ) );
			printf( '<p>%s</p>', esc_html( $this->scan_when( $scan ) ) );
		}
		echo '</div></div>';
		if ( ! $progress['running'] ) {
			echo '<form method="post" class="uaip-sfw-scan-action">';
			wp_nonce_field( 'uaip_sfw_scan_now' );
			submit_button( __( 'Scan now', 'uaip-security-firewall' ), 'primary button-hero', 'uaip_sfw_scan_now', false );
			echo '<label class="uaip-sfw-full-scan"><input type="checkbox" name="uaip_sfw_full" value="1"> ' . esc_html__( 'Re-check every file (slower)', 'uaip-security-firewall' ) . '</label>';
			echo '</form>';
		}
		echo '</div>';

		// Detail tiles.
		echo '<div class="uaip-sfw-modules uaip-sfw-scan-meta">';
		$this->stat( 'dashicons-media-code', __( 'PHP files tracked', 'uaip-security-firewall' ), $has_scan && isset( $scan['files'] ) ? number_format_i18n( (int) $scan['files'] ) : '—' );
		$this->stat( 'dashicons-search', __( 'Checked last scan', 'uaip-security-firewall' ), $has_scan ? number_format_i18n( (int) $scan['scanned'] ) : '—' );
		if ( $has_scan && empty( $scan['baseline'] ) && isset( $scan['changes'] ) ) {
			$ch = $scan['changes'];
			$this->stat( 'dashicons-backup', __( 'Changes since previous scan', 'uaip-security-firewall' ), sprintf( '+%d / ~%d / −%d', (int) $ch['added'], (int) $ch['changed'], (int) $ch['removed'] ) );
		}
		$this->stat( 'dashicons-warning', __( 'Open findings', 'uaip-security-firewall' ), $has_scan ? count( $open ) : '—' );
		echo '</div>';

		// ClamAV antivirus status (Pro).
		$this->render_clamav_card();

		if ( $open ) {
			$this->findings_table( __( 'Findings', 'uaip-security-firewall' ), $open, false );
		}
		if ( $ignored ) {
			$this->findings_table( __( 'Ignored', 'uaip-security-firewall' ), $ignored, true );
		}

		echo '<div class="uaip-sfw-card"><h2>' . esc_html__( 'What the scan checks', 'uaip-security-firewall' ) . '</h2><ul class="uaip-sfw-list">';
		foreach ( array(
			__( 'WordPress core files against the official checksums from wordpress.org, and unknown files in wp-admin and wp-includes.', 'uaip-security-firewall' ),
			__( 'Plugins from wordpress.org against their official checksums. Changed files can be restored in one click.', 'uaip-security-firewall' ),
			__( 'Unexpected PHP files in the site root, in wp-content and in the uploads folder.', 'uaip-security-firewall' ),
			__( 'Every other PHP file (themes, custom and premium plugins, wp-config.php, drop-ins) with malware rules.', 'uaip-security-firewall' ),
		) as $line ) {
			echo '<li>' . esc_html( $line ) . '</li>';
		}
		echo '</ul></div>';
		echo '</div>';
	}

	/**
	 * "Last scan 2 hours ago, took 40 seconds".
	 *
	 * @param array $scan Summary.
	 * @return string
	 */
	private function scan_when( array $scan ) {
		$text = sprintf(
			/* translators: %s: human-readable time difference */
			__( 'Last scan %s ago', 'uaip-security-firewall' ),
			human_time_diff( (int) $scan['ts'] )
		);
		if ( isset( $scan['duration'] ) ) {
			/* translators: 1: previous text, 2: duration such as "40 secs" */
			$text = sprintf( __( '%1$s, took %2$s', 'uaip-security-firewall' ), $text, human_time_diff( 0, max( 1, (int) $scan['duration'] ) ) );
		}
		return $text;
	}

	/**
	 * Progress line under the bar.
	 *
	 * @param array $p Progress.
	 * @return string
	 */
	private function scan_progress_text( array $p ) {
		if ( 'walk' === $p['phase'] ) {
			/* translators: %s: number of files found so far */
			return sprintf( __( 'Listing files… %s found', 'uaip-security-firewall' ), number_format_i18n( (int) $p['files'] ) );
		}
		/* translators: 1: files checked, 2: files to check */
		return sprintf( __( 'Checking files… %1$s of %2$s', 'uaip-security-firewall' ), number_format_i18n( (int) $p['checked'] ), number_format_i18n( (int) $p['to_check'] ) );
	}

	/**
	 * AJAX: run a short scan step and report progress (Scan page poller).
	 */
	public function ajax_scan_step() {
		check_ajax_referer( 'uaip_sfw_scan_step' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$scanner  = $this->plugin->module( 'scanner' );
		$progress = $scanner ? $scanner->step( 5 ) : array( 'running' => false );
		if ( ! empty( $progress['running'] ) ) {
			$progress['text'] = $this->scan_progress_text( $progress );
		}
		wp_send_json_success( $progress );
	}

	/**
	 * Findings table with per-row actions.
	 *
	 * @param string $title   Card title.
	 * @param array  $rows    Findings.
	 * @param bool   $ignored Whether these are ignored findings.
	 */
	private function findings_table( $title, array $rows, $ignored ) {
		echo '<div class="uaip-sfw-card"><h2>' . esc_html( $title ) . '</h2>';
		echo '<table class="widefat striped uaip-sfw-table"><thead><tr><th>' . esc_html__( 'Severity', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'File', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'What we found', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Action', 'uaip-security-firewall' ) . '</th></tr></thead><tbody>';
		foreach ( $rows as $f ) {
			echo '<tr><td><span class="uaip-sfw-sev uaip-sfw-sev-' . esc_attr( $f->severity ) . '">' . esc_html( ucfirst( $f->severity ) ) . '</span></td>';
			echo '<td><code>' . esc_html( $f->path ) . '</code></td>';
			echo '<td>' . esc_html( $f->description ) . '<br><span class="uaip-sfw-finding-desc">' . esc_html( $f->rule ) . '</span></td><td class="uaip-sfw-actions">';
			if ( $ignored ) {
				$this->finding_button( $f, 'unignore', __( 'Restore', 'uaip-security-firewall' ), 'button-small' );
			} else {
				if ( 'repair' === $f->fix ) {
					$this->finding_button( $f, 'repair', __( 'Repair', 'uaip-security-firewall' ), 'button-small button-primary', __( 'Replace this file with the official copy from wordpress.org?', 'uaip-security-firewall' ) );
				} elseif ( 'delete' === $f->fix ) {
					$this->finding_button( $f, 'delete', __( 'Delete', 'uaip-security-firewall' ), 'button-small button-link-delete', __( 'Permanently delete this file? Make sure you have a backup.', 'uaip-security-firewall' ) );
				}
				$this->finding_button( $f, 'ignore', __( 'Ignore', 'uaip-security-firewall' ), 'button-small button-link' );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * One finding action button (its own small form).
	 *
	 * @param object $f       Finding.
	 * @param string $action  Action.
	 * @param string $label   Button text.
	 * @param string $class   Button classes.
	 * @param string $confirm Optional confirmation question.
	 */
	private function finding_button( $f, $action, $label, $class, $confirm = '' ) {
		echo '<form method="post" class="uaip-sfw-inline-form"' . ( '' !== $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : '' ) . '>';
		wp_nonce_field( 'uaip_sfw_finding' );
		echo '<input type="hidden" name="uaip_sfw_finding" value="' . (int) $f->id . '">';
		echo '<button type="submit" class="button ' . esc_attr( $class ) . '" name="uaip_sfw_finding_action" value="' . esc_attr( $action ) . '">' . esc_html( $label ) . '</button></form>';
	}

	/**
	 * ClamAV antivirus status / configuration card (Pro), with cPanel guidance.
	 */
	private function render_clamav_card() {
		$is_pro = $this->plugin->license->is_pro();
		$clamav = $this->plugin->module( 'clamav' );

		// Save a socket override (Pro).
		if ( $clamav && isset( $_POST['uaip_sfw_clamav_save'] ) && check_admin_referer( 'uaip_sfw_clamav' ) ) {
			Uaip_Sfw_Settings::update( array( 'clamav_socket' => sanitize_text_field( wp_unslash( $_POST['clamav_socket'] ?? '' ) ) ) );
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'ClamAV connection saved.', 'uaip-security-firewall' ) . '</p></div>';
		}

		if ( ! $is_pro || ! $clamav ) {
			// Free: locked card with cPanel explanation.
			echo '<div class="uaip-sfw-card uaip-sfw-mod-locked" style="border-left:4px solid #f0b429;">';
			echo '<h2 style="display:flex;align-items:center;gap:8px;"><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__( 'ClamAV Antivirus', 'uaip-security-firewall' ) . ' <span class="uaip-sfw-badge uaip-sfw-badge-locked">' . esc_html__( 'Pro', 'uaip-security-firewall' ) . '</span></h2>';
			echo '<p>' . esc_html__( 'Add a second malware engine on top of YARA. UAIP Security talks to ClamAV over its socket — no shell access needed — and falls back to the cloud scanner when a local daemon is not reachable.', 'uaip-security-firewall' ) . '</p>';
			echo '<p><strong>' . esc_html__( 'On cPanel:', 'uaip-security-firewall' ) . '</strong> ' . esc_html__( 'On a VPS/dedicated server with root, install clamav-daemon and we use it directly. On locked-down shared cPanel (no exec, socket not readable), suspicious files are scanned by the UAIP Security Cloud ClamAV worker instead.', 'uaip-security-firewall' ) . '</p>';
			printf( '<a class="button button-primary" href="%s">%s</a>', esc_url( admin_url( 'admin.php?page=uaip-sfw-plans' ) ), esc_html__( 'Upgrade to Pro', 'uaip-security-firewall' ) );
			echo '</div>';
			return;
		}

		// Pro: live status.
		$method  = method_exists( $clamav, 'method' ) ? $clamav->method() : 'none';
		$version = method_exists( $clamav, 'version' ) ? $clamav->version() : null;
		$labels  = array(
			'clamd-socket' => __( 'Connected via Unix socket', 'uaip-security-firewall' ),
			'clamd-tcp'    => __( 'Connected via TCP', 'uaip-security-firewall' ),
			'clamscan'     => __( 'Using clamscan binary', 'uaip-security-firewall' ),
			'cloud'        => __( 'Using UAIP Security Cloud worker', 'uaip-security-firewall' ),
			'none'         => __( 'No ClamAV reachable', 'uaip-security-firewall' ),
		);
		$ok = ( 'none' !== $method );

		echo '<div class="uaip-sfw-card">';
		echo '<h2 style="display:flex;align-items:center;gap:8px;"><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__( 'ClamAV Antivirus', 'uaip-security-firewall' ) . '</h2>';
		printf(
			'<p><span class="uaip-sfw-sev %s">%s</span> %s%s</p>',
			esc_attr( $ok ? 'uaip-sfw-sev-low' : 'uaip-sfw-sev-high' ),
			esc_html( $ok ? __( 'Active', 'uaip-security-firewall' ) : __( 'Unavailable', 'uaip-security-firewall' ) ),
			esc_html( isset( $labels[ $method ] ) ? $labels[ $method ] : $method ),
			$version ? ' — <code>' . esc_html( $version ) . '</code>' : ''
		);
		echo '<form method="post"><div class="uaip-sfw-field" style="align-items:flex-start;">';
		wp_nonce_field( 'uaip_sfw_clamav' );
		echo '<div class="uaip-sfw-field-text"><strong>' . esc_html__( 'clamd socket (optional)', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Leave blank to auto-detect. Override for custom cPanel paths, e.g. unix:///var/clamd or tcp://127.0.0.1:3310', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<input type="text" name="clamav_socket" class="regular-text code" value="%s" placeholder="auto-detect" /></div>', esc_attr( Uaip_Sfw_Settings::get( 'clamav_socket', '' ) ) );
		echo '<p>';
		submit_button( __( 'Save & test connection', 'uaip-security-firewall' ), 'secondary', 'uaip_sfw_clamav_save', false );
		echo '</p></form></div>';
	}

	/**
	 * Hardening page — apply one-click security toggles.
	 */
	public function page_hardening() {
		$harden = $this->plugin->module( 'hardening' );

		if ( isset( $_POST['uaip_sfw_harden_save'] ) && check_admin_referer( 'uaip_sfw_hardening' ) ) {
			foreach ( array_keys( $harden->actions() ) as $key ) {
				$enabled = ! empty( $_POST[ $key ] );
				$res     = $harden->apply( $key, $enabled );
				if ( is_wp_error( $res ) ) {
					echo '<div class="notice notice-error"><p>' . esc_html( $res->get_error_message() ) . '</p></div>';
					$enabled = false; // do not record as on if it failed
				}
				Uaip_Sfw_Settings::update( array( $key => $enabled ) );
			}
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Hardening settings applied.', 'uaip-security-firewall' ) . '</p></div>';
		}

		$s = Uaip_Sfw_Settings::all();
		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'Hardening', 'uaip-security-firewall' ), __( 'Lock down common attack surfaces', 'uaip-security-firewall' ), 'dashicons-admin-tools' );
		echo '<form method="post"><div class="uaip-sfw-card uaip-sfw-set-group">';
		wp_nonce_field( 'uaip_sfw_hardening' );
		echo '<h2><span class="dashicons dashicons-shield"></span> ' . esc_html__( 'Recommended actions', 'uaip-security-firewall' ) . '</h2>';
		foreach ( $harden->actions() as $key => $a ) {
			$this->switch_field( $key, $a['label'], $a['desc'], ! empty( $s[ $key ] ) );
		}
		echo '<p>';
		submit_button( __( 'Apply hardening', 'uaip-security-firewall' ), 'primary button-hero', 'uaip_sfw_harden_save', false );
		echo '</p></div></form></div>';
	}

	/**
	 * Login Page customizer — clients brand their own wp-login.php.
	 */
	public function page_login_brand() {
		if ( isset( $_POST['uaip_sfw_login_save'] ) && check_admin_referer( 'uaip_sfw_login_brand' ) && current_user_can( 'manage_options' ) ) {
			Uaip_Sfw_Settings::update( array(
				'login_brand_enabled' => ! empty( $_POST['login_brand_enabled'] ),
				'login_logo_url'      => isset( $_POST['login_logo_url'] ) ? esc_url_raw( wp_unslash( $_POST['login_logo_url'] ) ) : '',
				'login_bg_from'       => isset( $_POST['login_bg_from'] ) ? sanitize_hex_color( wp_unslash( $_POST['login_bg_from'] ) ) : '',
				'login_bg_to'         => isset( $_POST['login_bg_to'] ) ? sanitize_hex_color( wp_unslash( $_POST['login_bg_to'] ) ) : '',
				'login_button_color'  => isset( $_POST['login_button_color'] ) ? sanitize_hex_color( wp_unslash( $_POST['login_button_color'] ) ) : '',
			) );
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Login page settings saved.', 'uaip-security-firewall' ) . '</p></div>';
		}

		$s = Uaip_Sfw_Settings::all();
		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'Login Page', 'uaip-security-firewall' ), __( 'Brand your WordPress login screen', 'uaip-security-firewall' ), 'dashicons-admin-appearance' );

		echo '<form method="post"><div class="uaip-sfw-card uaip-sfw-set-group">';
		wp_nonce_field( 'uaip_sfw_login_brand' );
		echo '<h2><span class="dashicons dashicons-art"></span> ' . esc_html__( 'Branding', 'uaip-security-firewall' ) . '</h2>';

		$this->switch_field( 'login_brand_enabled', __( 'Enable custom login page', 'uaip-security-firewall' ), __( 'Apply your branding to wp-login.php.', 'uaip-security-firewall' ), $s['login_brand_enabled'] );

		// Logo.
		echo '<div class="uaip-sfw-field" style="align-items:flex-start;"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Logo', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Shown above the login form.', 'uaip-security-firewall' ) . '</p></div><div>';
		printf( '<input type="text" id="login_logo_url" name="login_logo_url" class="regular-text" value="%s" placeholder="https://…/logo.png" /> ', esc_attr( $s['login_logo_url'] ) );
		echo '<button type="button" class="button" id="uaip-sfw-logo-upload">' . esc_html__( 'Choose image', 'uaip-security-firewall' ) . '</button> ';
		echo '<button type="button" class="button-link" id="uaip-sfw-logo-remove">' . esc_html__( 'Remove', 'uaip-security-firewall' ) . '</button>';
		printf(
			'<br><img id="uaip-sfw-logo-preview" src="%s" style="max-height:64px;margin-top:10px;%s" alt="" />',
			esc_attr( $s['login_logo_url'] ),
			$s['login_logo_url'] ? '' : 'display:none;'
		);
		echo '</div></div>';

		// Colors.
		$this->color_row( 'login_bg_from', __( 'Background colour', 'uaip-security-firewall' ), __( 'Top of the page background.', 'uaip-security-firewall' ), $s['login_bg_from'] );
		$this->color_row( 'login_bg_to', __( 'Background colour (gradient end)', 'uaip-security-firewall' ), __( 'Leave blank for a solid colour.', 'uaip-security-firewall' ), $s['login_bg_to'] );
		$this->color_row( 'login_button_color', __( 'Button colour', 'uaip-security-firewall' ), __( 'The “Log In” button and focus accents.', 'uaip-security-firewall' ), $s['login_button_color'] );

		echo '<p>';
		submit_button( __( 'Save login page', 'uaip-security-firewall' ), 'primary button-hero', 'uaip_sfw_login_save', false );
		echo ' <a class="button" href="' . esc_url( wp_login_url() ) . '" target="_blank" rel="noopener">' . esc_html__( 'Preview (incognito window)', 'uaip-security-firewall' ) . '</a>';
		echo '</p>';
		echo '<p class="uaip-sfw-empty">' . esc_html__( 'Tip: open the preview in a private/incognito window, since you are already logged in here.', 'uaip-security-firewall' ) . '</p>';
		echo '</div></form></div>';
	}

	/** A WP color-picker field row. */
	private function color_row( $name, $label, $desc, $value ) {
		echo '<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>' . esc_html( $label ) . '</strong><p>' . esc_html( $desc ) . '</p></div>';
		printf(
			'<input type="text" name="%s" class="uaip-sfw-color" value="%s" data-default-color="%s" />',
			esc_attr( $name ),
			esc_attr( $value ),
			esc_attr( $value )
		);
		echo '</div>';
	}

	public function page_audit() {
		$audit  = $this->plugin->module( 'audit_log' );

		// Clear-log action (nonce-protected).
		if ( isset( $_POST['uaip_sfw_clear_audit'] ) && check_admin_referer( 'uaip_sfw_clear_audit' ) ) {
			$removed = ( $audit && method_exists( $audit, 'clear' ) ) ? (int) $audit->clear() : 0;
			echo '<div class="notice notice-success is-dismissible"><p>';
			printf(
				/* translators: %d: number of events cleared */
				esc_html__( 'Audit log cleared (%d events removed).', 'uaip-security-firewall' ),
				(int) $removed
			);
			echo '</p></div>';
		}

		$events = $audit && method_exists( $audit, 'recent' ) ? $audit->recent( 100 ) : array();
		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'Audit Log', 'uaip-security-firewall' ), __( 'Security-relevant activity on your site', 'uaip-security-firewall' ), 'dashicons-list-view' );
		echo '<div class="uaip-sfw-card">';

		// Clear-log button (only when there is something to clear).
		if ( ! empty( $events ) ) {
			echo '<form method="post" style="float:right;margin:-4px 0 8px" onsubmit="return confirm(\'' . esc_js( __( 'Clear all local audit log entries? Synced events stay in your cloud activity log.', 'uaip-security-firewall' ) ) . '\');">';
			wp_nonce_field( 'uaip_sfw_clear_audit' );
			submit_button( __( 'Clear log', 'uaip-security-firewall' ), 'delete small', 'uaip_sfw_clear_audit', false );
			echo '</form><div style="clear:both"></div>';
		}

		if ( empty( $events ) ) {
			echo '<p class="uaip-sfw-empty">' . esc_html__( 'No events recorded yet.', 'uaip-security-firewall' ) . '</p>';
		} else {
			echo '<table class="widefat striped uaip-sfw-table"><thead><tr><th>' . esc_html__( 'When', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Event', 'uaip-security-firewall' ) . '</th><th>IP</th></tr></thead><tbody>';
			foreach ( $events as $e ) {
				printf(
					'<tr><td>%s</td><td><span class="uaip-sfw-ev-type uaip-sfw-ev-%s">%s</span></td><td><code>%s</code></td></tr>',
					esc_html( human_time_diff( (int) $e['ts'] ) . ' ' . __( 'ago', 'uaip-security-firewall' ) ),
					esc_attr( $this->event_severity( $e['type'] ) ),
					esc_html( $this->event_label( $e['type'] ) ),
					esc_html( isset( $e['ip'] ) ? $e['ip'] : '' )
				);
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';
	}

	public function page_settings() {
		if ( isset( $_POST['uaip_sfw_save_settings'] ) && check_admin_referer( 'uaip_sfw_settings' ) ) {
			Uaip_Sfw_Settings::update( array(
				'waf_enabled'       => ! empty( $_POST['waf_enabled'] ),
				'rate_limit_enabled' => ! empty( $_POST['rate_limit_enabled'] ),
				'scan_yara_enabled' => ! empty( $_POST['scan_yara_enabled'] ),
				'login_protection'  => ! empty( $_POST['login_protection'] ),
				'login_breached_pw' => ! empty( $_POST['login_breached_pw'] ),
				'audit_log_enabled' => ! empty( $_POST['audit_log_enabled'] ),
				'anomaly_alerts'    => ! empty( $_POST['anomaly_alerts'] ),
				'alert_email'       => isset( $_POST['alert_email'] ) ? sanitize_email( wp_unslash( $_POST['alert_email'] ) ) : '',
				'delete_data_on_uninstall' => ! empty( $_POST['delete_data_on_uninstall'] ),
			) );
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'uaip-security-firewall' ) . '</p></div>';
		}
		$s = Uaip_Sfw_Settings::all();
		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'Settings', 'uaip-security-firewall' ), __( 'Turn protections on or off', 'uaip-security-firewall' ), 'dashicons-admin-generic' );

		echo '<form method="post">';
		wp_nonce_field( 'uaip_sfw_settings' );

		// Group: Firewall & traffic.
		$this->settings_group( __( 'Firewall & Traffic', 'uaip-security-firewall' ), 'dashicons-shield', array(
			array( 'waf_enabled', __( 'Web Application Firewall', 'uaip-security-firewall' ), __( 'Block SQLi, RCE, XSS and traversal attacks.', 'uaip-security-firewall' ), $s['waf_enabled'] ),
			array( 'rate_limit_enabled', __( 'Rate limiting & bot throttling', 'uaip-security-firewall' ), __( 'Slow down scanners and abusive crawlers.', 'uaip-security-firewall' ), $s['rate_limit_enabled'] ),
		) );

		// Group: Malware scanning.
		$this->settings_group( __( 'Malware Scanning', 'uaip-security-firewall' ), 'dashicons-search', array(
			array( 'scan_yara_enabled', __( 'YARA malware scanning', 'uaip-security-firewall' ), __( 'Detect webshells and backdoors in your files.', 'uaip-security-firewall' ), $s['scan_yara_enabled'] ),
		) );

		// Group: Login security.
		$this->settings_group( __( 'Login Security', 'uaip-security-firewall' ), 'dashicons-lock', array(
			array( 'login_protection', __( 'Brute-force protection', 'uaip-security-firewall' ), __( 'Lock out IPs and require a CAPTCHA after repeated failed logins.', 'uaip-security-firewall' ), $s['login_protection'] ),
			array( 'login_breached_pw', __( 'Block compromised passwords', 'uaip-security-firewall' ), __( 'Stop privileged users signing in with a known-breached password.', 'uaip-security-firewall' ), $s['login_breached_pw'] ),
		) );

		// Two-factor authentication is enrolled per user account (not a global
		// toggle), so reflect THIS user's real state and link to its own page.
		$twofa_on = $this->twofa_active();
		echo '<div class="uaip-sfw-card uaip-sfw-set-group">';
		printf( '<h2><span class="dashicons %s"></span> %s</h2>', 'dashicons-smartphone', esc_html__( 'Two-Factor Authentication', 'uaip-security-firewall' ) );
		echo '<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Two-factor authentication (TOTP)', 'uaip-security-firewall' ) . '</strong><p>' .
			esc_html__( 'Require a one-time code at login. Set up per user account.', 'uaip-security-firewall' ) . ' ' .
			( $twofa_on
				? esc_html__( 'Status: active on your account.', 'uaip-security-firewall' )
				: esc_html__( 'Status: not set up on your account.', 'uaip-security-firewall' ) ) .
			'</p></div>';
		printf(
			'<a href="%s" class="button">%s</a></div>',
			esc_url( Uaip_Sfw_Twofa_Page::url() ),
			$twofa_on ? esc_html__( 'Manage', 'uaip-security-firewall' ) : esc_html__( 'Set up 2FA', 'uaip-security-firewall' )
		);
		echo '</div>';

		// Group: Auditing.
		$this->settings_group( __( 'Auditing', 'uaip-security-firewall' ), 'dashicons-list-view', array(
			array( 'audit_log_enabled', __( 'Activity audit log', 'uaip-security-firewall' ), __( 'Record logins, plugin and theme changes.', 'uaip-security-firewall' ), $s['audit_log_enabled'] ),
		) );

		// Group: Monitoring & alerts.
		echo '<div class="uaip-sfw-card uaip-sfw-set-group">';
		printf( '<h2><span class="dashicons %s"></span> %s</h2>', 'dashicons-cloud', esc_html__( 'Monitoring & Alerts', 'uaip-security-firewall' ) );
		$this->switch_field( 'anomaly_alerts', __( 'Traffic anomaly email alerts', 'uaip-security-firewall' ), __( 'Get notified when traffic or login patterns look abnormal.', 'uaip-security-firewall' ), $s['anomaly_alerts'] );
		echo '<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>' . esc_html__( 'Alert email', 'uaip-security-firewall' ) . '</strong><p>' . esc_html__( 'Where to send security notifications.', 'uaip-security-firewall' ) . '</p></div>';
		printf( '<input type="email" name="alert_email" class="regular-text" value="%s" placeholder="you@example.com" /></div>', esc_attr( $s['alert_email'] ) );
		echo '</div>';

		// Group: Data & uninstall (opt-in destructive cleanup).
		echo '<div class="uaip-sfw-card uaip-sfw-set-group">';
		printf( '<h2><span class="dashicons %s"></span> %s</h2>', 'dashicons-trash', esc_html__( 'Data & Uninstall', 'uaip-security-firewall' ) );
		$this->switch_field(
			'delete_data_on_uninstall',
			__( 'Delete all data when the plugin is removed', 'uaip-security-firewall' ),
			__( 'Off by default: deactivating or updating keeps your settings. When ON, deleting the plugin permanently erases all UAIP Security settings, license, 2FA enrollments, scan results and logs. Deactivation never deletes data. Tip: use "Disconnect" on the License page first to release your cloud seat.', 'uaip-security-firewall' ),
			! empty( $s['delete_data_on_uninstall'] )
		);
		echo '</div>';

		echo '<p>';
		submit_button( __( 'Save settings', 'uaip-security-firewall' ), 'primary button-hero', 'uaip_sfw_save_settings', false );
		echo '</p>';
		echo '</form></div>';
	}

	/**
	 * Render a settings card with a set of switch fields.
	 *
	 * @param string $title
	 * @param string $icon
	 * @param array  $fields Each: array(name, label, desc, checked).
	 */
	private function settings_group( $title, $icon, $fields ) {
		echo '<div class="uaip-sfw-card uaip-sfw-set-group">';
		printf( '<h2><span class="dashicons %s"></span> %s</h2>', esc_attr( $icon ), esc_html( $title ) );
		foreach ( $fields as $f ) {
			$this->switch_field( $f[0], $f[1], $f[2], $f[3] );
		}
		echo '</div>';
	}

	/**
	 * A single toggle-switch field row.
	 */
	private function switch_field( $name, $label, $desc, $checked ) {
		printf(
			'<div class="uaip-sfw-field"><div class="uaip-sfw-field-text"><strong>%s</strong><p>%s</p></div>' .
			'<label class="uaip-sfw-toggle"><input type="checkbox" name="%s" value="1" %s /><span class="uaip-sfw-toggle-track"></span></label></div>',
			esc_html( $label ),
			esc_html( $desc ),
			esc_attr( $name ),
			checked( (bool) $checked, true, false )
		);
	}

	// -----------------------------------------------------------------
	// Dashboard
	// -----------------------------------------------------------------
	public function page_dashboard() {
		$tier      = $this->plugin->license->tier();
		$is_pro    = $this->plugin->license->is_pro();
		$scan      = get_option( 'uaip_sfw_last_scan_summary', array() );
		$waf       = $this->plugin->module( 'waf' );
		$connected = Uaip_Sfw_Cloud_API::instance()->is_connected();

		$modules = $this->module_status();
		$score   = $this->security_score( $modules, $connected );

		echo '<div class="wrap uaip-sfw-wrap">';

		// ---- Header ----
		echo '<div class="uaip-sfw-header">';
		echo '<div class="uaip-sfw-header-title"><span class="dashicons dashicons-shield"></span><div><h1>UAIP Security Firewall</h1>';
		echo '<p class="uaip-sfw-sub">' . esc_html__( 'Endpoint firewall, malware scanning & login protection', 'uaip-security-firewall' ) . '</p></div></div>';
		printf(
			'<span class="uaip-sfw-tier uaip-sfw-tier-%1$s">%2$s</span>',
			esc_attr( $tier ),
			esc_html( strtoupper( $tier ) )
		);
		echo '</div>';

		// ---- Top: score + quick stats ----
		echo '<div class="uaip-sfw-grid-top">';

		// Security score ring.
		$grade = $this->score_grade( $score );
		echo '<div class="uaip-sfw-card uaip-sfw-score-card">';
		printf(
			'<div class="uaip-sfw-score-ring uaip-sfw-score-%1$s" style="--score:%2$d;"><div class="uaip-sfw-score-num">%2$d<span>/100</span></div></div>',
			esc_attr( $grade['key'] ),
			(int) $score
		);
		echo '<div class="uaip-sfw-score-meta">';
		printf( '<div class="uaip-sfw-score-label uaip-sfw-score-%s">%s</div>', esc_attr( $grade['key'] ), esc_html( $grade['label'] ) );
		echo '<p>' . esc_html( $grade['hint'] ) . '</p>';
		printf(
			'<a class="button button-primary" href="%s">%s</a>',
			esc_url( admin_url( 'admin.php?page=uaip-sfw-settings' ) ),
			esc_html__( 'Improve my score', 'uaip-security-firewall' )
		);
		echo '</div></div>';

		// Quick stats.
		echo '<div class="uaip-sfw-stats">';
		$this->stat( 'dashicons-shield-alt', __( 'Attacks blocked (15m)', 'uaip-security-firewall' ), $waf && method_exists( $waf, 'recent_block_count' ) ? (int) $waf->recent_block_count() : 0 );
		$this->stat( 'dashicons-search', __( 'Last scan findings', 'uaip-security-firewall' ), isset( $scan['findings'] ) ? (int) $scan['findings'] : '—' );
		$this->stat( 'dashicons-admin-tools', __( 'Malware scanner', 'uaip-security-firewall' ), isset( $scan['engine'] ) ? $this->scan_engine_label( $scan['engine'] ) : __( 'pending', 'uaip-security-firewall' ) );
		$this->stat( 'dashicons-cloud', __( 'Cloud', 'uaip-security-firewall' ), $connected ? __( 'connected', 'uaip-security-firewall' ) : __( 'standalone', 'uaip-security-firewall' ) );
		echo '</div>';

		echo '</div>'; // grid-top

		// ---- Protection status grid ----
		echo '<h2 class="uaip-sfw-section">' . esc_html__( 'Protection status', 'uaip-security-firewall' ) . '</h2>';
		echo '<div class="uaip-sfw-modules">';
		foreach ( $modules as $m ) {
			$this->module_card( $m );
		}
		echo '</div>';

		// ---- Two columns: recent activity + next steps ----
		echo '<div class="uaip-sfw-grid-bottom">';

		// Recent activity.
		echo '<div class="uaip-sfw-card uaip-sfw-activity">';
		echo '<h2>' . esc_html__( 'Recent activity', 'uaip-security-firewall' ) . '</h2>';
		$audit  = $this->plugin->module( 'audit_log' );
		$events = $audit && method_exists( $audit, 'recent' ) ? $audit->recent( 6 ) : array();
		if ( empty( $events ) ) {
			echo '<p class="uaip-sfw-empty">' . esc_html__( 'No security events recorded yet. That\'s a good thing.', 'uaip-security-firewall' ) . '</p>';
		} else {
			echo '<ul class="uaip-sfw-events">';
			foreach ( $events as $e ) {
				printf(
					'<li><span class="uaip-sfw-ev-type uaip-sfw-ev-%s">%s</span><span class="uaip-sfw-ev-time">%s</span></li>',
					esc_attr( $this->event_severity( $e['type'] ) ),
					esc_html( $this->event_label( $e['type'] ) ),
					esc_html( human_time_diff( (int) $e['ts'] ) . ' ' . __( 'ago', 'uaip-security-firewall' ) )
				);
			}
			echo '</ul>';
		}
		printf(
			'<a class="uaip-sfw-link" href="%s">%s &rarr;</a>',
			esc_url( admin_url( 'admin.php?page=uaip-sfw-audit' ) ),
			esc_html__( 'View full audit log', 'uaip-security-firewall' )
		);
		echo '</div>';

		// Next steps / recommendations.
		echo '<div class="uaip-sfw-card uaip-sfw-next">';
		echo '<h2>' . esc_html__( 'Recommended next steps', 'uaip-security-firewall' ) . '</h2>';
		echo '<ul class="uaip-sfw-todo">';
		foreach ( $this->recommendations( $modules, $connected, $is_pro ) as $rec ) {
			printf(
				'<li class="%s"><span class="dashicons %s"></span><div><strong>%s</strong><p>%s</p>%s</div></li>',
				$rec['done'] ? 'uaip-sfw-done' : '',
				esc_attr( $rec['done'] ? 'dashicons-yes-alt' : 'dashicons-arrow-right-alt2' ),
				esc_html( $rec['title'] ),
				esc_html( $rec['desc'] ),
				$rec['done'] || empty( $rec['url'] ) ? '' : sprintf( '<a class="button button-small" href="%s">%s</a>', esc_url( $rec['url'] ), esc_html( $rec['cta'] ) )
			);
		}
		echo '</ul>';
		echo '</div>';

		echo '</div>'; // grid-bottom

		// ---- Upgrade banner (Free only) ----
		if ( ! $is_pro ) {
			echo '<div class="uaip-sfw-upsell">';
			echo '<div><h2>' . esc_html__( 'Unlock UAIP Security Pro', 'uaip-security-firewall' ) . '</h2>';
			echo '<p>' . esc_html__( 'ClamAV antivirus, cloud threat intelligence, one-click malware cleanup, geo-blocking, real-time anomaly alerts and a multi-site dashboard.', 'uaip-security-firewall' ) . '</p></div>';
			printf(
				'<a class="button button-hero button-primary" href="%s">%s</a>',
				esc_url( admin_url( 'admin.php?page=uaip-sfw-plans' ) ),
				esc_html__( 'Compare Free vs Pro', 'uaip-security-firewall' )
			);
			echo '</div>';
		}

		echo '</div>'; // wrap
	}

	// -----------------------------------------------------------------
	// Dashboard helpers
	// -----------------------------------------------------------------

	/** A small quick-stat tile. */
	private function stat( $icon, $label, $value ) {
		printf(
			'<div class="uaip-sfw-card uaip-sfw-stat"><span class="dashicons %s"></span><div class="uaip-sfw-stat-num">%s</div><div class="uaip-sfw-stat-label">%s</div></div>',
			esc_attr( $icon ),
			esc_html( $value ),
			esc_html( $label )
		);
	}

	/**
	 * Whether the current user has two-factor authentication enrolled. 2FA is a
	 * per-user feature (set up on the Two-Factor page), so its "active" status
	 * reflects the current account's enrollment, not a global setting.
	 *
	 * @return bool
	 */
	private function twofa_active() {
		$twofa = $this->plugin->module( 'twofa' );
		return $twofa ? in_array( true, $twofa->methods( wp_get_current_user() ), true ) : false;
	}

	/**
	 * Current on/off + tier state for each protection module.
	 *
	 * @return array<int,array>
	 */
	private function module_status() {
		return array(
			array( 'key' => 'waf', 'icon' => 'dashicons-shield', 'label' => __( 'Firewall (WAF)', 'uaip-security-firewall' ), 'on' => (bool) Uaip_Sfw_Settings::get( 'waf_enabled' ), 'pro' => false ),
			array( 'key' => 'scan', 'icon' => 'dashicons-search', 'label' => __( 'Malware Scanner', 'uaip-security-firewall' ), 'on' => (bool) Uaip_Sfw_Settings::get( 'scan_yara_enabled' ), 'pro' => false ),
			array( 'key' => 'login', 'icon' => 'dashicons-lock', 'label' => __( 'Login Protection', 'uaip-security-firewall' ), 'on' => (bool) Uaip_Sfw_Settings::get( 'login_protection' ), 'pro' => false ),
			array( 'key' => 'twofa', 'icon' => 'dashicons-smartphone', 'label' => __( 'Two-Factor Auth', 'uaip-security-firewall' ), 'on' => $this->twofa_active(), 'pro' => false ),
			array( 'key' => 'hardening', 'icon' => 'dashicons-admin-tools', 'label' => __( 'Hardening', 'uaip-security-firewall' ), 'on' => (bool) Uaip_Sfw_Settings::get( 'harden_disable_editor' ), 'pro' => false ),
			array( 'key' => 'audit', 'icon' => 'dashicons-list-view', 'label' => __( 'Audit Log', 'uaip-security-firewall' ), 'on' => (bool) Uaip_Sfw_Settings::get( 'audit_log_enabled' ), 'pro' => false ),
			array( 'key' => 'clamav', 'icon' => 'dashicons-shield-alt', 'label' => __( 'ClamAV Antivirus', 'uaip-security-firewall' ), 'on' => $this->plugin->license->is_pro(), 'pro' => true ),
			array( 'key' => 'geo', 'icon' => 'dashicons-admin-site', 'label' => __( 'Geo Blocking', 'uaip-security-firewall' ), 'on' => $this->plugin->license->is_pro(), 'pro' => true ),
		);
	}

	/** Render one protection module tile. */
	private function module_card( $m ) {
		$is_pro = $this->plugin->license->is_pro();
		if ( $m['pro'] && ! $is_pro ) {
			$state = 'locked';
			$text  = __( 'Pro', 'uaip-security-firewall' );
		} elseif ( $m['on'] ) {
			$state = 'on';
			$text  = __( 'Active', 'uaip-security-firewall' );
		} else {
			$state = 'off';
			$text  = __( 'Off', 'uaip-security-firewall' );
		}
		printf(
			'<div class="uaip-sfw-card uaip-sfw-mod uaip-sfw-mod-%1$s"><span class="dashicons %2$s"></span><div class="uaip-sfw-mod-label">%3$s</div><span class="uaip-sfw-badge uaip-sfw-badge-%1$s">%4$s</span></div>',
			esc_attr( $state ),
			esc_attr( $m['icon'] ),
			esc_html( $m['label'] ),
			esc_html( $text )
		);
	}

	/**
	 * Compute a 0-100 security score from active protections.
	 *
	 * @param array $modules
	 * @param bool  $connected
	 * @return int
	 */
	private function security_score( $modules, $connected ) {
		// Weighted contributions for the core (non-Pro) protections.
		$weights = array(
			'waf'       => 25,
			'scan'      => 20,
			'login'     => 15,
			'twofa'     => 15,
			'hardening' => 10,
			'audit'     => 5,
		);
		$score = 0;
		foreach ( $modules as $m ) {
			if ( isset( $weights[ $m['key'] ] ) && $m['on'] ) {
				$score += $weights[ $m['key'] ];
			}
		}
		if ( $connected ) {
			$score += 10; // cloud alerts active
		}
		return min( 100, $score );
	}

	/** Map a score to a grade band. */
	private function score_grade( $score ) {
		if ( $score >= 80 ) {
			return array( 'key' => 'good', 'label' => __( 'Well protected', 'uaip-security-firewall' ), 'hint' => __( 'Your core defenses are active.', 'uaip-security-firewall' ) );
		}
		if ( $score >= 50 ) {
			return array( 'key' => 'warn', 'label' => __( 'Needs attention', 'uaip-security-firewall' ), 'hint' => __( 'A few protections are still off.', 'uaip-security-firewall' ) );
		}
		return array( 'key' => 'bad', 'label' => __( 'At risk', 'uaip-security-firewall' ), 'hint' => __( 'Turn on protection to secure your site.', 'uaip-security-firewall' ) );
	}

	/**
	 * Actionable recommendations based on current state.
	 *
	 * @return array<int,array>
	 */
	private function recommendations( $modules, $connected, $is_pro ) {
		$on  = wp_list_pluck( $modules, 'on', 'key' );
		$set = admin_url( 'admin.php?page=uaip-sfw-settings' );
		$rec = array();

		$rec[] = array(
			'title' => __( 'Enable the firewall', 'uaip-security-firewall' ),
			'desc'  => __( 'Block SQLi, RCE and XSS attacks at the endpoint.', 'uaip-security-firewall' ),
			'done'  => ! empty( $on['waf'] ),
			'url'   => $set,
			'cta'   => __( 'Enable', 'uaip-security-firewall' ),
		);
		$rec[] = array(
			'title' => __( 'Turn on two-factor authentication', 'uaip-security-firewall' ),
			'desc'  => __( 'Stop account takeover even if a password leaks.', 'uaip-security-firewall' ),
			'done'  => ! empty( $on['twofa'] ),
			'url'   => $set,
			'cta'   => __( 'Set up 2FA', 'uaip-security-firewall' ),
		);
		$rec[] = array(
			'title' => __( 'Run your first malware scan', 'uaip-security-firewall' ),
			'desc'  => __( 'Scan core, plugins and themes with YARA.', 'uaip-security-firewall' ),
			'done'  => ! empty( get_option( 'uaip_sfw_last_scan_summary', array() ) ),
			'url'   => admin_url( 'admin.php?page=uaip-sfw-scan' ),
			'cta'   => __( 'Scan now', 'uaip-security-firewall' ),
		);
		if ( $is_pro ) {
			$rec[] = array(
				'title' => __( 'Connect to UAIP Security Cloud', 'uaip-security-firewall' ),
				'desc'  => __( 'Link your account for the dashboard, cloud activity log and faster rule updates.', 'uaip-security-firewall' ),
				'done'  => $connected,
				'url'   => admin_url( 'admin.php?page=uaip-sfw-license' ),
				'cta'   => __( 'Connect', 'uaip-security-firewall' ),
			);
		}
		return $rec;
	}

	/** @return string severity key for styling */
	private function event_severity( $type ) {
		$high = array( 'attack_blocked', 'malware_found' );
		$mid  = array( 'login_failed', 'login_anomaly' );
		if ( in_array( $type, $high, true ) ) {
			return 'high';
		}
		if ( in_array( $type, $mid, true ) ) {
			return 'mid';
		}
		return 'low';
	}

	/** @return string human label for an event type */
	private function event_label( $type ) {
		$labels = array(
			'attack_blocked'     => __( 'Attack blocked', 'uaip-security-firewall' ),
			'malware_found'      => __( 'Malware detected', 'uaip-security-firewall' ),
			'login_failed'       => __( 'Failed login', 'uaip-security-firewall' ),
			'login_success'      => __( 'Login', 'uaip-security-firewall' ),
			'plugin_activated'   => __( 'Plugin activated', 'uaip-security-firewall' ),
			'plugin_deactivated' => __( 'Plugin deactivated', 'uaip-security-firewall' ),
			'theme_switched'     => __( 'Theme switched', 'uaip-security-firewall' ),
		);
		return isset( $labels[ $type ] ) ? $labels[ $type ] : ucwords( str_replace( '_', ' ', $type ) );
	}

	// -----------------------------------------------------------------
	// Plans & Upgrade — rendered straight from the feature registry
	// -----------------------------------------------------------------
	public function page_plans() {
		$features = Uaip_Sfw_Features::all();
		$is_pro   = $this->plugin->license->is_pro();

		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'Plans & Upgrade', 'uaip-security-firewall' ), __( 'Free runs standalone. Pro adds cloud power.', 'uaip-security-firewall' ), 'dashicons-star-filled' );

		// Pricing cards.
		echo '<div class="uaip-sfw-pricing">';

		// Free card.
		echo '<div class="uaip-sfw-price-card ' . ( $is_pro ? '' : 'uaip-sfw-price-current' ) . '">';
		echo '<div class="uaip-sfw-price-name">Free</div>';
		echo '<div class="uaip-sfw-price-amount">$0<span>/mo</span></div>';
		echo '<p class="uaip-sfw-price-tag">' . esc_html__( 'Standalone protection, no account needed.', 'uaip-security-firewall' ) . '</p>';
		echo '<ul class="uaip-sfw-price-list">';
		foreach ( array(
			__( 'Endpoint firewall (WAF)', 'uaip-security-firewall' ),
			__( 'YARA malware scanning', 'uaip-security-firewall' ),
			__( 'Brute-force login protection', 'uaip-security-firewall' ),
			__( 'Two-factor authentication', 'uaip-security-firewall' ),
			__( 'Site hardening & audit log', 'uaip-security-firewall' ),
		) as $li ) {
			echo '<li><span class="dashicons dashicons-yes"></span>' . esc_html( $li ) . '</li>';
		}
		echo '</ul>';
		echo '<div class="uaip-sfw-price-foot">' . ( $is_pro ? '' : '<span class="uaip-sfw-current-badge">' . esc_html__( 'Your plan', 'uaip-security-firewall' ) . '</span>' ) . '</div>';
		echo '</div>';

		// Pro card.
		echo '<div class="uaip-sfw-price-card uaip-sfw-price-pro ' . ( $is_pro ? 'uaip-sfw-price-current' : '' ) . '">';
		echo '<div class="uaip-sfw-price-ribbon">' . esc_html__( 'Recommended', 'uaip-security-firewall' ) . '</div>';
		echo '<div class="uaip-sfw-price-name">Pro</div>';
		echo '<div class="uaip-sfw-price-amount">$9<span>/mo</span></div>';
		echo '<p class="uaip-sfw-price-tag">' . esc_html__( 'Everything in Free, plus cloud scanning & remediation.', 'uaip-security-firewall' ) . '</p>';
		echo '<p class="uaip-sfw-price-yearly">' . esc_html__( 'or $97.20/yr — save 10% when billed annually', 'uaip-security-firewall' ) . '</p>';
		echo '<ul class="uaip-sfw-price-list">';
		foreach ( array(
			__( 'ClamAV antivirus engine', 'uaip-security-firewall' ),
			__( 'Cloud threat intelligence (hash reputation)', 'uaip-security-firewall' ),
			__( 'One-click malware cleanup', 'uaip-security-firewall' ),
			__( 'Real-time anomaly alerts (email)', 'uaip-security-firewall' ),
			__( 'Country / geo blocking', 'uaip-security-firewall' ),
			__( 'Multi-site dashboard & reports', 'uaip-security-firewall' ),
		) as $li ) {
			echo '<li><span class="dashicons dashicons-yes"></span>' . esc_html( $li ) . '</li>';
		}
		echo '</ul>';
		echo '<div class="uaip-sfw-price-foot">';
		if ( $is_pro ) {
			echo '<span class="uaip-sfw-current-badge uaip-sfw-current-pro">' . esc_html__( 'Your plan', 'uaip-security-firewall' ) . '</span>';
		} else {
			printf(
				'<a class="button button-hero button-primary" href="%s" target="_blank">%s</a><a class="uaip-sfw-link" href="%s">%s</a>',
				esc_url( $this->cloud_pricing_url() ),
				esc_html__( 'Get Pro', 'uaip-security-firewall' ),
				esc_url( admin_url( 'admin.php?page=uaip-sfw-license' ) ),
				esc_html__( 'I have a license key', 'uaip-security-firewall' )
			);
		}
		echo '</div>';
		echo '</div>';

		echo '</div>'; // pricing

		// Detailed comparison table.
		echo '<div class="uaip-sfw-card"><h2>' . esc_html__( 'Full feature comparison', 'uaip-security-firewall' ) . '</h2>';
		echo '<table class="uaip-sfw-compare"><thead><tr><th>' . esc_html__( 'Feature', 'uaip-security-firewall' ) . '</th><th>Free</th><th class="uaip-sfw-col-pro">Pro</th></tr></thead><tbody>';

		$last_group = '';
		foreach ( $features as $f ) {
			if ( $f['group'] !== $last_group ) {
				printf( '<tr class="uaip-sfw-group-row"><td colspan="3">%s</td></tr>', esc_html( $f['group'] ) );
				$last_group = $f['group'];
			}
			$free_yes = ( 'pro' !== $f['availability'] );
			$free_cell = $free_yes
				? '<span class="uaip-sfw-yes dashicons dashicons-yes"></span>' . ( $f['free_note'] ? '<small>' . esc_html( $f['free_note'] ) . '</small>' : '' )
				: '<span class="uaip-sfw-no">—</span>';
			$pro_note = ( 'free' === $f['availability'] ) ? __( 'Included', 'uaip-security-firewall' ) : ( $f['pro_note'] ? $f['pro_note'] : $f['free_note'] );
			$pro_cell = '<span class="uaip-sfw-yes dashicons dashicons-yes"></span>' . ( $pro_note ? '<small>' . esc_html( $pro_note ) . '</small>' : '' );
			printf(
				'<tr><td>%s</td><td>%s</td><td class="uaip-sfw-col-pro">%s</td></tr>',
				esc_html( $f['label'] ),
				$free_cell, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- cell markup escaped above.
				$pro_cell // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- cell markup escaped above.
			);
		}
		echo '</tbody></table></div>';
		echo '</div>';
	}

	// -----------------------------------------------------------------
	// License
	// -----------------------------------------------------------------
	/**
	 * Cloud connection status card — live indicator, account, last sync, actions.
	 */
	private function render_cloud_connection() {
		// Cloud connectivity (account dashboard, monitoring, threat intel) is a
		// Pro feature. Free runs fully standalone, so show an upsell instead.
		if ( ! $this->plugin->license->is_pro() ) {
			echo '<div class="uaip-sfw-card uaip-sfw-conn uaip-sfw-conn-off">';
			echo '<div class="uaip-sfw-conn-head"><span class="uaip-sfw-conn-dot off"></span><div>';
			echo '<strong>' . esc_html__( 'UAIP Security Cloud is a Pro feature', 'uaip-security-firewall' ) . '</strong>';
			echo '<p>' . esc_html__( 'The Free plugin runs fully standalone and never sends data to the cloud. Pro adds your account dashboard, centralized activity log, cloud monitoring, file-hash threat intelligence and faster rule updates. Activate a Pro license below to enable them.', 'uaip-security-firewall' ) . '</p>';
			echo '</div></div></div>';
			return;
		}

		$api       = Uaip_Sfw_Cloud_API::instance();
		$connected = $api->is_connected();
		$account   = (string) get_option( 'uaip_sfw_account_email', '' );
		$site_id   = (string) get_option( Uaip_Sfw_Cloud_API::OPT_SITE_ID, '' );
		$last      = (int) get_option( 'uaip_sfw_last_heartbeat', 0 );
		$live      = $last && ( time() - $last ) < 2 * HOUR_IN_SECONDS;
		$dev       = $this->plugin->license->is_dev_pro();

		// Inline notices from the connect/sync/disconnect actions. These are just
		// presence checks on redirect flags set by our own nonce-verified
		// admin-post handlers; they display a message and mutate nothing.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['uaip_sfw_synced'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Synced with UAIP Security Cloud.', 'uaip-security-firewall' ) . '</p></div>';
		}
		if ( isset( $_GET['uaip_sfw_disconnected'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Disconnected from UAIP Security Cloud.', 'uaip-security-firewall' ) . '</p></div>';
		}
		if ( isset( $_GET['uaip_sfw_connect_err'] ) ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Could not connect to UAIP Security Cloud. Please try again.', 'uaip-security-firewall' ) . '</p></div>';
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		echo '<div class="uaip-sfw-card uaip-sfw-conn uaip-sfw-conn-' . ( $connected ? 'on' : 'off' ) . '">';

		// --- Not connected ---
		if ( ! $connected ) {
			echo '<div class="uaip-sfw-conn-head"><span class="uaip-sfw-conn-dot off"></span><div>';
			echo '<strong>' . esc_html__( 'Not connected to UAIP Security Cloud', 'uaip-security-firewall' ) . '</strong>';
			echo '<p>' . esc_html__( 'Connect this site to enable your account dashboard, centralized activity log, licence management and Pro features. We verify the request comes from this exact site.', 'uaip-security-firewall' ) . '</p>';
			echo '</div></div>';
			echo '<div class="uaip-sfw-conn-actions">';
			$this->conn_button( 'uaip_sfw_connect_account', __( 'Connect to UAIP Security Cloud', 'uaip-security-firewall' ), 'primary' );
			echo '</div></div>';
			return;
		}

		// --- Connected --- (ids let the poller refresh state without a reload)
		$dot_class = $live ? 'on live' : 'on';
		$state_txt = $live ? __( 'Connected', 'uaip-security-firewall' ) : __( 'Connected (idle)', 'uaip-security-firewall' );
		echo '<div class="uaip-sfw-conn-head"><span id="uaip-sfw-conn-dot" class="uaip-sfw-conn-dot ' . esc_attr( $dot_class ) . '"></span><div>';
		echo '<strong><span id="uaip-sfw-conn-state">' . esc_html( $state_txt ) . '</span>';
		echo ' <span id="uaip-sfw-conn-live" class="uaip-sfw-conn-live"' . ( $live ? '' : ' style="display:none;"' ) . '>' . esc_html__( 'live', 'uaip-security-firewall' ) . '</span>';
		echo '</strong>';
		echo '<p>' . esc_html__( 'This site is linked to UAIP Security Cloud and sending heartbeats.', 'uaip-security-firewall' ) . '</p>';
		echo '</div></div>';

		// Details grid.
		echo '<div class="uaip-sfw-conn-grid">';
		echo '<div><div class="l">' . esc_html__( 'Account', 'uaip-security-firewall' ) . '</div><div class="v">' . ( '' !== $account ? esc_html( $account ) : '<span style="color:#996800;">' . esc_html__( 'Not linked', 'uaip-security-firewall' ) . '</span>' ) . '</div></div>';
		echo '<div><div class="l">' . esc_html__( 'Last sync', 'uaip-security-firewall' ) . '</div><div class="v" id="uaip-sfw-conn-lastsync">' . ( $last ? esc_html( human_time_diff( $last ) . ' ' . __( 'ago', 'uaip-security-firewall' ) ) : esc_html__( 'never', 'uaip-security-firewall' ) ) . '</div></div>';
		echo '<div><div class="l">' . esc_html__( 'Site ID', 'uaip-security-firewall' ) . '</div><div class="v"><code>' . esc_html( $site_id ) . '</code></div></div>';
		echo '</div>';

		if ( '' === $account ) {
			echo '<p class="uaip-sfw-empty">' . esc_html__( 'This site is not linked to an account yet — connect your account so only you can manage it.', 'uaip-security-firewall' ) . '</p>';
		}
		if ( $dev ) {
			echo '<p class="uaip-sfw-empty">' . esc_html__( 'Dev Pro simulation is active, so the cloud connection is optional locally.', 'uaip-security-firewall' ) . '</p>';
		}

		// Actions.
		echo '<div class="uaip-sfw-conn-actions">';
		$this->conn_button( 'uaip_sfw_connect_account', '' !== $account ? __( 'Change account', 'uaip-security-firewall' ) : __( 'Connect your account', 'uaip-security-firewall' ), '' !== $account ? 'secondary' : 'primary' );
		$this->conn_button( 'uaip_sfw_sync_cloud', __( 'Sync now', 'uaip-security-firewall' ), 'secondary' );
		$this->conn_button( 'uaip_sfw_disconnect_cloud', __( 'Disconnect', 'uaip-security-firewall' ), 'link-delete', __( 'Disconnect this site from UAIP Security Cloud?', 'uaip-security-firewall' ) );
		echo '</div></div>';
	}

	/** Render an admin-post action button (nonce-protected form). */
	private function conn_button( $action, $label, $style, $confirm = '' ) {
		$onsubmit = $confirm ? ' onsubmit="return confirm(\'' . esc_js( $confirm ) . '\');"' : '';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"' . $onsubmit . '>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $onsubmit is esc_js'd.
		wp_nonce_field( $action );
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '" />';
		submit_button( $label, $style, 'submit', false );
		echo '</form>';
	}

	/**
	 * JS that polls the connection-status REST route every 30s and updates the
	 * live dot, state label and "Last sync" in place. Returns early if the
	 * connected card isn't on the page (e.g. not connected yet).
	 *
	 * @return string
	 */
	private function connection_poll_js() {
		return <<<'JS'
(function(){
  var cfg = window.uaipSfwConn;
  if (!cfg) { return; }
  var dot   = document.getElementById('uaip-sfw-conn-dot');
  var state = document.getElementById('uaip-sfw-conn-state');
  var live  = document.getElementById('uaip-sfw-conn-live');
  var sync  = document.getElementById('uaip-sfw-conn-lastsync');
  if (!dot) { return; } // only present on the connected card
  function refresh(){
    fetch(cfg.url, { headers: { 'X-WP-Nonce': cfg.nonce }, credentials: 'same-origin' })
      .then(function(r){ return r.ok ? r.json() : null; })
      .then(function(d){
        if (!d || !d.connected) { return; }
        if (sync) { sync.textContent = d.last_sync_human; }
        if (d.live) {
          dot.classList.add('live');
          if (live)  { live.style.display = ''; }
          if (state) { state.textContent = cfg.labels.connected; }
        } else {
          dot.classList.remove('live');
          if (live)  { live.style.display = 'none'; }
          if (state) { state.textContent = cfg.labels.idle; }
        }
      })
      .catch(function(){ /* transient; try again next tick */ });
  }
  // Pause polling when the tab is hidden to avoid needless requests.
  var timer = null;
  function start(){ if (!timer) { timer = setInterval(refresh, 30000); } }
  function stop(){ if (timer) { clearInterval(timer); timer = null; } }
  document.addEventListener('visibilitychange', function(){
    if (document.hidden) { stop(); } else { refresh(); start(); }
  });
  refresh();
  start();
})();
JS;
	}

	public function page_license() {
		$state   = $this->plugin->license->state();
		$has_pkg = UAIP_SFW_HAS_PRO_PACKAGE;
		$is_pro  = $this->plugin->license->is_pro();
		$expired = $this->plugin->license->is_expired();
		$has_key = '' !== $this->plugin->license->key();
		$active  = $is_pro; // "active" means effectively Pro (not expired)

		echo '<div class="wrap uaip-sfw-wrap">';
		$this->header( __( 'License', 'uaip-security-firewall' ), __( 'Activate UAIP Security Pro on this site', 'uaip-security-firewall' ), 'dashicons-admin-network' );

		// Cloud connection status (most relevant — shown first).
		$this->render_cloud_connection();

		echo '<div class="uaip-sfw-license-grid">';

		// Form card.
		echo '<div class="uaip-sfw-card">';
		echo '<h2>' . esc_html__( 'License key', 'uaip-security-firewall' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'uaip_sfw_license' );
		echo '<input type="hidden" name="action" value="uaip_sfw_license" />';
		printf(
			'<input type="text" name="license_key" class="uaip-sfw-license-input" placeholder="%s" value="%s" />',
			esc_attr__( 'XXXX-XXXX-XXXX-XXXX', 'uaip-security-firewall' ),
			esc_attr( $this->plugin->license->key() )
		);
		echo '<p>';
		submit_button( __( 'Save & Validate', 'uaip-security-firewall' ), 'primary button-hero', 'submit', false );
		echo '</p>';
		echo '</form>';
		echo '</div>';

		// Status card — distinguishes Active / Expired / Inactive.
		$status_class = $is_pro ? 'active' : ( $expired ? 'expired' : 'inactive' );
		$status_icon  = $is_pro ? 'dashicons-yes-alt' : ( $expired ? 'dashicons-clock' : 'dashicons-dismiss' );
		$status_label = $is_pro ? __( 'Active', 'uaip-security-firewall' ) : ( $expired ? __( 'Expired', 'uaip-security-firewall' ) : __( 'Inactive', 'uaip-security-firewall' ) );

		echo '<div class="uaip-sfw-card uaip-sfw-license-status uaip-sfw-license-' . esc_attr( $status_class ) . '">';
		printf( '<span class="dashicons %s"></span>', esc_attr( $status_icon ) );
		echo '<div class="uaip-sfw-license-state">' . esc_html( $status_label ) . '</div>';
		if ( ! empty( $state['plan'] ) && ( $is_pro || $expired ) ) {
			/* translators: %s: plan name */
			echo '<p>' . esc_html( sprintf( __( 'Plan: %s', 'uaip-security-firewall' ), strtoupper( $state['plan'] ) ) ) . '</p>';
		}
		if ( ! empty( $state['expires'] ) ) {
			echo '<p>' . esc_html( sprintf(
				/* translators: %s: date */
				$expired ? __( 'Expired %s', 'uaip-security-firewall' ) : __( 'Renews / expires %s', 'uaip-security-firewall' ),
				$state['expires']
			) ) . '</p>';
		}
		if ( $is_pro && ! empty( $state['seats'] ) && isset( $state['seats']['used'], $state['seats']['limit'] ) ) {
			/* translators: 1: seats used, 2: seat limit */
			echo '<p>' . esc_html( sprintf( __( 'Seats: %1$d / %2$d', 'uaip-security-firewall' ), (int) $state['seats']['used'], (int) $state['seats']['limit'] ) ) . '</p>';
		}
		if ( ! empty( $state['is_local'] ) ) {
			echo '<p style="color:#996800;">' . esc_html__( 'Local/dev site — no seat used.', 'uaip-security-firewall' ) . '</p>';
		}
		if ( ! empty( $state['reason'] ) && 'seat_limit' === $state['reason'] ) {
			echo '<p style="color:#b32d2e;font-weight:600;">' . esc_html__( 'Seat limit reached — release a seat or upgrade.', 'uaip-security-firewall' ) . '</p>';
		}
		if ( ! empty( $state['reason'] ) && 'local_limit' === $state['reason'] ) {
			echo '<p style="color:#b32d2e;font-weight:600;">' . esc_html__( 'Local/staging activation limit reached for this license.', 'uaip-security-firewall' ) . '</p>';
		}

		// Buy / Renew / Manage call-to-action.
		echo '<p class="uaip-sfw-license-cta">';
		if ( $is_pro ) {
			printf( '<a class="button" href="%s" target="_blank">%s</a>', esc_url( $this->cloud_renew_url() ), esc_html__( 'Manage subscription', 'uaip-security-firewall' ) );
		} elseif ( $expired || $has_key ) {
			printf( '<a class="button button-primary" href="%s" target="_blank">%s</a>', esc_url( $this->cloud_renew_url() ), esc_html__( 'Renew subscription', 'uaip-security-firewall' ) );
		} else {
			printf( '<a class="button button-primary" href="%s" target="_blank">%s</a>', esc_url( $this->cloud_pricing_url() ), esc_html__( 'Buy Pro', 'uaip-security-firewall' ) );
		}
		echo '</p>';
		echo '</div>';

		echo '</div>'; // license-grid

		if ( ! $has_pkg ) {
			echo '<div class="uaip-sfw-card uaip-sfw-license-help"><h2>' . esc_html__( 'Don\'t have the Pro package yet?', 'uaip-security-firewall' ) . '</h2>';
			echo '<p>' . esc_html__( 'Pro is a separate download. After purchasing, download the UAIP Security Pro package from your account and install it (it replaces this Free build), then enter your license key above to activate.', 'uaip-security-firewall' ) . '</p>';
			printf(
				'<a class="button button-primary" href="%s" target="_blank">%s</a>',
				esc_url( UAIP_SFW_CLOUD_SITE . '/account' ),
				esc_html__( 'Go to my account', 'uaip-security-firewall' )
			);
			echo '</div>';
		}
		echo '</div>';
	}

	public function handle_license() {
		check_admin_referer( 'uaip_sfw_license' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '403' );
		}
		$key = isset( $_POST['license_key'] ) ? sanitize_text_field( wp_unslash( $_POST['license_key'] ) ) : '';
		$api = Uaip_Sfw_Cloud_API::instance();
		// Validation is a signed cloud call, so the site must be registered
		// first. For a Free site this one-time registration is the act of
		// upgrading to Pro — the only cloud contact the Free tier ever makes.
		if ( '' !== $key && ! $api->is_connected() ) {
			$api->register_site( get_option( 'admin_email' ) );
		}
		$this->plugin->license->activate( $key );
		$this->plugin->license->enforce_tier();
		wp_safe_redirect( admin_url( 'admin.php?page=uaip-sfw-license' ) );
		exit;
	}

	public function handle_connect() {
		check_admin_referer( 'uaip_sfw_connect' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '403' );
		}
		$email = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
		Uaip_Sfw_Cloud_API::instance()->register_site( $email );
		// Re-validate any stored key now that we're connected (see handle_connect_account).
		$license = Uaip_Sfw_Plugin::instance()->license;
		if ( '' !== $license->key() ) {
			$license->revalidate();
			$license->enforce_tier();
		}
		wp_safe_redirect( admin_url( 'admin.php?page=uaip-sfw' ) );
		exit;
	}

	/** Trigger an immediate heartbeat (manual "Sync now"). */
	public function handle_sync_cloud() {
		check_admin_referer( 'uaip_sfw_sync_cloud' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '403' );
		}
		$hb = $this->plugin->module( 'heartbeat' );
		if ( $hb && method_exists( $hb, 'run' ) ) {
			$hb->run();
		}
		wp_safe_redirect( add_query_arg( 'uaip_sfw_synced', '1', admin_url( 'admin.php?page=uaip-sfw-license' ) ) );
		exit;
	}

	/** Disconnect this site from UAIP Security Cloud (clears local credentials). */
	public function handle_disconnect_cloud() {
		check_admin_referer( 'uaip_sfw_disconnect_cloud' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '403' );
		}
		// Release the licence seat in the cloud, then clear local connection.
		$this->plugin->license->deactivate();
		delete_option( Uaip_Sfw_Cloud_API::OPT_SITE_ID );
		delete_option( Uaip_Sfw_Cloud_API::OPT_SECRET );
		delete_option( 'uaip_sfw_account_email' );
		delete_option( 'uaip_sfw_last_heartbeat' );
		Uaip_Sfw_Settings::update( array( 'cloud_connected' => false ) );
		wp_safe_redirect( add_query_arg( 'uaip_sfw_disconnected', '1', admin_url( 'admin.php?page=uaip-sfw-license' ) ) );
		exit;
	}

	/**
	 * Register the site if needed, then redirect the admin to the cloud's
	 * signed account-connect handshake.
	 */
	public function handle_connect_account() {
		check_admin_referer( 'uaip_sfw_connect_account' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '403' );
		}
		$api    = Uaip_Sfw_Cloud_API::instance();
		$return = admin_url( 'admin.php?page=uaip-sfw-license' );

		if ( ! $api->is_connected() ) {
			$res = $api->register_site( get_option( 'admin_email' ) );
			if ( is_wp_error( $res ) ) {
				wp_safe_redirect( add_query_arg( 'uaip_sfw_connect_err', '1', $return ) );
				exit;
			}
		}
		// A key entered before connecting cached an "inactive" state (its first
		// validation failed with not-connected). Now that we're connected,
		// re-validate so the tier reflects reality immediately.
		$license = Uaip_Sfw_Plugin::instance()->license;
		if ( '' !== $license->key() ) {
			$license->revalidate();
			$license->enforce_tier();
		}
		$url = $api->connect_url( $return );
		if ( '' === $url ) {
			wp_safe_redirect( add_query_arg( 'uaip_sfw_connect_err', '1', $return ) );
			exit;
		}
		// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- intentional off-site redirect to the UAIP Security Cloud connect page; wp_safe_redirect would strip the external host.
		wp_redirect( $url );
		exit;
	}
}
