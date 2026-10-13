<?php
/**
 * Settings storage wrapper. One option blob, typed accessors.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Settings {

	const OPTION = 'uaip_sfw_settings';

	/** @return array Default settings. */
	public static function defaults() {
		return array(
			'waf_enabled'            => true,
			'waf_mode'               => 'plugin',   // 'plugin' | 'extended'
			'waf_action'             => 'block',    // 'block' | 'learn'
			'waf_threshold'          => 5,
			'waf_allowlist_ips'      => '',
			'waf_fail_open'          => true,
			'waf_extended'           => false,      // auto_prepend extended protection
			'rate_limit_rpm'         => 240,        // max requests/min per IP (0 = off)
			'login_breached_pw'      => true,
			'harden_hide_version'    => false,
			'harden_block_php_uploads' => false,
			'harden_disable_xmlrpc'  => false,
			'geo_enabled'            => false,          // Pro
			'geo_mode'               => 'block',        // 'block' (blocklist) | 'allow' (allowlist)
			'geo_countries'          => '',             // comma/space ISO-3166 codes
			'geo_block_unknown'      => false,
			'geo_bypass_ips'         => '',
			'rate_limit_enabled'     => true,
			'scan_schedule'          => 'daily',
			'scan_yara_enabled'      => true,
			'clamav_socket'          => '', // empty = auto-detect; or unix:///path or tcp://host:port (Pro)
			'login_protection'       => true,
			'login_captcha_after'    => 3,
			'login_brand_enabled'    => false,
			'login_logo_url'         => '',
			'login_bg_from'          => '#1a0b06',
			'login_bg_to'            => '#ea580c',
			'login_button_color'     => '#ea580c',
			'audit_log_enabled'      => true,
			'cloud_connected'        => false,
			'cloud_sample_upload'    => 'hashes_only', // 'off' | 'hashes_only' | 'full' (full = opt-in)
			'anomaly_alerts'         => true,
			'alert_email'            => '',
			'delete_data_on_uninstall' => false, // wipe all settings/data when the plugin is deleted
		);
	}

	public static function install_defaults() {
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, self::defaults() );
		}
	}

	/** @return array */
	public static function all() {
		return wp_parse_args( get_option( self::OPTION, array() ), self::defaults() );
	}

	/**
	 * @param string $key
	 * @param mixed  $fallback
	 * @return mixed
	 */
	public static function get( $key, $fallback = null ) {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $fallback;
	}

	/**
	 * @param array $values Partial settings to merge.
	 */
	public static function update( array $values ) {
		update_option( self::OPTION, array_merge( self::all(), $values ) );
	}
}
