<?php
/**
 * Feature registry — the single source of truth for the Free vs Pro spec.
 *
 * Every module asks this registry whether a capability is available for the
 * current tier, and the admin "Plans" screen renders straight from it. Keep
 * product decisions HERE so code and marketing never drift apart.
 *
 * availability:
 *   'free' => in both tiers
 *   'pro'  => Pro only
 *   'free_basic' => present in Free but limited; Pro enhances it (see pro_note)
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Features {

	/**
	 * @return array<string,array{group:string,label:string,availability:string,free_note:string,pro_note:string}>
	 */
	public static function all() {
		return array(

			// ---------------- Firewall ----------------
			'waf' => array(
				'group'        => __( 'Firewall', 'uaip-security-firewall' ),
				'label'        => __( 'Endpoint Web Application Firewall (SQLi/RCE/XSS/LFI)', 'uaip-security-firewall' ),
				'availability' => 'free_basic',
				'free_note'    => __( 'Local blocking, bundled ruleset', 'uaip-security-firewall' ),
				'pro_note'     => __( 'Cloud rule updates every 5 min + virtual patching', 'uaip-security-firewall' ),
			),
			'waf_extended' => array(
				'group'        => __( 'Firewall', 'uaip-security-firewall' ),
				'label'        => __( 'Extended protection (auto_prepend, runs before WordPress)', 'uaip-security-firewall' ),
				'availability' => 'free',
				'free_note'    => __( 'One-click enable', 'uaip-security-firewall' ),
				'pro_note'     => '',
			),
			'rate_limit' => array(
				'group'        => __( 'Firewall', 'uaip-security-firewall' ),
				'label'        => __( 'Rate limiting & bot throttling', 'uaip-security-firewall' ),
				'availability' => 'free',
				'free_note'    => '',
				'pro_note'     => '',
			),
			'geo_blocking' => array(
				'group'        => __( 'Firewall', 'uaip-security-firewall' ),
				'label'        => __( 'Country / geo blocking', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Block or allow by country', 'uaip-security-firewall' ),
			),

			// ---------------- Malware scanning ----------------
			'scan_integrity' => array(
				'group'        => __( 'Malware Scanning', 'uaip-security-firewall' ),
				'label'        => __( 'Core/plugin/theme integrity vs WordPress.org', 'uaip-security-firewall' ),
				'availability' => 'free',
				'free_note'    => '',
				'pro_note'     => '',
			),
			'scan_yara' => array(
				'group'        => __( 'Malware Scanning', 'uaip-security-firewall' ),
				'label'        => __( 'YARA malware/webshell scanning', 'uaip-security-firewall' ),
				'availability' => 'free_basic',
				'free_note'    => __( 'Binary or PHP-lite fallback, bundled ruleset', 'uaip-security-firewall' ),
				'pro_note'     => __( 'Premium & private YARA rules', 'uaip-security-firewall' ),
			),
			'scan_clamav' => array(
				'group'        => __( 'Malware Scanning', 'uaip-security-firewall' ),
				'label'        => __( 'ClamAV antivirus engine', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Local clamd or cloud ClamAV worker', 'uaip-security-firewall' ),
			),
			'scan_cloud_deep' => array(
				'group'        => __( 'Malware Scanning', 'uaip-security-firewall' ),
				'label'        => __( 'Cloud threat intelligence (file-hash reputation)', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Flag known malware by hash (only hashes leave your site)', 'uaip-security-firewall' ),
			),
			'malware_cleanup' => array(
				'group'        => __( 'Malware Scanning', 'uaip-security-firewall' ),
				'label'        => __( 'Malware removal', 'uaip-security-firewall' ),
				'availability' => 'free_basic',
				'free_note'    => __( 'Manual repair / delete flagged files', 'uaip-security-firewall' ),
				'pro_note'     => __( 'One-click automatic & unlimited cleanup', 'uaip-security-firewall' ),
			),

			// ---------------- Login security ----------------
			'login_bruteforce' => array(
				'group'        => __( 'Login Security', 'uaip-security-firewall' ),
				'label'        => __( 'Brute-force lockouts + CAPTCHA', 'uaip-security-firewall' ),
				'availability' => 'free',
				'free_note'    => '',
				'pro_note'     => __( 'Bot fingerprinting', 'uaip-security-firewall' ),
			),
			'login_2fa' => array(
				'group'        => __( 'Login Security', 'uaip-security-firewall' ),
				'label'        => __( 'Two-factor authentication (TOTP)', 'uaip-security-firewall' ),
				'availability' => 'free',
				'free_note'    => '',
				'pro_note'     => __( 'Enforced per-role policies', 'uaip-security-firewall' ),
			),
			'login_breached_pw' => array(
				'group'        => __( 'Login Security', 'uaip-security-firewall' ),
				'label'        => __( 'Breached-password blocking', 'uaip-security-firewall' ),
				'availability' => 'free_basic',
				'free_note'    => __( 'Local k-anonymity list', 'uaip-security-firewall' ),
				'pro_note'     => __( 'Live breach database', 'uaip-security-firewall' ),
			),

			// ---------------- Hardening & audit ----------------
			'hardening' => array(
				'group'        => __( 'Hardening', 'uaip-security-firewall' ),
				'label'        => __( 'Site hardening (.htaccess, disable editor, block PHP in uploads)', 'uaip-security-firewall' ),
				'availability' => 'free',
				'free_note'    => '',
				'pro_note'     => '',
			),
			'audit_log' => array(
				'group'        => __( 'Auditing', 'uaip-security-firewall' ),
				'label'        => __( 'Security activity audit log', 'uaip-security-firewall' ),
				'availability' => 'free_basic',
				'free_note'    => __( 'Local, 30-day', 'uaip-security-firewall' ),
				'pro_note'     => __( 'Cloud activity log, unlimited retention, multi-site', 'uaip-security-firewall' ),
			),

			// ---------------- Cloud & monitoring ----------------
			'anomaly_alerts' => array(
				'group'        => __( 'Cloud Monitoring', 'uaip-security-firewall' ),
				'label'        => __( 'Traffic anomaly auto-notifications', 'uaip-security-firewall' ),
				'availability' => 'free_basic',
				'free_note'    => __( 'Basic local heuristics, email alerts', 'uaip-security-firewall' ),
				'pro_note'     => __( 'Cloud anomaly detection + email alerts', 'uaip-security-firewall' ),
			),
			'cloud_sample_upload' => array(
				'group'        => __( 'Cloud Monitoring', 'uaip-security-firewall' ),
				'label'        => __( 'Suspicious code sent to UAIP Security Cloud', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Hashes + full sample analysis & sandboxing', 'uaip-security-firewall' ),
			),
			'vuln_intel' => array(
				'group'        => __( 'Cloud Monitoring', 'uaip-security-firewall' ),
				'label'        => __( 'Known-vulnerability alerts (CVE matching)', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Real-time CVE alerts + auto virtual patch', 'uaip-security-firewall' ),
			),
			'cloud_account' => array(
				'group'        => __( 'Cloud Monitoring', 'uaip-security-firewall' ),
				'label'        => __( 'Connect to your UAIP Security Cloud account', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Account dashboard, activity log & licence in one place', 'uaip-security-firewall' ),
			),

			// ---------------- Branding ----------------
			'login_brand' => array(
				'group'        => __( 'Branding', 'uaip-security-firewall' ),
				'label'        => __( 'Custom login page (logo, colours, custom CSS)', 'uaip-security-firewall' ),
				'availability' => 'free',
				'free_note'    => __( 'White-label your wp-login.php', 'uaip-security-firewall' ),
				'pro_note'     => '',
			),
			'white_label' => array(
				'group'        => __( 'Branding', 'uaip-security-firewall' ),
				'label'        => __( 'White-label cloud reports', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Agency plan', 'uaip-security-firewall' ),
			),

			'multisite_dashboard' => array(
				'group'        => __( 'Management', 'uaip-security-firewall' ),
				'label'        => __( 'Multi-site dashboard & reports', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Manage all your sites from UAIP Security Cloud', 'uaip-security-firewall' ),
			),
			'billing_portal' => array(
				'group'        => __( 'Management', 'uaip-security-firewall' ),
				'label'        => __( 'Self-service billing & invoices', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => __( 'Stripe customer portal', 'uaip-security-firewall' ),
			),
			'uptime_perf' => array(
				'group'        => __( 'Management', 'uaip-security-firewall' ),
				'label'        => __( 'Uptime & performance monitoring', 'uaip-security-firewall' ),
				'availability' => 'pro',
				'free_note'    => '',
				'pro_note'     => '',
			),
		);
	}

	/**
	 * Is a capability available for the current tier?
	 *
	 * @param string $key
	 * @return bool
	 */
	public static function available( $key ) {
		$all = self::all();
		if ( ! isset( $all[ $key ] ) ) {
			return false;
		}
		$availability = $all[ $key ]['availability'];
		if ( 'pro' === $availability ) {
			return Uaip_Sfw_Plugin::instance()->license->is_pro();
		}
		// 'free' and 'free_basic' are available in both tiers.
		return true;
	}

	/**
	 * Does the current tier get the *enhanced* version of a free_basic feature?
	 *
	 * @param string $key
	 * @return bool
	 */
	public static function enhanced( $key ) {
		return Uaip_Sfw_Plugin::instance()->license->is_pro();
	}
}
