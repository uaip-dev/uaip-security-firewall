<?php
/**
 * Uninstall cleanup. Runs ONLY when the plugin is deleted (never on deactivate).
 *
 * Destructive removal is OPT-IN: it happens only if the admin enabled
 * "Delete all data when the plugin is removed" under UAIP Security → Settings.
 * Otherwise everything is left in place, so a delete → reinstall keeps the
 * configuration. Deactivation never deletes data (see the deactivation hook).
 *
 * Cleanup is prefix-based so nothing is missed: every option, user-meta key and
 * transient starting with `uaip_sfw_`, plus the scheduled cron events.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/** Did the admin opt in to data deletion on the current blog? */
function uaip_sfw_should_delete() {
	$settings = get_option( 'uaip_sfw_settings' );
	return is_array( $settings ) && ! empty( $settings['delete_data_on_uninstall'] );
}

/** Remove every UAIP Security option, user-meta, transient and cron on this blog. */
function uaip_sfw_purge_blog() {
	global $wpdb;

	// Direct deletes are correct here: this is one-time uninstall cleanup of the
	// plugin's own rows via prepared LIKE queries; caching is not applicable.
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$like = $wpdb->esc_like( 'uaip_sfw_' ) . '%';
	// Options: settings, license key/state, site id/secret, caches, notices…
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like ) );
	// Per-user meta: 2FA secrets, enrolment flags, recovery codes…
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $like ) );
	// Transients + their timeouts (stored in the options table).
	$t   = $wpdb->esc_like( '_transient_uaip_sfw_' ) . '%';
	$tt  = $wpdb->esc_like( '_transient_timeout_uaip_sfw_' ) . '%';
	$st  = $wpdb->esc_like( '_site_transient_uaip_sfw_' ) . '%';
	$stt = $wpdb->esc_like( '_site_transient_timeout_uaip_sfw_' ) . '%';
	$wpdb->query( $wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
		$t, $tt, $st, $stt
	) );
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	// Scheduled events.
	wp_clear_scheduled_hook( 'uaip_sfw_heartbeat' );
	wp_clear_scheduled_hook( 'uaip_sfw_scan' );
}

if ( is_multisite() ) {
	$uaip_sfw_any = false;
	foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $blog_id ) {
		switch_to_blog( $blog_id );
		if ( uaip_sfw_should_delete() ) {
			uaip_sfw_purge_blog();
			$uaip_sfw_any = true;
		}
		restore_current_blog();
	}
	// Network-level site transients (rule/geo intel caches) live in sitemeta.
	if ( $uaip_sfw_any ) {
		global $wpdb;
		$uaip_sfw_st  = $wpdb->esc_like( '_site_transient_uaip_sfw_' ) . '%';
		$uaip_sfw_stt = $wpdb->esc_like( '_site_transient_timeout_uaip_sfw_' ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time uninstall cleanup; prepared LIKE delete, no caching applicable.
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
			$uaip_sfw_st, $uaip_sfw_stt
		) );
	}
} elseif ( uaip_sfw_should_delete() ) {
	uaip_sfw_purge_blog();
}
