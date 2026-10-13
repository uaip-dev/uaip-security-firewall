<?php
/**
 * Custom tables: the scanner's file baseline and its findings.
 *
 * Tables are created on activation and upgraded on load when the schema
 * version changes. They are dropped on uninstall only when the site owner
 * opted in to data deletion.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_DB {

	const VERSION_OPTION = 'uaip_sfw_db_version';
	const VERSION        = '1';

	/** @return string File baseline table. */
	public static function files() {
		global $wpdb;
		return $wpdb->prefix . 'uaip_sfw_files';
	}

	/** @return string Findings table. */
	public static function findings() {
		global $wpdb;
		return $wpdb->prefix . 'uaip_sfw_findings';
	}

	/**
	 * Create or upgrade the tables when needed (cheap: one autoloaded option).
	 */
	public static function maybe_upgrade() {
		if ( self::VERSION !== get_option( self::VERSION_OPTION ) ) {
			self::install();
		}
	}

	/**
	 * Create/upgrade the tables with dbDelta().
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$files   = self::files();
		$finds   = self::findings();

		dbDelta(
			"CREATE TABLE {$files} (
			path_hash char(40) NOT NULL,
			path text NOT NULL,
			area varchar(20) NOT NULL DEFAULT '',
			size bigint(20) unsigned NOT NULL DEFAULT 0,
			mtime bigint(20) unsigned NOT NULL DEFAULT 0,
			sha256 char(64) NOT NULL DEFAULT '',
			rules_version varchar(32) NOT NULL DEFAULT '',
			scanned_at bigint(20) unsigned NOT NULL DEFAULT 0,
			seen_run bigint(20) unsigned NOT NULL DEFAULT 0,
			scanned_run bigint(20) unsigned NOT NULL DEFAULT 0,
			dirty tinyint(1) unsigned NOT NULL DEFAULT 1,
			is_new tinyint(1) unsigned NOT NULL DEFAULT 1,
			PRIMARY KEY  (path_hash),
			KEY seen_dirty (seen_run,dirty)
			) {$charset};"
		);
		dbDelta(
			"CREATE TABLE {$finds} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			fkey char(40) NOT NULL,
			path_hash char(40) NOT NULL DEFAULT '',
			path text NOT NULL,
			rule varchar(64) NOT NULL DEFAULT '',
			kind varchar(20) NOT NULL DEFAULT '',
			severity varchar(10) NOT NULL DEFAULT 'medium',
			description text NOT NULL,
			file_hash char(64) NOT NULL DEFAULT '',
			fix varchar(20) NOT NULL DEFAULT '',
			status varchar(10) NOT NULL DEFAULT 'open',
			first_seen bigint(20) unsigned NOT NULL DEFAULT 0,
			last_seen bigint(20) unsigned NOT NULL DEFAULT 0,
			seen_run bigint(20) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			UNIQUE KEY fkey (fkey),
			KEY status (status),
			KEY path_hash (path_hash)
			) {$charset};"
		);
		update_option( self::VERSION_OPTION, self::VERSION );
	}

	/**
	 * Drop the tables (uninstall with data deletion only).
	 */
	public static function drop() {
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- one-time uninstall cleanup of the plugin's own tables.
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', self::files() ) );
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', self::findings() ) );
		// phpcs:enable
		delete_option( self::VERSION_OPTION );
	}
}
