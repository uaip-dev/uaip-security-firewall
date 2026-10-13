<?php
/**
 * Official checksums for WordPress core and wordpress.org plugins, and repair
 * of modified files from the official sources.
 *
 * Repairs are verified: the downloaded file must match the official checksum
 * before it replaces anything, so a repair can never install an unexpected file.
 *
 * Remote services (all wordpress.org, see readme "External services"):
 *   - api.wordpress.org/core/checksums  (via get_core_checksums())
 *   - downloads.wordpress.org/plugin-checksums/{slug}/{version}.json
 *   - core.svn.wordpress.org / plugins.svn.wordpress.org (only when repairing)
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Integrity {

	const CORE_OPTION = 'uaip_sfw_core_sums_v2';

	/**
	 * Core checksums for the running version and locale: rel path => md5.
	 * Cached (not autoloaded) until the version or locale changes.
	 *
	 * @return array<string,string>|null Null when unavailable (offline).
	 */
	public static function core() {
		global $wp_version, $wp_local_package;
		$locale = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$key    = $wp_version . '|' . $locale;
		$cached = get_option( self::CORE_OPTION );
		if ( is_array( $cached ) && isset( $cached['key'], $cached['sums'] ) && $cached['key'] === $key ) {
			return $cached['sums'];
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$sums = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $sums ) && 'en_US' !== $locale ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $sums ) ) {
			return null;
		}
		// The core package also lists its bundled wp-content (Akismet, default
		// themes). Those update on their own, so they are checked as plugins or
		// not at all, never against the core release.
		foreach ( array_keys( $sums ) as $file ) {
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				unset( $sums[ $file ] );
			}
		}
		update_option(
			self::CORE_OPTION,
			array(
				'key'  => $key,
				'sums' => $sums,
			),
			false
		);
		return $sums;
	}

	/**
	 * Checksums of a wordpress.org plugin version: path in the plugin => list of
	 * md5 hashes (wordpress.org may list several). Cached for a week; plugins not
	 * hosted on wordpress.org are remembered for a day.
	 *
	 * @param string $slug    Plugin folder name.
	 * @param string $version Installed version.
	 * @return array<string,string[]>|null Null when not a wordpress.org plugin/version.
	 */
	public static function plugin( $slug, $version ) {
		if ( ! preg_match( '/^[a-z0-9][a-z0-9_-]*$/i', $slug ) || ! preg_match( '/^[0-9A-Za-z._-]+$/', (string) $version ) ) {
			return null;
		}
		$key    = 'uaip_sfw_psum_' . md5( $slug . '|' . $version );
		$cached = get_transient( $key );
		if ( 'none' === $cached ) {
			return null;
		}
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$url = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$res = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $res ) ) {
			return null; // Network trouble: try again next scan, don't cache.
		}
		$body = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( 200 !== (int) wp_remote_retrieve_response_code( $res ) || empty( $body['files'] ) || ! is_array( $body['files'] ) ) {
			set_transient( $key, 'none', DAY_IN_SECONDS );
			return null;
		}
		$sums = array();
		foreach ( $body['files'] as $file => $info ) {
			if ( isset( $info['md5'] ) ) {
				$sums[ (string) $file ] = array_map( 'strtolower', (array) $info['md5'] );
			}
		}
		set_transient( $key, $sums, WEEK_IN_SECONDS );
		return $sums;
	}

	/**
	 * Installed plugins: folder slug => version (single-file plugins skipped).
	 *
	 * @return array<string,string>
	 */
	public static function plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' !== $slug && ! empty( $data['Version'] ) ) {
				$out[ $slug ] = (string) $data['Version'];
			}
		}
		return $out;
	}

	/**
	 * Replace a modified core or wordpress.org plugin file with the official copy.
	 *
	 * @param string $rel Path relative to ABSPATH.
	 * @return true|WP_Error
	 */
	public static function repair( $rel ) {
		global $wp_version;
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		if ( '' === $rel || false !== strpos( $rel, '..' ) ) {
			return new WP_Error( 'uaip_sfw_bad_path', __( 'Invalid file path.', 'uaip-security-firewall' ) );
		}

		$core = self::core();
		if ( is_array( $core ) && isset( $core[ $rel ] ) ) {
			$url      = 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $rel ) ) );
			$expected = array( strtolower( $core[ $rel ] ) );
			return self::replace( ABSPATH . $rel, array( $url ), $expected );
		}

		$plugin_dir = wp_normalize_path( trailingslashit( WP_PLUGIN_DIR ) );
		$abs        = wp_normalize_path( ABSPATH . $rel );
		if ( 0 === strpos( $abs, $plugin_dir ) ) {
			$inner = substr( $abs, strlen( $plugin_dir ) );
			$slash = strpos( $inner, '/' );
			if ( false !== $slash ) {
				$slug     = substr( $inner, 0, $slash );
				$file     = substr( $inner, $slash + 1 );
				$versions = self::plugins();
				$sums     = isset( $versions[ $slug ] ) ? self::plugin( $slug, $versions[ $slug ] ) : null;
				if ( is_array( $sums ) && isset( $sums[ $file ] ) ) {
					$path = implode( '/', array_map( 'rawurlencode', explode( '/', $file ) ) );
					$base = 'https://plugins.svn.wordpress.org/' . rawurlencode( $slug ) . '/';
					return self::replace(
						$abs,
						array( $base . 'tags/' . rawurlencode( $versions[ $slug ] ) . '/' . $path, $base . 'trunk/' . $path ),
						$sums[ $file ]
					);
				}
			}
		}
		return new WP_Error( 'uaip_sfw_no_source', __( 'There is no official copy of this file to restore it from.', 'uaip-security-firewall' ) );
	}

	/**
	 * Download, verify against the expected md5 hashes, then write.
	 *
	 * @param string   $abs      Target file.
	 * @param string[] $urls     Candidate sources, tried in order.
	 * @param string[] $expected Accepted md5 hashes.
	 * @return true|WP_Error
	 */
	private static function replace( $abs, array $urls, array $expected ) {
		$body = null;
		foreach ( $urls as $url ) {
			$res = wp_remote_get( $url, array( 'timeout' => 20 ) );
			if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
				continue;
			}
			$candidate = (string) wp_remote_retrieve_body( $res );
			if ( in_array( md5( $candidate ), $expected, true ) ) {
				$body = $candidate;
				break;
			}
		}
		if ( null === $body ) {
			return new WP_Error( 'uaip_sfw_no_match', __( 'Could not download an official copy that matches the published checksum, so nothing was changed.', 'uaip-security-firewall' ) );
		}

		global $wp_filesystem;
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( ! WP_Filesystem() || ! $wp_filesystem ) {
			return new WP_Error( 'uaip_sfw_fs', __( 'WordPress cannot write files on this server without FTP credentials, so the file could not be repaired automatically.', 'uaip-security-firewall' ) );
		}
		if ( ! $wp_filesystem->put_contents( $abs, $body, FS_CHMOD_FILE ) ) {
			return new WP_Error( 'uaip_sfw_write', __( 'The file could not be written. Check file permissions.', 'uaip-security-firewall' ) );
		}
		clearstatcache( true, $abs );
		return md5_file( $abs ) === md5( $body ) ? true : new WP_Error( 'uaip_sfw_verify', __( 'The file was written but does not match afterwards.', 'uaip-security-firewall' ) );
	}
}
