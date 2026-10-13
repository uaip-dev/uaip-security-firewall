<?php
/**
 * Site hardening (Free): actionable one-click toggles.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Hardening {

	const MARKER = 'UAIP Security PHP Block';

	public function register_hooks() {
		if ( Uaip_Sfw_Settings::get( 'harden_disable_editor' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- DISALLOW_FILE_EDIT is a documented WordPress core constant; defining it is the intended way to disable the file editor.
			define( 'DISALLOW_FILE_EDIT', true );
		}
		if ( Uaip_Sfw_Settings::get( 'harden_hide_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( Uaip_Sfw_Settings::get( 'harden_disable_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
		}
	}

	/**
	 * Available hardening actions (rendered on the Hardening screen).
	 *
	 * @return array<string,array{label:string,desc:string}>
	 */
	public function actions() {
		return array(
			'harden_disable_editor'    => array(
				'label' => __( 'Disable the plugin/theme file editor', 'uaip-security-firewall' ),
				'desc'  => __( 'Stops attackers (and accidents) editing PHP from wp-admin.', 'uaip-security-firewall' ),
			),
			'harden_hide_version'      => array(
				'label' => __( 'Hide the WordPress version', 'uaip-security-firewall' ),
				'desc'  => __( 'Removes the version meta tag and generator output.', 'uaip-security-firewall' ),
			),
			'harden_block_php_uploads' => array(
				'label' => __( 'Block PHP execution in uploads', 'uaip-security-firewall' ),
				'desc'  => __( 'Writes an .htaccess rule so uploaded files cannot run as PHP.', 'uaip-security-firewall' ),
			),
			'harden_disable_xmlrpc'    => array(
				'label' => __( 'Disable XML-RPC', 'uaip-security-firewall' ),
				'desc'  => __( 'Blocks a common brute-force and DDoS amplification vector.', 'uaip-security-firewall' ),
			),
		);
	}

	/**
	 * Apply a hardening setting change (called when settings are saved).
	 *
	 * @param string $key
	 * @param bool   $enabled
	 * @return true|WP_Error
	 */
	public function apply( $key, $enabled ) {
		if ( 'harden_block_php_uploads' === $key ) {
			$dir = trailingslashit( wp_upload_dir()['basedir'] );
			return $enabled ? $this->write_php_block( $dir ) : $this->remove_php_block( $dir );
		}
		return true; // others apply at runtime via register_hooks()
	}

	/**
	 * Write an .htaccess block that denies direct PHP execution in a directory.
	 *
	 * @param string $dir Absolute path with trailing slash.
	 * @return true|WP_Error
	 */
	public function write_php_block( $dir ) {
		$file  = $dir . '.htaccess';
		$rules = "# BEGIN " . self::MARKER . "\n"
			. "<Files *.php>\n"
			. "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"
			. "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n"
			. "</Files>\n"
			. "# END " . self::MARKER . "\n";

		$existing = file_exists( $file ) ? (string) @file_get_contents( $file ) : '';
		if ( false !== strpos( $existing, '# BEGIN ' . self::MARKER ) ) {
			return true; // already present
		}
		if ( ! wp_is_writable( $dir ) ) {
			return new WP_Error( 'not_writable', __( 'The uploads directory is not writable.', 'uaip-security-firewall' ) );
		}
		$ok = @file_put_contents( $file, $rules . $existing );
		return false === $ok ? new WP_Error( 'write_failed', __( 'Could not write .htaccess.', 'uaip-security-firewall' ) ) : true;
	}

	/**
	 * Remove our managed PHP-block from a directory's .htaccess.
	 *
	 * @param string $dir
	 * @return true
	 */
	public function remove_php_block( $dir ) {
		$file = $dir . '.htaccess';
		if ( ! file_exists( $file ) ) {
			return true;
		}
		$content = (string) @file_get_contents( $file );
		$clean   = preg_replace(
			'/# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\s*/s',
			'',
			$content
		);
		if ( '' === trim( $clean ) ) {
			wp_delete_file( $file );
		} else {
			@file_put_contents( $file, $clean );
		}
		return true;
	}
}
