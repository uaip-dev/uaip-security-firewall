<?php
/**
 * Site hardening: file editor, version, uploads, XML-RPC, security headers
 * and hiding usernames from visitors.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Hardening {

	const MARKER = 'UAIP Security PHP Block';

	/** Script extensions refused in uploads (also matches "shell.php.jpg"). */
	const SCRIPT_PATTERN = '(?i)\.(php[0-9]?|phtml|phar|pht|phps)(\.|$)';

	/** Last upload execution test: {ts, result: blocked|runs|unknown}. */
	const PROBE_OPTION = 'uaip_sfw_upload_probe';

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
		if ( Uaip_Sfw_Settings::get( 'harden_headers' ) || Uaip_Sfw_Settings::get( 'harden_hsts' ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
			add_action( 'admin_init', array( $this, 'send_security_headers' ) );
			add_action( 'login_init', array( $this, 'send_security_headers' ) );
		}
		if ( Uaip_Sfw_Settings::get( 'harden_hide_users' ) ) {
			add_action( 'parse_request', array( $this, 'block_author_scan' ), 1 );
			add_filter( 'rest_pre_dispatch', array( $this, 'block_rest_users' ), 10, 3 );
			add_filter( 'wp_sitemaps_add_provider', array( $this, 'drop_users_sitemap' ), 10, 2 );
			add_filter( 'oembed_response_data', array( $this, 'strip_oembed_author' ) );
			add_filter( 'authenticate', array( $this, 'generic_login_error' ), 99 );
		}
	}

	/**
	 * Hardening toggles shown on the Hardening screen.
	 *
	 * @return array<string,array{label:string,desc:string}>
	 */
	public function actions() {
		return array(
			'harden_disable_editor'    => array(
				'label' => __( 'Turn off the plugin and theme file editor', 'uaip-security-firewall' ),
				'desc'  => __( 'Nobody can edit PHP files from wp-admin, so a stolen admin account cannot plant code that way.', 'uaip-security-firewall' ),
			),
			'harden_block_php_uploads' => array(
				'label' => __( 'Stop scripts running in uploads', 'uaip-security-firewall' ),
				'desc'  => __( 'Adds a rule to the uploads folder so .php, .phtml, .phar and similar files cannot run, even with a second extension like shell.php.jpg. Works on Apache and LiteSpeed.', 'uaip-security-firewall' ),
			),
			'harden_hide_users'        => array(
				'label' => __( 'Hide usernames from visitors', 'uaip-security-firewall' ),
				'desc'  => __( 'Blocks ?author= scans and the public REST users list, removes users from the sitemap and oEmbed data, and gives the same sign-in error for a wrong username or password.', 'uaip-security-firewall' ),
			),
			'harden_headers'           => array(
				'label' => __( 'Send security headers', 'uaip-security-firewall' ),
				'desc'  => __( 'X-Content-Type-Options, X-Frame-Options (same site only), Referrer-Policy and Permissions-Policy. If another site shows your pages in a frame, leave this off.', 'uaip-security-firewall' ),
			),
			'harden_hsts'              => array(
				'label' => __( 'Force HTTPS in browsers (HSTS)', 'uaip-security-firewall' ),
				'desc'  => __( 'Browsers will only use HTTPS for this site for a year. Turn on only when HTTPS works everywhere on this domain.', 'uaip-security-firewall' ),
			),
			'harden_disable_xmlrpc'    => array(
				'label' => __( 'Turn off XML-RPC', 'uaip-security-firewall' ),
				'desc'  => __( 'Closes a common route for password guessing. Leave on if you use the Jetpack app or old publishing tools.', 'uaip-security-firewall' ),
			),
			'harden_hide_version'      => array(
				'label' => __( 'Hide the WordPress version', 'uaip-security-firewall' ),
				'desc'  => __( 'Removes the generator tag. A small step: keeping WordPress updated matters far more.', 'uaip-security-firewall' ),
			),
		);
	}

	/**
	 * Apply a setting change (called when settings are saved).
	 *
	 * @param string $key     Setting.
	 * @param bool   $enabled On.
	 * @return true|WP_Error
	 */
	public function apply( $key, $enabled ) {
		if ( 'harden_block_php_uploads' === $key ) {
			$dir = $this->uploads_dir();
			delete_option( self::PROBE_OPTION );
			return $enabled ? $this->write_php_block( $dir ) : $this->remove_php_block( $dir );
		}
		if ( 'harden_hsts' === $key && $enabled && ! is_ssl() && 0 !== strpos( home_url(), 'https://' ) ) {
			return new WP_Error( 'no_https', __( 'HSTS was not turned on: this site does not use HTTPS.', 'uaip-security-firewall' ) );
		}
		return true;
	}

	/** @return string Uploads base directory with a trailing slash. */
	private function uploads_dir() {
		return trailingslashit( wp_upload_dir()['basedir'] );
	}

	// ------------------------------------------------------------------
	// Uploads
	// ------------------------------------------------------------------

	/** @return string The managed .htaccess block. */
	private function php_block_rules() {
		return '# BEGIN ' . self::MARKER . "\n"
			. '<FilesMatch "' . self::SCRIPT_PATTERN . "\">\n"
			. "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"
			. "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n"
			. "</FilesMatch>\n"
			. '# END ' . self::MARKER . "\n";
	}

	/**
	 * Write (or refresh) the block in a directory's .htaccess.
	 *
	 * @param string $dir Absolute path with trailing slash.
	 * @return true|WP_Error
	 */
	public function write_php_block( $dir ) {
		$file     = $dir . '.htaccess';
		$rules    = $this->php_block_rules();
		$existing = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		if ( false !== strpos( $existing, $rules ) ) {
			return true;
		}
		$existing = $this->strip_block( $existing );
		if ( ! wp_is_writable( $dir ) ) {
			return new WP_Error( 'not_writable', __( 'The uploads folder is not writable, so the rule could not be added.', 'uaip-security-firewall' ) );
		}
		$ok = file_put_contents( $file, $rules . $existing ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- writing a server config file directly, like core's insert_with_markers().
		return false === $ok ? new WP_Error( 'write_failed', __( 'Could not write the uploads .htaccess file.', 'uaip-security-firewall' ) ) : true;
	}

	/**
	 * Remove the managed block.
	 *
	 * @param string $dir Directory with trailing slash.
	 * @return true
	 */
	public function remove_php_block( $dir ) {
		$file = $dir . '.htaccess';
		if ( ! file_exists( $file ) ) {
			return true;
		}
		$clean = $this->strip_block( (string) file_get_contents( $file ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		if ( '' === trim( $clean ) ) {
			wp_delete_file( $file );
		} else {
			file_put_contents( $file, $clean ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- server config file.
		}
		return true;
	}

	/**
	 * @param string $content .htaccess content.
	 * @return string Without our block.
	 */
	private function strip_block( $content ) {
		return (string) preg_replace( '/# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\s*/s', '', $content );
	}

	/** @return bool The current rule is in place. */
	public function php_block_present() {
		$file = $this->uploads_dir() . '.htaccess';
		return file_exists( $file ) && false !== strpos( (string) file_get_contents( $file ), $this->php_block_rules() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
	}

	/** Rewrite an older version of the block (from a previous plugin version). */
	public function maybe_refresh_php_block() {
		if ( Uaip_Sfw_Settings::get( 'harden_block_php_uploads' ) && ! $this->php_block_present() ) {
			$this->write_php_block( $this->uploads_dir() );
		}
	}

	/**
	 * Put a harmless PHP file in uploads, request it, and see whether it ran.
	 *
	 * @return string blocked|runs|unknown
	 */
	public function probe_uploads() {
		$up   = wp_upload_dir();
		$name = 'uaip-sfw-probe-' . wp_generate_password( 12, false ) . '.php';
		$path = trailingslashit( $up['basedir'] ) . $name;
		// Concatenated so the raw file never contains the token: seeing it means PHP ran.
		if ( false === file_put_contents( $path, "<?php echo 'UAIP' . 'SFW' . '_RAN';\n" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- short-lived test file.
			return 'unknown';
		}
		$res = wp_remote_get(
			trailingslashit( $up['baseurl'] ) . $name,
			array(
				'timeout'     => 8,
				'redirection' => 0,
				'sslverify'   => false, // Loopback to this same site; self-signed certs are common.
			)
		);
		wp_delete_file( $path );

		if ( is_wp_error( $res ) ) {
			$result = 'unknown';
		} elseif ( false !== strpos( (string) wp_remote_retrieve_body( $res ), 'UAIPSFW_RAN' ) ) {
			$result = 'runs';
		} else {
			$code   = (int) wp_remote_retrieve_response_code( $res );
			$result = in_array( $code, array( 401, 403, 404, 200 ), true ) ? 'blocked' : 'unknown';
		}
		update_option(
			self::PROBE_OPTION,
			array(
				'ts'     => time(),
				'result' => $result,
			),
			false
		);
		return $result;
	}

	/** @return array{ts:int,result:string}|null Last probe. */
	public function last_probe() {
		$p = get_option( self::PROBE_OPTION );
		return is_array( $p ) && isset( $p['ts'], $p['result'] ) ? $p : null;
	}

	// ------------------------------------------------------------------
	// Headers
	// ------------------------------------------------------------------

	/** @return array<string,string> Headers to send. */
	public function security_headers() {
		$h = array();
		if ( Uaip_Sfw_Settings::get( 'harden_headers' ) ) {
			$h['X-Content-Type-Options'] = 'nosniff';
			$h['X-Frame-Options']        = 'SAMEORIGIN';
			$h['Referrer-Policy']        = 'strict-origin-when-cross-origin';
			$h['Permissions-Policy']     = 'camera=(), microphone=(), geolocation=(), browsing-topics=()';
		}
		if ( Uaip_Sfw_Settings::get( 'harden_hsts' ) && is_ssl() ) {
			$h['Strict-Transport-Security'] = 'max-age=31536000';
		}
		/**
		 * Filter the security headers. Remove a key to stop sending it.
		 *
		 * @param array<string,string> $h Headers.
		 */
		return (array) apply_filters( 'uaip_sfw_security_headers', $h );
	}

	/** Send headers that another layer has not already set. */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		$already = array();
		foreach ( headers_list() as $line ) {
			$already[ strtolower( trim( strtok( $line, ':' ) ) ) ] = true;
		}
		foreach ( $this->security_headers() as $name => $value ) {
			if ( ! isset( $already[ strtolower( $name ) ] ) ) {
				header( $name . ': ' . $value );
			}
		}
	}

	// ------------------------------------------------------------------
	// Usernames
	// ------------------------------------------------------------------

	/**
	 * ?author=N reveals the login slug through the redirect: refuse it.
	 *
	 * @param WP $wp Request.
	 */
	public function block_author_scan( $wp ) {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only check of a public query var.
		$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : ( isset( $wp->query_vars['author'] ) ? (string) $wp->query_vars['author'] : '' );
		if ( '' !== $author && preg_match( '/^\s*-?\d/', $author ) ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Visitors cannot list users through the REST API.
	 *
	 * @param mixed           $result  Result.
	 * @param WP_REST_Server  $server  Server.
	 * @param WP_REST_Request $request Request.
	 * @return mixed
	 */
	public function block_rest_users( $result, $server, $request ) {
		// Signed-in users keep core's own rules (the editor needs the author list).
		if ( null === $result && ! is_user_logged_in() && preg_match( '#^/wp/v2/users(/|$)#', (string) $request->get_route() ) ) {
			return new WP_Error( 'rest_user_cannot_view', __( 'Sorry, you are not allowed to list users.', 'uaip-security-firewall' ), array( 'status' => 401 ) );
		}
		return $result;
	}

	/**
	 * @param WP_Sitemaps_Provider $provider Provider.
	 * @param string               $name     Name.
	 * @return WP_Sitemaps_Provider|false
	 */
	public function drop_users_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * @param array $data oEmbed data.
	 * @return array
	 */
	public function strip_oembed_author( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	/**
	 * The same message for an unknown user and a wrong password.
	 *
	 * @param WP_User|WP_Error|null $user Result so far.
	 * @return WP_User|WP_Error|null
	 */
	public function generic_login_error( $user ) {
		if ( is_wp_error( $user ) ) {
			$hit = array_intersect( $user->get_error_codes(), array( 'invalid_username', 'invalid_email', 'incorrect_password' ) );
			if ( $hit ) {
				// The real reason stays in the data for the activity log.
				return new WP_Error(
					'uaip_sfw_bad_login',
					__( '<strong>Error:</strong> The username, email address or password is not correct.', 'uaip-security-firewall' ) . ' <a href="' . esc_url( wp_lostpassword_url() ) . '">' . __( 'Lost your password?', 'uaip-security-firewall' ) . '</a>',
					array( 'reason' => reset( $hit ) )
				);
			}
		}
		return $user;
	}
}
