<?php
/**
 * Uaip_Sfw_WAF_Request — a normalized view of the incoming HTTP request that the
 * rule engine inspects. Provides named "targets" (query, body, uri, headers,
 * ua, referer, cookies) flattened to scalar strings for matching.
 *
 * @package UaipSecurityFirewall
 */

// Block direct web access. Allow loading either inside WordPress (ABSPATH) or
// standalone from the auto_prepend WAF bootstrap (which defines
// UAIP_SFW_WAF_PREPEND before WordPress is available).
if ( ! defined( 'ABSPATH' ) ) {
	if ( ! defined( 'UAIP_SFW_WAF_PREPEND' ) ) {
		exit;
	}
}

class Uaip_Sfw_WAF_Request {

	public $ip      = '';
	public $method  = '';
	public $uri     = '';
	public $path    = '';
	public $query   = array();
	public $body    = array();
	public $headers = array();
	public $ua      = '';
	public $referer = '';
	public $cookies = array();

	/**
	 * Build from PHP superglobals.
	 *
	 * @return Uaip_Sfw_WAF_Request
	 */
	public static function from_globals() {
		$r = new self();

		// A firewall must inspect the RAW request bytes: sanitising (e.g.
		// sanitize_text_field) would strip the very "<script>", quotes and
		// control characters the rules exist to detect, defeating the WAF. These
		// values are used ONLY for in-memory pattern matching and are never
		// trusted downstream — the only value persisted is the URI, which is
		// sanitized on storage (sanitize_text_field in Uaip_Sfw_WAF::trim_uri) and
		// escaped again on output (esc_html in the admin tables). self::unslash
		// mirrors wp_unslash() but is safe before WordPress loads (auto_prepend).
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- raw request data is required for signature matching; escaped at every output.
		$r->method  = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( preg_replace( '/[^A-Za-z]/', '', (string) $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		$r->uri     = isset( $_SERVER['REQUEST_URI'] ) ? self::unslash( $_SERVER['REQUEST_URI'] ) : '';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- runs standalone via auto_prepend before WordPress loads, so wp_parse_url() is unavailable.
		$r->path    = (string) parse_url( $r->uri, PHP_URL_PATH );
		$r->ua      = isset( $_SERVER['HTTP_USER_AGENT'] ) ? self::unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
		$r->referer = isset( $_SERVER['HTTP_REFERER'] ) ? self::unslash( $_SERVER['HTTP_REFERER'] ) : '';
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput
		$r->ip      = self::client_ip();

		// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification -- raw request data required for WAF matching (see note above); read-only, no state change.
		$r->query   = self::unslash( $_GET );
		$r->body    = self::unslash( $_POST );
		$r->cookies = self::unslash( $_COOKIE );

		foreach ( $_SERVER as $k => $v ) {
			if ( 0 === strpos( $k, 'HTTP_' ) ) {
				$name                = strtolower( str_replace( '_', '-', substr( $k, 5 ) ) );
				$r->headers[ $name ] = self::unslash( $v );
			}
		}
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
		return $r;
	}

	/**
	 * Remove WordPress's added slashes — but only when running inside WP (which
	 * adds them). In the standalone auto_prepend context the superglobals are
	 * not slashed, so we must NOT strip. Uses no WP functions so it is safe to
	 * run before WordPress loads.
	 *
	 * @param mixed $value
	 * @return mixed
	 */
	private static function unslash( $value ) {
		$wp_loaded = defined( 'ABSPATH' ) && ! defined( 'UAIP_SFW_WAF_PREPEND' );
		if ( ! $wp_loaded ) {
			return $value;
		}
		if ( is_array( $value ) ) {
			return array_map( array( __CLASS__, 'unslash' ), $value );
		}
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}

	/**
	 * Return the scalar string values for a named target.
	 *
	 * @param string $target
	 * @return array<int,string>
	 */
	public function target( $target ) {
		switch ( $target ) {
			case 'uri':
				return array( $this->uri );
			case 'path':
				return array( $this->path );
			case 'ua':
				return array( $this->ua );
			case 'referer':
				return array( $this->referer );
			case 'query':
				return $this->flatten( $this->query );
			case 'query_keys':
				return $this->keys( $this->query );
			case 'body':
				return $this->flatten( $this->body );
			case 'body_keys':
				return $this->keys( $this->body );
			case 'cookies':
				return $this->flatten( $this->cookies );
			case 'headers':
				return array_values( $this->headers );
			default:
				return array();
		}
	}

	/**
	 * Flatten a (possibly nested) array to scalar string leaves.
	 *
	 * @param mixed $data
	 * @return array<int,string>
	 */
	private function flatten( $data ) {
		$out = array();
		$arr = (array) $data;
		array_walk_recursive(
			$arr,
			function ( $v ) use ( &$out ) {
				if ( is_scalar( $v ) ) {
					$out[] = (string) $v;
				}
			}
		);
		return $out;
	}

	/**
	 * Collect all (including nested) array keys as strings.
	 *
	 * @param array $data
	 * @return array<int,string>
	 */
	private function keys( $data ) {
		$out = array();
		$walk = function ( $arr ) use ( &$walk, &$out ) {
			foreach ( (array) $arr as $k => $v ) {
				$out[] = (string) $k;
				if ( is_array( $v ) ) {
					$walk( $v );
				}
			}
		};
		$walk( $data );
		return $out;
	}

	/** @return string Best-effort client IP (no WP dependency). */
	public static function client_ip() {
		if ( ! isset( $_SERVER['REMOTE_ADDR'] ) ) {
			return '';
		}
		// Validated as an IP address (the correct sanitiser for this datum);
		// anything that fails validation is reduced to IP-legal characters.
		$ip = trim( (string) $_SERVER['REMOTE_ADDR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated as an IP below; IPs contain no slashes so wp_unslash is unnecessary.
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : preg_replace( '/[^0-9a-fA-F:.]/', '', $ip );
	}
}
