<?php
/**
 * Uaip_Sfw_WAF_Request — a normalized view of the incoming HTTP request that the
 * rule engine inspects. Provides named "targets" (query, body, uri, headers,
 * ua, referer, cookies, files, raw) flattened to scalar strings for matching.
 *
 * Bodies are read whatever their format: form posts ($_POST), JSON (REST API,
 * block editor, many AJAX endpoints) and other raw bodies. Password fields are
 * never inspected, so a password with quotes or SQL-looking text still works.
 *
 * @package UaipSecurityFirewall
 */

// Block direct web access. Allow loading either inside WordPress (ABSPATH) or
// standalone from an early-firewall bootstrap (which defines UAIP_SFW_WAF_PREPEND
// before WordPress is available).
if ( ! defined( 'ABSPATH' ) ) {
	if ( ! defined( 'UAIP_SFW_WAF_PREPEND' ) ) {
		exit;
	}
}

class Uaip_Sfw_WAF_Request {

	/** Most body bytes read from php://input (bigger bodies are inspected up to this). */
	const MAX_BODY_BYTES = 1048576;

	/** Body/query keys whose values are never inspected (passwords). */
	const SECRET_KEY = '/(^|[_\-\[])(pass(word)?|pwd|passwd|pass1|pass2|user_pass|new_?pass(word)?|current_?pass(word)?)($|[_\-\]])/i';

	public $ip      = '';
	public $method  = '';
	public $uri     = '';
	public $path    = '';
	public $query   = array();
	public $body    = array();
	public $raw     = '';
	public $files   = array();
	public $headers = array();
	public $ua      = '';
	public $referer = '';
	public $cookies = array();

	/**
	 * Build from PHP superglobals.
	 *
	 * @param string $ip_source One of Uaip_Sfw_IP::SOURCES.
	 * @param array  $trusted   Trusted proxy IPs/CIDRs.
	 * @return Uaip_Sfw_WAF_Request
	 */
	public static function from_globals( $ip_source = 'remote_addr', array $trusted = array() ) {
		// A firewall must inspect the RAW request bytes: sanitising (e.g.
		// sanitize_text_field) would strip the very "<script>", quotes and
		// control characters the rules exist to detect, defeating the WAF. These
		// values are used ONLY for in-memory pattern matching and are never
		// trusted downstream — the only value persisted is the URI, which is
		// sanitized on storage (sanitize_text_field in Uaip_Sfw_WAF::trim_uri) and
		// escaped again on output (esc_html in the admin tables). self::unslash
		// mirrors wp_unslash() but is safe before WordPress loads.
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification -- raw request data is required for signature matching; read-only, escaped at every output.
		$server = $_SERVER;
		$data   = array(
			'method'  => isset( $server['REQUEST_METHOD'] ) ? (string) $server['REQUEST_METHOD'] : 'GET',
			'uri'     => isset( $server['REQUEST_URI'] ) ? self::unslash( $server['REQUEST_URI'] ) : '',
			'ua'      => isset( $server['HTTP_USER_AGENT'] ) ? self::unslash( $server['HTTP_USER_AGENT'] ) : '',
			'referer' => isset( $server['HTTP_REFERER'] ) ? self::unslash( $server['HTTP_REFERER'] ) : '',
			'query'   => self::unslash( $_GET ),
			'body'    => self::unslash( $_POST ),
			'cookies' => self::unslash( $_COOKIE ),
			'files'   => self::file_names( $_FILES ),
			'headers' => array(),
			'ip'      => Uaip_Sfw_IP::client( $server, $ip_source, $trusted ),
		);
		foreach ( $server as $k => $v ) {
			if ( 0 === strpos( $k, 'HTTP_' ) && is_string( $v ) ) {
				$data['headers'][ strtolower( str_replace( '_', '-', substr( $k, 5 ) ) ) ] = self::unslash( $v );
			}
		}
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification

		// Non-form bodies (JSON, XML, text): PHP leaves $_POST empty for these.
		$type = isset( $server['CONTENT_TYPE'] ) ? strtolower( (string) $server['CONTENT_TYPE'] ) : '';
		if ( empty( $data['body'] ) && in_array( strtoupper( $data['method'] ), array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true )
			&& false === strpos( $type, 'multipart/form-data' ) ) {
			// php://input can be read again by WordPress/REST later (not multipart).
			$raw = @file_get_contents( 'php://input', false, null, 0, self::MAX_BODY_BYTES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the raw request body (not a file), read before WordPress's HTTP API is relevant.
			if ( is_string( $raw ) && '' !== $raw ) {
				$json = ( false !== strpos( $type, 'json' ) || in_array( substr( ltrim( $raw ), 0, 1 ), array( '{', '[' ), true ) ) ? json_decode( $raw, true ) : null;
				if ( is_array( $json ) ) {
					$data['body'] = $json;
				} else {
					$data['raw'] = $raw;
				}
			}
		}
		return self::from_array( $data );
	}

	/**
	 * Build from plain data (used by from_globals() and by the tests).
	 *
	 * @param array $data Keys: method, uri, ua, referer, query, body, raw, cookies, files, headers, ip.
	 * @return Uaip_Sfw_WAF_Request
	 */
	public static function from_array( array $data ) {
		$r          = new self();
		$r->method  = strtoupper( preg_replace( '/[^A-Za-z]/', '', isset( $data['method'] ) ? (string) $data['method'] : 'GET' ) );
		$r->uri     = isset( $data['uri'] ) ? (string) $data['uri'] : '/';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- also runs before WordPress loads, where wp_parse_url() is unavailable.
		$r->path    = (string) parse_url( $r->uri, PHP_URL_PATH );
		$r->ua      = isset( $data['ua'] ) ? (string) $data['ua'] : '';
		$r->referer = isset( $data['referer'] ) ? (string) $data['referer'] : '';
		$r->query   = self::without_secrets( isset( $data['query'] ) ? (array) $data['query'] : array() );
		$r->body    = self::without_secrets( isset( $data['body'] ) ? (array) $data['body'] : array() );
		$r->raw     = isset( $data['raw'] ) ? (string) $data['raw'] : '';
		$r->cookies = isset( $data['cookies'] ) ? (array) $data['cookies'] : array();
		$r->files   = isset( $data['files'] ) ? array_values( array_map( 'strval', (array) $data['files'] ) ) : array();
		$r->headers = isset( $data['headers'] ) ? array_change_key_case( (array) $data['headers'], CASE_LOWER ) : array();
		$r->ip      = isset( $data['ip'] ) ? (string) $data['ip'] : '';
		return $r;
	}

	/**
	 * Drop password-like fields (at any depth) so they are never inspected.
	 *
	 * @param array $data Fields.
	 * @return array
	 */
	private static function without_secrets( array $data ) {
		foreach ( $data as $key => $value ) {
			if ( is_string( $key ) && preg_match( self::SECRET_KEY, $key ) ) {
				unset( $data[ $key ] );
			} elseif ( is_array( $value ) ) {
				$data[ $key ] = self::without_secrets( $value );
			}
		}
		return $data;
	}

	/**
	 * Uploaded file names from $_FILES (single and multiple uploads).
	 *
	 * @param array $files $_FILES.
	 * @return string[]
	 */
	private static function file_names( $files ) {
		$names = array();
		foreach ( (array) $files as $file ) {
			if ( isset( $file['name'] ) ) {
				$list = (array) $file['name'];
				array_walk_recursive(
					$list,
					function ( $n ) use ( &$names ) {
						if ( is_string( $n ) && '' !== $n ) {
							$names[] = $n;
						}
					}
				);
			}
		}
		return $names;
	}

	/**
	 * Remove WordPress's added slashes — but only when running inside WP (which
	 * adds them). In a standalone early bootstrap the superglobals are not
	 * slashed, so we must NOT strip. Uses no WP functions.
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
				$values = $this->flatten( $this->body );
				if ( '' !== $this->raw ) {
					$values[] = $this->raw;
				}
				return $values;
			case 'body_keys':
				return $this->keys( $this->body );
			case 'raw':
				return '' !== $this->raw ? array( $this->raw ) : array();
			case 'files':
				return $this->files;
			case 'cookies':
				return $this->flatten( $this->cookies );
			case 'headers':
				return array_values( array_filter( $this->headers, 'is_string' ) );
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
		$out  = array();
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
}
