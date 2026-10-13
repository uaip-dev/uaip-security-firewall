<?php
/**
 * Uaip_Sfw_WAF_Engine — declarative, anomaly-scoring rule engine.
 *
 * Each rule contributes a score when it matches; the request is blocked when
 * the total score reaches the threshold. Critical rules carry a score >=
 * threshold so a single match blocks, while lower-confidence rules must
 * corroborate — the ModSecurity/CRS model, but lightweight.
 *
 * Rule (JSON):
 *   {
 *     "id": "uaip-sfw-sqli-001",
 *     "class": "sqli",
 *     "msg": "SQL injection: UNION SELECT",
 *     "severity": "critical",
 *     "score": 10,
 *     "targets": ["query","body","uri"],
 *     "transform": ["urldecode","lowercase","remove_nulls"],
 *     "pattern": "union\\s+(all\\s+)?select",
 *     "flags": "i",
 *     "methods": ["POST"]          (optional: only for these HTTP methods)
 *   }
 *
 * Exceptions switch rules off for a path prefix: array( array( 'rule' => 'sfw-xss-003',
 * 'path' => '/wp-json/contact-form-7/' ) ). Rule "*" means every rule.
 *
 * @package UaipSecurityFirewall
 */

// Block direct web access. Allow loading inside WordPress (ABSPATH) or from the
// standalone auto_prepend WAF bootstrap (which defines UAIP_SFW_WAF_PREPEND
// before WordPress is available).
if ( ! defined( 'ABSPATH' ) ) {
	if ( ! defined( 'UAIP_SFW_WAF_PREPEND' ) ) {
		exit;
	}
}

class Uaip_Sfw_WAF_Engine {

	/** @var array<int,array> */
	private $rules = array();

	/** @var int Block when total score reaches this. */
	private $threshold;

	/** Longest value inspected per field (bytes); the rest is ignored. */
	const MAX_VALUE_BYTES = 65536;

	/**
	 * @param int $threshold
	 */
	public function __construct( $threshold = 5 ) {
		$this->threshold = max( 1, (int) $threshold );
	}

	/** @param string $path JSON ruleset. */
	public function load_json( $path ) {
		$raw = @file_get_contents( $path );
		if ( false === $raw ) {
			return $this;
		}
		$data = json_decode( $raw, true );
		if ( isset( $data['rules'] ) && is_array( $data['rules'] ) ) {
			$this->load_array( $data['rules'] );
		}
		return $this;
	}

	/** @param array $rules */
	public function load_array( array $rules ) {
		foreach ( $rules as $rule ) {
			if ( isset( $rule['id'], $rule['pattern'] ) ) {
				// Key by id so a later load overrides an earlier rule with the
				// same id (bundled baseline + cloud additions/overrides).
				$this->rules[ $rule['id'] ] = $rule;
			}
		}
		return $this;
	}

	/** @return int */
	public function rule_count() {
		return count( $this->rules );
	}

	/**
	 * Evaluate a request.
	 *
	 * @param Uaip_Sfw_WAF_Request $req
	 * @param array                $exceptions Rule/path exceptions (see class docblock).
	 * @return array{score:int,block:bool,matched:array,classes:array}
	 */
	public function evaluate( Uaip_Sfw_WAF_Request $req, array $exceptions = array() ) {
		$score   = 0;
		$matched = array();
		$classes = array();

		foreach ( $this->rules as $rule ) {
			if ( ! empty( $rule['methods'] ) && ! in_array( $req->method, array_map( 'strtoupper', (array) $rule['methods'] ), true ) ) {
				continue;
			}
			if ( self::excepted( $rule['id'], $req->path, $exceptions ) ) {
				continue;
			}
			$hit = $this->match_rule( $rule, $req );
			if ( null === $hit ) {
				continue;
			}
			$rule_score = isset( $rule['score'] ) ? (int) $rule['score'] : 5;
			$score     += $rule_score;
			$class      = isset( $rule['class'] ) ? $rule['class'] : 'generic';

			$matched[]          = array(
				'id'       => $rule['id'],
				'class'    => $class,
				'msg'      => isset( $rule['msg'] ) ? $rule['msg'] : $rule['id'],
				'severity' => isset( $rule['severity'] ) ? $rule['severity'] : 'medium',
				'score'    => $rule_score,
				'sample'   => $hit,
			);
			$classes[ $class ] = ( isset( $classes[ $class ] ) ? $classes[ $class ] : 0 ) + $rule_score;
		}

		return array(
			'score'   => $score,
			'block'   => $score >= $this->threshold,
			'matched' => $matched,
			'classes' => $classes,
		);
	}

	/**
	 * Whether an exception switches this rule off for this path.
	 *
	 * @param string $rule_id    Rule id.
	 * @param string $path       Request path.
	 * @param array  $exceptions Exceptions.
	 * @return bool
	 */
	public static function excepted( $rule_id, $path, array $exceptions ) {
		foreach ( $exceptions as $ex ) {
			$rule = isset( $ex['rule'] ) ? (string) $ex['rule'] : '';
			$pre  = isset( $ex['path'] ) ? (string) $ex['path'] : '';
			if ( ( '*' === $rule || $rule === $rule_id ) && ( '' === $pre || 0 === strpos( $path, $pre ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Parse exception lines: "rule-id [/path/prefix]" per line, "#" comments.
	 *
	 * @param string $text Raw text.
	 * @return array{valid:array,invalid:string[]}
	 */
	public static function parse_exceptions( $text ) {
		$valid   = array();
		$invalid = array();
		foreach ( preg_split( '/[\r\n]+/', (string) $text ) as $line ) {
			$line = trim( preg_replace( '/#.*$/', '', $line ) );
			if ( '' === $line ) {
				continue;
			}
			$parts = preg_split( '/\s+/', $line );
			$rule  = $parts[0];
			$path  = isset( $parts[1] ) ? $parts[1] : '';
			if ( count( $parts ) > 2 || ! preg_match( '/^(\*|[a-z0-9][a-z0-9._-]{0,80})$/i', $rule ) || ( '' !== $path && '/' !== substr( $path, 0, 1 ) ) ) {
				$invalid[] = $line;
				continue;
			}
			$valid[] = array(
				'rule' => strtolower( $rule ),
				'path' => $path,
			);
		}
		return array(
			'valid'   => $valid,
			'invalid' => $invalid,
		);
	}

	/**
	 * Match a single rule across its targets; returns a short matched sample
	 * (truncated) or null.
	 *
	 * @param array          $rule
	 * @param Uaip_Sfw_WAF_Request $req
	 * @return string|null
	 */
	private function match_rule( $rule, Uaip_Sfw_WAF_Request $req ) {
		$targets    = isset( $rule['targets'] ) ? (array) $rule['targets'] : array( 'query', 'body', 'uri' );
		$transforms = isset( $rule['transform'] ) ? (array) $rule['transform'] : array( 'urldecode', 'lowercase', 'remove_nulls' );
		$flags      = isset( $rule['flags'] ) ? preg_replace( '/[^a-z]/', '', strtolower( $rule['flags'] ) ) : 'i';
		$pattern    = isset( $rule['pattern'] ) ? (string) $rule['pattern'] : '';
		// Reject empty or pathologically long patterns from the rule bundle
		// before compiling them (defense-in-depth against a malformed/hostile
		// feed). Catastrophic backtracking is additionally bounded by PHP's
		// pcre.backtrack_limit, after which @preg_match() returns false.
		if ( '' === $pattern || strlen( $pattern ) > 1000 ) {
			return null;
		}
		$regex = '~' . str_replace( '~', '\~', $pattern ) . '~' . $flags;

		foreach ( $targets as $target ) {
			foreach ( $req->target( $target ) as $value ) {
				if ( strlen( $value ) > self::MAX_VALUE_BYTES ) {
					$value = substr( $value, 0, self::MAX_VALUE_BYTES );
				}
				$normalized = $this->transform( $value, $transforms );
				if ( 1 === @preg_match( $regex, $normalized ) ) {
					return $this->sample( $value );
				}
			}
		}
		return null;
	}

	/**
	 * Apply normalization transforms (defeats common evasion).
	 *
	 * @param string $value
	 * @param array  $transforms
	 * @return string
	 */
	private function transform( $value, $transforms ) {
		foreach ( $transforms as $t ) {
			switch ( $t ) {
				case 'lowercase':
					$value = strtolower( $value );
					break;
				case 'urldecode':
					// Decode twice to catch double-encoding.
					$value = rawurldecode( rawurldecode( $value ) );
					break;
				case 'remove_nulls':
					$value = str_replace( "\0", '', $value );
					break;
				case 'compress_whitespace':
					$value = preg_replace( '/\s+/', ' ', $value );
					break;
				case 'remove_whitespace':
					$value = preg_replace( '/\s+/', '', $value );
					break;
				case 'html_decode':
					$value = html_entity_decode( $value, ENT_QUOTES | ENT_HTML5 );
					break;
				case 'strip_comments':
					// SQL/C style comments used to break up keywords count as a space
					// ("union/**/select" -> "union select").
					$value = preg_replace( '#/\*.*?\*/#s', ' ', $value );
					break;
			}
		}
		return $value;
	}

	/** @return string Truncated, safe sample of the offending value. */
	private function sample( $value ) {
		$value = preg_replace( '/\s+/', ' ', $value );
		if ( strlen( $value ) > 120 ) {
			$value = substr( $value, 0, 120 ) . '…';
		}
		return $value;
	}
}
