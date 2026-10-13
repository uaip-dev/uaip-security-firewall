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
 *     "flags": "i"
 *   }
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
	 * @return array{score:int,block:bool,matched:array,classes:array}
	 */
	public function evaluate( Uaip_Sfw_WAF_Request $req ) {
		$score   = 0;
		$matched = array();
		$classes = array();

		foreach ( $this->rules as $rule ) {
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
					// Strip SQL/C style comments used to break up keywords.
					$value = preg_replace( '#/\*.*?\*/#s', '', $value );
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
