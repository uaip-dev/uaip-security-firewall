<?php
/**
 * Uaip_Sfw_Yara_Lite — a pure-PHP matcher for a practical subset of the YARA rule
 * language. It exists so UAIP Security can run YARA-style detection on hosts
 * where the native `yara` binary is unavailable (most shared hosting).
 *
 * Supported:
 *   - strings: text ("..."), regex (/.../), hex ({ AA ?? BB [2-4] })
 *   - string modifiers: nocase, wide, ascii, fullword
 *   - condition: $ids with and/or/not + parentheses,
 *                "all|any|N of them", "all|any|N of ($a,$b*)",
 *                filesize <op> N[KB|MB]
 *
 * Limitations (documented): no offset/@ operators, no `for` loops, no module
 * imports. Rule string identifiers should be lowercase. If a condition cannot
 * be parsed it evaluates to false (fail-closed) to avoid false positives.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Yara_Lite {

	/** @var array<int,array> Parsed rules. */
	private $rules = array();

	/** @var array<int,string> Non-fatal parse warnings. */
	private $warnings = array();

	// ------------------------------------------------------------------
	// Loading
	// ------------------------------------------------------------------

	/** @param string $dir Directory of rule files (.txt, YARA syntax). */
	public function load_dir( $dir ) {
		foreach ( (array) glob( rtrim( $dir, '/' ) . '/*.txt' ) as $file ) {
			$this->load_file( $file );
		}
		return $this;
	}

	/** @param string $path */
	public function load_file( $path ) {
		$text = @file_get_contents( $path );
		if ( false !== $text ) {
			$this->load_string( $text );
		}
		return $this;
	}

	/** @param string $text Raw rule content (YARA syntax). */
	public function load_string( $text ) {
		foreach ( $this->parse( $text ) as $rule ) {
			$this->rules[] = $rule;
		}
		return $this;
	}

	/** @return int Number of loaded rules. */
	public function rule_count() {
		return count( $this->rules );
	}

	/** @return array */
	public function warnings() {
		return $this->warnings;
	}

	// ------------------------------------------------------------------
	// Scanning
	// ------------------------------------------------------------------

	/**
	 * @param string $path
	 * @return array<int,array{rule:string,severity:string,description:string}>
	 */
	public function scan_file( $path ) {
		$data = @file_get_contents( $path );
		if ( false === $data ) {
			return array();
		}
		return $this->scan_data( $data, strlen( $data ) );
	}

	/**
	 * @param string   $content
	 * @param int|null $size
	 * @return array
	 */
	public function scan_data( $content, $size = null ) {
		if ( null === $size ) {
			$size = strlen( $content );
		}
		$hits = array();
		foreach ( $this->rules as $rule ) {
			if ( $this->eval_rule( $rule, $content, $size ) ) {
				$hits[] = array(
					'rule'        => $rule['name'],
					'severity'    => isset( $rule['meta']['severity'] ) ? $rule['meta']['severity'] : 'medium',
					'description' => isset( $rule['meta']['description'] ) ? $rule['meta']['description'] : '',
				);
			}
		}
		return $hits;
	}

	// ------------------------------------------------------------------
	// Parsing
	// ------------------------------------------------------------------

	/**
	 * @param string $text
	 * @return array<int,array>
	 */
	private function parse( $text ) {
		// Strip block comments and whole-line // comments only (so we never
		// touch "http://" inside a string literal).
		$text = preg_replace( '#/\*.*?\*/#s', '', $text );
		$text = preg_replace( '#^[ \t]*//.*$#m', '', $text );

		$rules = array();
		$len   = strlen( $text );
		$offset = 0;

		while ( preg_match( '/\brule\s+([A-Za-z_]\w*)\s*(?::[^{]*)?\{/', $text, $m, PREG_OFFSET_CAPTURE, $offset ) ) {
			$name        = $m[1][0];
			$brace_start = $m[0][1] + strlen( $m[0][0] ) - 1;

			// Brace-match the rule body.
			$depth = 0;
			$end   = $brace_start;
			for ( ; $end < $len; $end++ ) {
				if ( '{' === $text[ $end ] ) {
					$depth++;
				} elseif ( '}' === $text[ $end ] ) {
					$depth--;
					if ( 0 === $depth ) {
						break;
					}
				}
			}
			$body  = substr( $text, $brace_start + 1, $end - $brace_start - 1 );
			$rules[] = $this->parse_body( $name, $body );
			$offset  = $end + 1;
		}
		return $rules;
	}

	/**
	 * @param string $name
	 * @param string $body
	 * @return array
	 */
	private function parse_body( $name, $body ) {
		$sections = array( 'meta' => '', 'strings' => '', 'condition' => '' );
		$parts    = preg_split( '/\b(meta|strings|condition)\s*:/', $body, -1, PREG_SPLIT_DELIM_CAPTURE );
		for ( $i = 1; $i < count( $parts ); $i += 2 ) {
			$sections[ $parts[ $i ] ] = $parts[ $i + 1 ];
		}

		return array(
			'name'      => $name,
			'meta'      => $this->parse_meta( $sections['meta'] ),
			'strings'   => $this->parse_strings( $sections['strings'] ),
			'condition' => trim( $sections['condition'] ),
		);
	}

	/** @return array<string,string> */
	private function parse_meta( $text ) {
		$meta = array();
		if ( preg_match_all( '/(\w+)\s*=\s*"((?:\\\\.|[^"])*)"/', $text, $mm, PREG_SET_ORDER ) ) {
			foreach ( $mm as $m ) {
				$meta[ $m[1] ] = stripcslashes( $m[2] );
			}
		}
		return $meta;
	}

	/**
	 * @param string $text
	 * @return array<string,string> id => compiled PCRE
	 */
	private function parse_strings( $text ) {
		$out = array();
		$re  = '/\$(\w+)\s*=\s*("(?:\\\\.|[^"])*"|\/(?:\\\\.|[^\/])*\/|\{[^}]*\})\s*((?:nocase|wide|ascii|fullword|private|\s)*)/i';
		if ( preg_match_all( $re, $text, $mm, PREG_SET_ORDER ) ) {
			foreach ( $mm as $m ) {
				$id        = strtolower( $m[1] );
				$value     = $m[2];
				$modifiers = strtolower( $m[3] );
				$compiled  = $this->compile_string( $value, $modifiers );
				if ( null !== $compiled ) {
					$out[ $id ] = $compiled;
				}
			}
		}
		return $out;
	}

	/**
	 * Compile a YARA string definition to a PCRE pattern.
	 *
	 * @param string $value
	 * @param string $modifiers
	 * @return string|null
	 */
	private function compile_string( $value, $modifiers ) {
		$nocase   = false !== strpos( $modifiers, 'nocase' );
		$wide     = false !== strpos( $modifiers, 'wide' );
		$ascii    = false !== strpos( $modifiers, 'ascii' ) || ! $wide;
		$fullword = false !== strpos( $modifiers, 'fullword' );

		$first = $value[0];

		if ( '"' === $first ) {
			$lit  = stripcslashes( substr( $value, 1, -1 ) );
			$base = preg_quote( $lit, '~' );
			if ( $fullword ) {
				$base = '\b' . $base . '\b';
			}
			$alts = array();
			if ( $ascii ) {
				$alts[] = $base;
			}
			if ( $wide ) {
				// UTF-16LE: a NUL byte between each character.
				$wide_pat = implode( '\x00', array_map(
					function ( $ch ) {
						return preg_quote( $ch, '~' );
					},
					str_split( $lit )
				) );
				$alts[] = $wide_pat;
			}
			$pat   = '(?:' . implode( '|', $alts ) . ')';
			$flags = 's' . ( $nocase ? 'i' : '' );
			return '~' . $pat . '~' . $flags;
		}

		if ( '/' === $first ) {
			$close = strrpos( $value, '/' );
			$pat   = substr( $value, 1, $close - 1 );
			$flags = strtolower( substr( $value, $close + 1 ) );
			$flags = preg_replace( '/[^a-z]/', '', $flags );
			if ( false === strpos( $flags, 's' ) ) {
				$flags .= 's';
			}
			if ( $nocase && false === strpos( $flags, 'i' ) ) {
				$flags .= 'i';
			}
			return '/' . $pat . '/' . $flags;
		}

		if ( '{' === $first ) {
			return $this->compile_hex( substr( $value, 1, -1 ) );
		}
		return null;
	}

	/**
	 * Compile a hex string ({ AA ?? BB [2-4] }) to a PCRE pattern.
	 *
	 * @param string $hex
	 * @return string|null
	 */
	private function compile_hex( $hex ) {
		$hex    = trim( $hex );
		$tokens = preg_split( '/\s+/', $hex );
		$pat    = '';
		foreach ( $tokens as $t ) {
			if ( '' === $t ) {
				continue;
			}
			if ( '??' === $t ) {
				$pat .= '.';
			} elseif ( preg_match( '/^\[(\d+)(?:-(\d+))?\]$/', $t, $j ) ) {
				$pat .= isset( $j[2] ) ? '.{' . $j[1] . ',' . $j[2] . '}' : '.{' . $j[1] . '}';
			} elseif ( preg_match( '/^[0-9a-fA-F]{2}$/', $t ) ) {
				$pat .= '\x' . strtoupper( $t );
			} else {
				$this->warnings[] = "Unsupported hex token: $t";
				return null;
			}
		}
		return '~' . $pat . '~s';
	}

	// ------------------------------------------------------------------
	// Evaluation
	// ------------------------------------------------------------------

	/**
	 * @param array  $rule
	 * @param string $content
	 * @param int    $size
	 * @return bool
	 */
	private function eval_rule( $rule, $content, $size ) {
		if ( empty( $rule['condition'] ) ) {
			return false;
		}
		$matched = array();
		foreach ( $rule['strings'] as $id => $regex ) {
			$matched[ $id ] = ( 1 === @preg_match( $regex, $content ) );
		}
		return $this->eval_condition( $rule['condition'], $matched, $size );
	}

	/**
	 * @param string $cond
	 * @param array  $matched id => bool
	 * @param int    $size
	 * @return bool
	 */
	private function eval_condition( $cond, $matched, $size ) {
		$cond    = strtolower( $cond );
		$all_ids = array_keys( $matched );

		// 1) filesize comparisons.
		$cond = preg_replace_callback(
			'/filesize\s*(<=|>=|<|>|==|!=)\s*(\d+)\s*(kb|mb|gb)?/',
			function ( $m ) use ( $size ) {
				$n    = (int) $m[2];
				$mult = array( '' => 1, 'kb' => 1024, 'mb' => 1048576, 'gb' => 1073741824 );
				$n   *= $mult[ isset( $m[3] ) ? $m[3] : '' ];
				return $this->cmp( $size, $m[1], $n ) ? 'true' : 'false';
			},
			$cond
		);

		// 2) "X of them".
		$cond = preg_replace_callback(
			'/\b(all|any|\d+)\s+of\s+them\b/',
			function ( $m ) use ( $matched, $all_ids ) {
				return $this->quantify( $m[1], $all_ids, $matched ) ? 'true' : 'false';
			},
			$cond
		);

		// 3) "X of ($a, $b*)".
		$cond = preg_replace_callback(
			'/\b(all|any|\d+)\s+of\s+\(([^)]*)\)/',
			function ( $m ) use ( $matched, $all_ids ) {
				$set = $this->resolve_set( $m[2], $all_ids );
				return $this->quantify( $m[1], $set, $matched ) ? 'true' : 'false';
			},
			$cond
		);

		// 4) Replace remaining $ids with their boolean.
		$cond = preg_replace_callback(
			'/\$(\w+)/',
			function ( $m ) use ( $matched ) {
				$id = strtolower( $m[1] );
				return ( ! empty( $matched[ $id ] ) ) ? 'true' : 'false';
			},
			$cond
		);

		return $this->eval_bool( $cond );
	}

	/** Numeric comparison helper. */
	private function cmp( $a, $op, $b ) {
		switch ( $op ) {
			case '<':  return $a < $b;
			case '>':  return $a > $b;
			case '<=': return $a <= $b;
			case '>=': return $a >= $b;
			case '==': return $a === $b;
			case '!=': return $a !== $b;
		}
		return false;
	}

	/**
	 * @param string $quant 'all'|'any'|integer
	 * @param array  $set   ids
	 * @param array  $matched
	 * @return bool
	 */
	private function quantify( $quant, $set, $matched ) {
		$count = 0;
		foreach ( $set as $id ) {
			if ( ! empty( $matched[ $id ] ) ) {
				$count++;
			}
		}
		$total = count( $set );
		if ( 'all' === $quant ) {
			return $total > 0 && $count === $total;
		}
		if ( 'any' === $quant ) {
			return $count >= 1;
		}
		return $count >= (int) $quant;
	}

	/**
	 * Resolve a set spec like "$a, $b*, $c" into matching ids (supports * prefix wildcard).
	 *
	 * @param string $spec
	 * @param array  $all_ids
	 * @return array
	 */
	private function resolve_set( $spec, $all_ids ) {
		$out = array();
		foreach ( explode( ',', $spec ) as $tok ) {
			$tok = strtolower( trim( $tok ) );
			$tok = ltrim( $tok, '$' );
			if ( '' === $tok ) {
				continue;
			}
			if ( '*' === substr( $tok, -1 ) ) {
				$prefix = rtrim( $tok, '*' );
				foreach ( $all_ids as $id ) {
					if ( 0 === strpos( $id, $prefix ) ) {
						$out[] = $id;
					}
				}
			} else {
				$out[] = $tok;
			}
		}
		return array_unique( $out );
	}

	/**
	 * Evaluate a boolean expression of true/false/and/or/not/() via shunting-yard.
	 *
	 * @param string $expr
	 * @return bool
	 */
	private function eval_bool( $expr ) {
		preg_match_all( '/true|false|and|or|not|\(|\)/', $expr, $tm );
		$tokens = $tm[0];
		if ( empty( $tokens ) ) {
			return false;
		}

		$prec   = array( 'not' => 3, 'and' => 2, 'or' => 1 );
		$output = array();
		$ops    = array();

		foreach ( $tokens as $tok ) {
			if ( 'true' === $tok || 'false' === $tok ) {
				$output[] = ( 'true' === $tok );
			} elseif ( 'not' === $tok ) {
				$ops[] = $tok;
			} elseif ( 'and' === $tok || 'or' === $tok ) {
				while ( ! empty( $ops ) && isset( $prec[ end( $ops ) ] ) && $prec[ end( $ops ) ] >= $prec[ $tok ] ) {
					$this->apply_op( array_pop( $ops ), $output );
				}
				$ops[] = $tok;
			} elseif ( '(' === $tok ) {
				$ops[] = $tok;
			} elseif ( ')' === $tok ) {
				while ( ! empty( $ops ) && '(' !== end( $ops ) ) {
					$this->apply_op( array_pop( $ops ), $output );
				}
				array_pop( $ops ); // discard '('
			}
		}
		while ( ! empty( $ops ) ) {
			$op = array_pop( $ops );
			if ( '(' === $op ) {
				continue;
			}
			$this->apply_op( $op, $output );
		}

		return ! empty( $output ) ? (bool) array_pop( $output ) : false;
	}

	/**
	 * @param string $op
	 * @param array  $stack
	 */
	private function apply_op( $op, &$stack ) {
		if ( 'not' === $op ) {
			$a       = array_pop( $stack );
			$stack[] = ! $a;
			return;
		}
		$b = array_pop( $stack );
		$a = array_pop( $stack );
		if ( 'and' === $op ) {
			$stack[] = ( $a && $b );
		} elseif ( 'or' === $op ) {
			$stack[] = ( $a || $b );
		}
	}
}
