<?php
/**
 * Uaip_Sfw_QR — a self-contained QR Code encoder (byte mode, ECC level L,
 * versions 1-10) that renders to SVG. No external library, no network: the
 * TOTP secret is encoded on the server and embedded inline, so it never
 * leaves the site.
 *
 * Algorithm follows the public QR Code spec (Nayuki reference model). GF(256)
 * tables, generator polynomials and BCH format/version bits are all computed
 * at runtime to avoid transcription errors; only the standard per-version
 * error-correction block structure and alignment positions are tabulated.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_QR {

	/** ECC level L: error-correction codewords per block, and block layout. */
	private static $ECC_L = array(
		1  => array( 7,  array( array( 1, 19 ) ) ),
		2  => array( 10, array( array( 1, 34 ) ) ),
		3  => array( 15, array( array( 1, 55 ) ) ),
		4  => array( 20, array( array( 1, 80 ) ) ),
		5  => array( 26, array( array( 1, 108 ) ) ),
		6  => array( 18, array( array( 2, 68 ) ) ),
		7  => array( 20, array( array( 2, 78 ) ) ),
		8  => array( 24, array( array( 2, 97 ) ) ),
		9  => array( 30, array( array( 2, 116 ) ) ),
		10 => array( 18, array( array( 2, 68 ), array( 2, 69 ) ) ),
	);

	/** Alignment pattern centre coordinates per version. */
	private static $ALIGN = array(
		1  => array(),
		2  => array( 6, 18 ),
		3  => array( 6, 22 ),
		4  => array( 6, 26 ),
		5  => array( 6, 30 ),
		6  => array( 6, 34 ),
		7  => array( 6, 22, 38 ),
		8  => array( 6, 24, 42 ),
		9  => array( 6, 26, 46 ),
		10 => array( 6, 28, 50 ),
	);

	/** Remainder bits appended after the interleaved codewords. */
	private static $REMAINDER = array( 1 => 0, 2 => 7, 3 => 7, 4 => 7, 5 => 7, 6 => 7, 7 => 0, 8 => 0, 9 => 0, 10 => 0 );

	private $version;
	private $size;
	private $modules = array();   // int 0/1
	private $isfn    = array();   // bool
	private $finalbytes = array();

	// GF(256)
	private $exp = array();
	private $log = array();

	/**
	 * Render $text as an SVG QR code string.
	 *
	 * @param string $text
	 * @param int    $scale Module size in px.
	 * @param int    $quiet Quiet-zone width in modules.
	 * @return string SVG markup.
	 * @throws Exception If the text does not fit in versions 1-10.
	 */
	public static function svg( $text, $scale = 5, $quiet = 4 ) {
		$qr = new self();
		$qr->build( $text );
		return $qr->to_svg( $scale, $quiet );
	}

	/**
	 * Build the QR matrix for the given text.
	 *
	 * @param string $text
	 * @throws Exception
	 */
	public function build( $text ) {
		$this->init_gf();

		$bytes = array_values( unpack( 'C*', $text ) );
		$len   = count( $bytes );

		// Pick the smallest version (1-10, ECC L) that fits.
		$this->version = 0;
		for ( $v = 1; $v <= 10; $v++ ) {
			$cap_bits   = $this->data_codewords( $v ) * 8;
			$count_bits = ( $v < 10 ) ? 8 : 16;
			$needed     = 4 + $count_bits + 8 * $len;
			if ( $needed <= $cap_bits ) {
				$this->version = $v;
				break;
			}
		}
		if ( 0 === $this->version ) {
			throw new Exception( 'QR payload too large for versions 1-10' );
		}

		$this->size = 17 + 4 * $this->version;
		$this->finalbytes = $this->encode_codewords( $bytes, $len );

		$this->init_matrix();
		$this->draw_function_patterns();
		$this->place_data( $this->bytes_to_bits( $this->finalbytes ) );

		// Choose the mask with the lowest penalty.
		$best = -1;
		$best_pen = PHP_INT_MAX;
		$best_matrix = null;
		for ( $m = 0; $m < 8; $m++ ) {
			$cand = $this->with_mask( $m );
			$pen  = $this->penalty( $cand );
			if ( $pen < $best_pen ) {
				$best_pen    = $pen;
				$best        = $m;
				$best_matrix = $cand;
			}
		}
		$this->modules = $best_matrix;
		$this->mask    = $best;
	}

	private $mask = 0;

	// ------------------------------------------------------------------
	// Codeword encoding
	// ------------------------------------------------------------------

	/** @return int Total data codewords for a version at ECC L. */
	private function data_codewords( $v ) {
		$total = 0;
		foreach ( self::$ECC_L[ $v ][1] as $grp ) {
			$total += $grp[0] * $grp[1];
		}
		return $total;
	}

	/**
	 * Build the interleaved data+ECC codeword stream.
	 *
	 * @param array $bytes
	 * @param int   $len
	 * @return array
	 */
	private function encode_codewords( $bytes, $len ) {
		$count_bits = ( $this->version < 10 ) ? 8 : 16;
		$cap_cw     = $this->data_codewords( $this->version );
		$cap_bits   = $cap_cw * 8;

		// Bit stream: mode (0100) + count + data.
		$bits = array();
		$this->push_bits( $bits, 0b0100, 4 );
		$this->push_bits( $bits, $len, $count_bits );
		foreach ( $bytes as $b ) {
			$this->push_bits( $bits, $b, 8 );
		}
		// Terminator + pad to byte boundary.
		$term = min( 4, $cap_bits - count( $bits ) );
		$this->push_bits( $bits, 0, $term );
		while ( count( $bits ) % 8 !== 0 ) {
			$bits[] = 0;
		}
		// Pad bytes 0xEC / 0x11.
		$pad = array( 0xEC, 0x11 );
		$pi  = 0;
		$data = $this->bits_to_bytes( $bits );
		while ( count( $data ) < $cap_cw ) {
			$data[] = $pad[ $pi % 2 ];
			$pi++;
		}

		// Split into blocks, compute ECC per block.
		$ec_per   = self::$ECC_L[ $this->version ][0];
		$blocks   = array();
		$ec_blocks = array();
		$idx = 0;
		foreach ( self::$ECC_L[ $this->version ][1] as $grp ) {
			for ( $b = 0; $b < $grp[0]; $b++ ) {
				$blk = array_slice( $data, $idx, $grp[1] );
				$idx += $grp[1];
				$blocks[]    = $blk;
				$ec_blocks[] = $this->rs_ecc( $blk, $ec_per );
			}
		}

		// Interleave data, then ECC.
		$result   = array();
		$max_data = 0;
		foreach ( $blocks as $blk ) {
			$max_data = max( $max_data, count( $blk ) );
		}
		for ( $i = 0; $i < $max_data; $i++ ) {
			foreach ( $blocks as $blk ) {
				if ( $i < count( $blk ) ) {
					$result[] = $blk[ $i ];
				}
			}
		}
		for ( $i = 0; $i < $ec_per; $i++ ) {
			foreach ( $ec_blocks as $ec ) {
				$result[] = $ec[ $i ];
			}
		}
		return $result;
	}

	// ------------------------------------------------------------------
	// GF(256) + Reed-Solomon
	// ------------------------------------------------------------------

	private function init_gf() {
		$x = 1;
		for ( $i = 0; $i < 255; $i++ ) {
			$this->exp[ $i ]   = $x;
			$this->log[ $x ]   = $i;
			$x <<= 1;
			if ( $x & 0x100 ) {
				$x ^= 0x11D;
			}
		}
		for ( $i = 255; $i < 512; $i++ ) {
			$this->exp[ $i ] = $this->exp[ $i - 255 ];
		}
	}

	private function gf_mul( $a, $b ) {
		if ( 0 === $a || 0 === $b ) {
			return 0;
		}
		return $this->exp[ ( $this->log[ $a ] + $this->log[ $b ] ) % 255 ];
	}

	/** @return array Generator polynomial of degree $n. */
	private function rs_generator( $n ) {
		$g = array( 1 );
		for ( $i = 0; $i < $n; $i++ ) {
			// Multiply g by (x - α^i) = (x + α^i) in GF(2^8).
			$next = array_fill( 0, count( $g ) + 1, 0 );
			for ( $j = 0; $j < count( $g ); $j++ ) {
				$next[ $j ]     ^= $this->gf_mul( $g[ $j ], 1 );
				$next[ $j + 1 ] ^= $this->gf_mul( $g[ $j ], $this->exp[ $i ] );
			}
			$g = $next;
		}
		return $g;
	}

	/**
	 * @param array $data
	 * @param int   $ec_len
	 * @return array ECC codewords.
	 */
	private function rs_ecc( $data, $ec_len ) {
		$gen = $this->rs_generator( $ec_len );
		$res = array_merge( $data, array_fill( 0, $ec_len, 0 ) );
		$dlen = count( $data );
		for ( $i = 0; $i < $dlen; $i++ ) {
			$coef = $res[ $i ];
			if ( 0 !== $coef ) {
				for ( $j = 0; $j <= $ec_len; $j++ ) {
					$res[ $i + $j ] ^= $this->gf_mul( $gen[ $j ], $coef );
				}
			}
		}
		return array_slice( $res, $dlen, $ec_len );
	}

	// ------------------------------------------------------------------
	// Matrix
	// ------------------------------------------------------------------

	private function init_matrix() {
		$this->modules = array();
		$this->isfn    = array();
		for ( $r = 0; $r < $this->size; $r++ ) {
			$this->modules[ $r ] = array_fill( 0, $this->size, 0 );
			$this->isfn[ $r ]    = array_fill( 0, $this->size, false );
		}
	}

	private function set_fn( $r, $c, $dark ) {
		if ( $r < 0 || $c < 0 || $r >= $this->size || $c >= $this->size ) {
			return;
		}
		$this->modules[ $r ][ $c ] = $dark ? 1 : 0;
		$this->isfn[ $r ][ $c ]    = true;
	}

	private function draw_function_patterns() {
		// Timing patterns.
		for ( $i = 0; $i < $this->size; $i++ ) {
			$this->set_fn( 6, $i, 0 === $i % 2 );
			$this->set_fn( $i, 6, 0 === $i % 2 );
		}
		// Finder patterns (+ separators via chebyshev distance 4 = light).
		$this->draw_finder( 3, 3 );
		$this->draw_finder( 3, $this->size - 4 );
		$this->draw_finder( $this->size - 4, 3 );

		// Alignment patterns.
		$pos  = self::$ALIGN[ $this->version ];
		$last = count( $pos ) - 1;
		for ( $i = 0; $i <= $last; $i++ ) {
			for ( $j = 0; $j <= $last; $j++ ) {
				if ( ( 0 === $i && 0 === $j ) || ( 0 === $i && $last === $j ) || ( $last === $i && 0 === $j ) ) {
					continue; // overlaps a finder
				}
				$this->draw_alignment( $pos[ $i ], $pos[ $j ] );
			}
		}

		// Dark module.
		$this->set_fn( 4 * $this->version + 9, 8, true );

		// Reserve format + version areas (values written after masking).
		$this->reserve_format();
		if ( $this->version >= 7 ) {
			$this->reserve_version();
		}
	}

	private function draw_finder( $cr, $cc ) {
		for ( $dr = -4; $dr <= 4; $dr++ ) {
			for ( $dc = -4; $dc <= 4; $dc++ ) {
				$dist = max( abs( $dr ), abs( $dc ) );
				$this->set_fn( $cr + $dr, $cc + $dc, ( 2 !== $dist && 4 !== $dist ) );
			}
		}
	}

	private function draw_alignment( $cr, $cc ) {
		for ( $dr = -2; $dr <= 2; $dr++ ) {
			for ( $dc = -2; $dc <= 2; $dc++ ) {
				$dist = max( abs( $dr ), abs( $dc ) );
				$this->set_fn( $cr + $dr, $cc + $dc, ( 1 !== $dist ) );
			}
		}
	}

	private function reserve_format() {
		// Reserve exactly the cells write_format() writes (row, col).
		for ( $i = 0; $i <= 5; $i++ ) {
			$this->set_fn( $i, 8, false );
		}
		$this->set_fn( 7, 8, false );
		$this->set_fn( 8, 8, false );
		$this->set_fn( 8, 7, false );
		for ( $i = 9; $i <= 14; $i++ ) {
			$this->set_fn( 8, 14 - $i, false );
		}
		for ( $i = 0; $i <= 7; $i++ ) {
			$this->set_fn( 8, $this->size - 1 - $i, false );
		}
		for ( $i = 8; $i <= 14; $i++ ) {
			$this->set_fn( $this->size - 15 + $i, 8, false );
		}
	}

	private function reserve_version() {
		for ( $i = 0; $i < 18; $i++ ) {
			$a = $this->size - 11 + $i % 3;
			$b = intdiv( $i, 3 );
			$this->set_fn( $a, $b, false );
			$this->set_fn( $b, $a, false );
		}
	}

	/**
	 * Place data bits in the zigzag pattern, skipping function modules.
	 *
	 * @param array $bits 0/1 values (MSB-first per codeword).
	 */
	private function place_data( $bits ) {
		$n = count( $bits );
		$i = 0;
		for ( $col = $this->size - 1; $col > 0; $col -= 2 ) {
			if ( 6 === $col ) {
				$col = 5;
			}
			for ( $row = 0; $row < $this->size; $row++ ) {
				for ( $c = 0; $c < 2; $c++ ) {
					$cc = $col - $c;
					$up = ( ( ( $col + 1 ) & 2 ) === 0 );
					$rr = $up ? $this->size - 1 - $row : $row;
					if ( ! $this->isfn[ $rr ][ $cc ] ) {
						$this->modules[ $rr ][ $cc ] = ( $i < $n ) ? $bits[ $i ] : 0;
						$i++;
					}
				}
			}
		}
	}

	private function mask_condition( $m, $r, $c ) {
		switch ( $m ) {
			case 0: return 0 === ( $r + $c ) % 2;
			case 1: return 0 === $r % 2;
			case 2: return 0 === $c % 3;
			case 3: return 0 === ( $r + $c ) % 3;
			case 4: return 0 === ( intdiv( $r, 2 ) + intdiv( $c, 3 ) ) % 2;
			case 5: return 0 === ( ( $r * $c ) % 2 + ( $r * $c ) % 3 );
			case 6: return 0 === ( ( ( $r * $c ) % 2 + ( $r * $c ) % 3 ) % 2 );
			case 7: return 0 === ( ( ( $r + $c ) % 2 + ( $r * $c ) % 3 ) % 2 );
		}
		return false;
	}

	/** @return array A masked copy with format (and version) bits written. */
	private function with_mask( $m ) {
		$mat = $this->modules;
		for ( $r = 0; $r < $this->size; $r++ ) {
			for ( $c = 0; $c < $this->size; $c++ ) {
				if ( ! $this->isfn[ $r ][ $c ] && $this->mask_condition( $m, $r, $c ) ) {
					$mat[ $r ][ $c ] ^= 1;
				}
			}
		}
		$this->write_format( $mat, $m );
		if ( $this->version >= 7 ) {
			$this->write_version( $mat );
		}
		return $mat;
	}

	private function write_format( &$mat, $m ) {
		$data = ( 1 << 3 ) | $m; // ECC L = 0b01, then 3 mask bits.
		$rem  = $data;
		for ( $i = 0; $i < 10; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 9 ) * 0x537 );
		}
		$bits = ( ( $data << 10 ) | $rem ) ^ 0x5412;

		// First copy — around the top-left finder. Coordinates are (row, col).
		for ( $i = 0; $i <= 5; $i++ ) {
			$mat[ $i ][8] = $this->bit( $bits, $i );
		}
		$mat[7][8] = $this->bit( $bits, 6 );
		$mat[8][8] = $this->bit( $bits, 7 );
		$mat[8][7] = $this->bit( $bits, 8 );
		for ( $i = 9; $i <= 14; $i++ ) {
			$mat[8][ 14 - $i ] = $this->bit( $bits, $i );
		}
		// Second copy — top-right along row 8, bottom-left down col 8.
		for ( $i = 0; $i <= 7; $i++ ) {
			$mat[8][ $this->size - 1 - $i ] = $this->bit( $bits, $i );
		}
		for ( $i = 8; $i <= 14; $i++ ) {
			$mat[ $this->size - 15 + $i ][8] = $this->bit( $bits, $i );
		}
		$mat[ $this->size - 8 ][8] = 1; // dark module
	}

	private function write_version( &$mat ) {
		$rem = $this->version;
		for ( $i = 0; $i < 12; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 11 ) * 0x1F25 );
		}
		$bits = ( $this->version << 12 ) | $rem;
		for ( $i = 0; $i < 18; $i++ ) {
			$b = $this->bit( $bits, $i );
			$a = $this->size - 11 + $i % 3;
			$d = intdiv( $i, 3 );
			$mat[ $a ][ $d ] = $b;
			$mat[ $d ][ $a ] = $b;
		}
	}

	private function bit( $x, $i ) {
		return ( $x >> $i ) & 1;
	}

	// ------------------------------------------------------------------
	// Penalty scoring
	// ------------------------------------------------------------------

	private function penalty( $mat ) {
		$size  = $this->size;
		$score = 0;

		// Rule 1: runs of 5+ same-color in rows/cols.
		for ( $r = 0; $r < $size; $r++ ) {
			$run = 1;
			for ( $c = 1; $c < $size; $c++ ) {
				if ( $mat[ $r ][ $c ] === $mat[ $r ][ $c - 1 ] ) {
					$run++;
					if ( 5 === $run ) {
						$score += 3;
					} elseif ( $run > 5 ) {
						$score++;
					}
				} else {
					$run = 1;
				}
			}
		}
		for ( $c = 0; $c < $size; $c++ ) {
			$run = 1;
			for ( $r = 1; $r < $size; $r++ ) {
				if ( $mat[ $r ][ $c ] === $mat[ $r - 1 ][ $c ] ) {
					$run++;
					if ( 5 === $run ) {
						$score += 3;
					} elseif ( $run > 5 ) {
						$score++;
					}
				} else {
					$run = 1;
				}
			}
		}

		// Rule 2: 2x2 blocks of same color.
		for ( $r = 0; $r < $size - 1; $r++ ) {
			for ( $c = 0; $c < $size - 1; $c++ ) {
				$v = $mat[ $r ][ $c ];
				if ( $v === $mat[ $r ][ $c + 1 ] && $v === $mat[ $r + 1 ][ $c ] && $v === $mat[ $r + 1 ][ $c + 1 ] ) {
					$score += 3;
				}
			}
		}

		// Rule 3: finder-like patterns 1:1:3:1:1 with 4 light around.
		$patterns = array(
			array( 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0 ),
			array( 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1 ),
		);
		for ( $r = 0; $r < $size; $r++ ) {
			for ( $c = 0; $c < $size; $c++ ) {
				foreach ( $patterns as $pat ) {
					if ( $this->match_at( $mat, $r, $c, $pat, true ) ) {
						$score += 40;
					}
					if ( $this->match_at( $mat, $r, $c, $pat, false ) ) {
						$score += 40;
					}
				}
			}
		}

		// Rule 4: dark/light balance.
		$dark = 0;
		for ( $r = 0; $r < $size; $r++ ) {
			$dark += array_sum( $mat[ $r ] );
		}
		$total = $size * $size;
		$ratio = ( $dark * 100 ) / $total;
		$score += ( (int) ( abs( $ratio - 50 ) / 5 ) ) * 10;

		return $score;
	}

	private function match_at( $mat, $r, $c, $pat, $horizontal ) {
		$n = count( $pat );
		for ( $k = 0; $k < $n; $k++ ) {
			$rr = $horizontal ? $r : $r + $k;
			$cc = $horizontal ? $c + $k : $c;
			if ( $rr >= $this->size || $cc >= $this->size ) {
				return false;
			}
			if ( $mat[ $rr ][ $cc ] !== $pat[ $k ] ) {
				return false;
			}
		}
		return true;
	}

	// ------------------------------------------------------------------
	// Bit helpers
	// ------------------------------------------------------------------

	private function push_bits( &$bits, $value, $n ) {
		for ( $i = $n - 1; $i >= 0; $i-- ) {
			$bits[] = ( $value >> $i ) & 1;
		}
	}

	private function bits_to_bytes( $bits ) {
		$out = array();
		for ( $i = 0; $i < count( $bits ); $i += 8 ) {
			$b = 0;
			for ( $j = 0; $j < 8; $j++ ) {
				$b = ( $b << 1 ) | ( isset( $bits[ $i + $j ] ) ? $bits[ $i + $j ] : 0 );
			}
			$out[] = $b;
		}
		return $out;
	}

	private function bytes_to_bits( $bytes ) {
		$bits = array();
		foreach ( $bytes as $b ) {
			for ( $i = 7; $i >= 0; $i-- ) {
				$bits[] = ( $b >> $i ) & 1;
			}
		}
		// Remainder bits.
		for ( $i = 0; $i < self::$REMAINDER[ $this->version ]; $i++ ) {
			$bits[] = 0;
		}
		return $bits;
	}

	// ------------------------------------------------------------------
	// Output
	// ------------------------------------------------------------------

	/**
	 * @param int $scale
	 * @param int $quiet
	 * @return string SVG.
	 */
	public function to_svg( $scale = 5, $quiet = 4 ) {
		$dim = ( $this->size + 2 * $quiet ) * $scale;
		$svg  = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $dim . '" height="' . $dim . '" viewBox="0 0 ' . $dim . ' ' . $dim . '" role="img" aria-label="QR code" shape-rendering="crispEdges">';
		$svg .= '<rect width="' . $dim . '" height="' . $dim . '" fill="#ffffff"/>';
		$svg .= '<path fill="#000000" d="';
		for ( $r = 0; $r < $this->size; $r++ ) {
			for ( $c = 0; $c < $this->size; $c++ ) {
				if ( $this->modules[ $r ][ $c ] ) {
					$x = ( $c + $quiet ) * $scale;
					$y = ( $r + $quiet ) * $scale;
					$svg .= 'M' . $x . ' ' . $y . 'h' . $scale . 'v' . $scale . 'h-' . $scale . 'z';
				}
			}
		}
		$svg .= '"/></svg>';
		return $svg;
	}

	/**
	 * Optional raster (PNG) output via GD — a fallback when inline SVG is not
	 * desired. Returns raw PNG bytes, or '' if GD is unavailable.
	 *
	 * @param int $scale
	 * @param int $quiet
	 * @return string
	 */
	public function to_png( $scale = 6, $quiet = 4 ) {
		if ( ! function_exists( 'imagecreatetruecolor' ) ) {
			return '';
		}
		$dim = ( $this->size + 2 * $quiet ) * $scale;
		$img = imagecreatetruecolor( $dim, $dim );
		$white = imagecolorallocate( $img, 255, 255, 255 );
		$black = imagecolorallocate( $img, 0, 0, 0 );
		imagefilledrectangle( $img, 0, 0, $dim, $dim, $white );
		for ( $r = 0; $r < $this->size; $r++ ) {
			for ( $c = 0; $c < $this->size; $c++ ) {
				if ( $this->modules[ $r ][ $c ] ) {
					$x = ( $c + $quiet ) * $scale;
					$y = ( $r + $quiet ) * $scale;
					imagefilledrectangle( $img, $x, $y, $x + $scale - 1, $y + $scale - 1, $black );
				}
			}
		}
		ob_start();
		imagepng( $img );
		imagedestroy( $img );
		return ob_get_clean();
	}

	// ------------------------------------------------------------------
	// Self-test (independent verification, no scanner needed)
	// ------------------------------------------------------------------

	/**
	 * Verify the encoder three ways: RS syndromes zero, data round-trips out
	 * of the placed/masked matrix, and function patterns are intact.
	 *
	 * @param string $text
	 * @return array Diagnostics.
	 */
	public static function selftest( $text ) {
		$qr = new self();
		$qr->build( $text );

		$result = array(
			'version'    => $qr->version,
			'size'       => $qr->size,
			'mask'       => $qr->mask,
			'rs_ok'      => $qr->verify_rs(),
			'roundtrip'  => $qr->verify_roundtrip(),
			'finder_ok'  => $qr->verify_finders(),
		);
		$result['pass'] = $result['rs_ok'] && $result['roundtrip'] && $result['finder_ok'];
		return $result;
	}

	/** Each block's full codeword must have zero RS syndromes. */
	private function verify_rs() {
		$ec_per = self::$ECC_L[ $this->version ][0];
		$data   = array();
		// Re-derive blocks the same way encode_codewords did, but check syndromes.
		$bytes  = array_values( unpack( 'C*', 'verify' ) ); // unused; real check below
		// Reuse: rebuild data codewords then per-block ecc, then syndrome-check.
		// Simpler: take finalbytes, de-interleave back to blocks.
		$blocks = $this->deinterleave();
		foreach ( $blocks as $full ) {
			for ( $k = 0; $k < $ec_per; $k++ ) {
				$s = 0;
				$xk = $this->exp[ $k ];
				foreach ( $full as $coef ) {
					$s = $this->gf_mul( $s, $xk ) ^ $coef;
				}
				if ( 0 !== $s ) {
					return false;
				}
			}
		}
		return true;
	}

	/** De-interleave finalbytes back into per-block full codewords. */
	private function deinterleave() {
		$layout = self::$ECC_L[ $this->version ][1];
		$ec_per = self::$ECC_L[ $this->version ][0];
		$blocks = array();
		$sizes  = array();
		foreach ( $layout as $grp ) {
			for ( $b = 0; $b < $grp[0]; $b++ ) {
				$blocks[] = array();
				$sizes[]  = $grp[1];
			}
		}
		$nblocks  = count( $blocks );
		$max_data = max( $sizes );
		$pos      = 0;
		for ( $i = 0; $i < $max_data; $i++ ) {
			for ( $b = 0; $b < $nblocks; $b++ ) {
				if ( $i < $sizes[ $b ] ) {
					$blocks[ $b ][ $i ] = $this->finalbytes[ $pos++ ];
				}
			}
		}
		// ECC.
		$ec = array_fill( 0, $nblocks, array() );
		for ( $i = 0; $i < $ec_per; $i++ ) {
			for ( $b = 0; $b < $nblocks; $b++ ) {
				$ec[ $b ][ $i ] = $this->finalbytes[ $pos++ ];
			}
		}
		$out = array();
		for ( $b = 0; $b < $nblocks; $b++ ) {
			$out[] = array_merge( $blocks[ $b ], $ec[ $b ] );
		}
		return $out;
	}

	/** Reverse-read the masked matrix and confirm we recover finalbytes. */
	private function verify_roundtrip() {
		// Un-apply the mask on a working copy (function modules unaffected).
		$mat = $this->modules;
		for ( $r = 0; $r < $this->size; $r++ ) {
			for ( $c = 0; $c < $this->size; $c++ ) {
				if ( ! $this->isfn[ $r ][ $c ] && $this->mask_condition( $this->mask, $r, $c ) ) {
					$mat[ $r ][ $c ] ^= 1;
				}
			}
		}
		// Read bits in the same zigzag order.
		$bits = array();
		for ( $col = $this->size - 1; $col > 0; $col -= 2 ) {
			if ( 6 === $col ) {
				$col = 5;
			}
			for ( $row = 0; $row < $this->size; $row++ ) {
				for ( $c = 0; $c < 2; $c++ ) {
					$cc = $col - $c;
					$up = ( ( ( $col + 1 ) & 2 ) === 0 );
					$rr = $up ? $this->size - 1 - $row : $row;
					if ( ! $this->isfn[ $rr ][ $cc ] ) {
						$bits[] = $mat[ $rr ][ $cc ];
					}
				}
			}
		}
		$bytes = $this->bits_to_bytes( array_slice( $bits, 0, count( $this->finalbytes ) * 8 ) );
		return $bytes === $this->finalbytes;
	}

	/** Confirm the three finder cores are dark 3x3 centres. */
	private function verify_finders() {
		$centres = array( array( 3, 3 ), array( 3, $this->size - 4 ), array( $this->size - 4, 3 ) );
		foreach ( $centres as $ct ) {
			if ( 1 !== $this->modules[ $ct[0] ][ $ct[1] ] ) {
				return false;
			}
			// Light separator ring (distance 2) sampled.
			if ( 0 !== $this->modules[ $ct[0] ][ $ct[1] + 2 ] ) {
				return false;
			}
		}
		return true;
	}
}
