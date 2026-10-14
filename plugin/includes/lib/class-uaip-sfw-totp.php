<?php
/**
 * RFC 6238 TOTP + RFC 4648 Base32. Self-contained, no external dependency.
 *
 * Compatible with Google Authenticator, Authy, 1Password, Microsoft
 * Authenticator (SHA1, 6 digits, 30s period).
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_TOTP {

	const PERIOD = 30;
	const DIGITS = 6;
	const ALGO   = 'sha1';

	/**
	 * Generate a new Base32 secret.
	 *
	 * @param int $bytes Entropy bytes (20 = 160-bit, the standard).
	 * @return string
	 */
	public static function generate_secret( $bytes = 20 ) {
		return self::base32_encode( random_bytes( $bytes ) );
	}

	/**
	 * Compute the TOTP code for a given moment.
	 *
	 * @param string   $secret    Base32 secret.
	 * @param int|null $timestamp Defaults to now.
	 * @param int      $offset    Counter offset (for window tolerance).
	 * @return string Zero-padded code.
	 */
	public static function code( $secret, $timestamp = null, $offset = 0 ) {
		$timestamp = ( null === $timestamp ) ? time() : $timestamp;
		$counter   = intdiv( $timestamp, self::PERIOD ) + $offset;
		$key       = self::base32_decode( $secret );

		// 64-bit big-endian counter.
		$bin  = pack( 'N', 0 ) . pack( 'N', $counter );
		$hash = hash_hmac( self::ALGO, $bin, $key, true );

		$off  = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
		$part = ( ( ord( $hash[ $off ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $off + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $off + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $off + 3 ] ) & 0xff );

		$code = $part % ( 10 ** self::DIGITS );
		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a user-entered code within a +/- window (clock drift tolerance).
	 *
	 * @param string $secret Base32 secret.
	 * @param string $input  User input.
	 * @param int    $window Allowed steps each side (1 = +/-30s).
	 * @return bool
	 */
	public static function verify( $secret, $input, $window = 1 ) {
		$input = preg_replace( '/\D/', '', (string) $input );
		if ( strlen( $input ) !== self::DIGITS ) {
			return false;
		}
		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( hash_equals( self::code( $secret, null, $i ), $input ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Verify a code and return the matched time step, so callers can refuse a
	 * code that was already used (replay protection).
	 *
	 * @param string $secret Base32 secret.
	 * @param string $input  User input.
	 * @param int    $window Allowed steps each side.
	 * @param int    $now    Timestamp (tests).
	 * @return int|false Matched step counter, or false.
	 */
	public static function verify_step( $secret, $input, $window = 1, $now = null ) {
		$input = preg_replace( '/\D/', '', (string) $input );
		if ( strlen( $input ) !== self::DIGITS || '' === (string) $secret ) {
			return false;
		}
		$now  = null === $now ? time() : (int) $now;
		$base = intdiv( $now, self::PERIOD );
		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( hash_equals( self::code( $secret, $now, $i ), $input ) ) {
				return $base + $i;
			}
		}
		return false;
	}

	/**
	 * Build the otpauth:// provisioning URI for QR/manual entry.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $label  Usually the account/email.
	 * @param string $issuer Usually the site name.
	 * @return string
	 */
	public static function provisioning_uri( $secret, $label, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $label )
			. '?secret=' . rawurlencode( $secret )
			. '&issuer=' . rawurlencode( $issuer )
			. '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
	}

	/**
	 * Format a secret in readable 4-char groups for manual entry.
	 *
	 * @param string $secret
	 * @return string
	 */
	public static function format_secret( $secret ) {
		return trim( chunk_split( $secret, 4, ' ' ) );
	}

	// ------------------------------------------------------------------
	// Base32 (RFC 4648, no padding on output)
	// ------------------------------------------------------------------

	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * @param string $data Raw bytes.
	 * @return string Base32.
	 */
	public static function base32_encode( $data ) {
		if ( '' === $data ) {
			return '';
		}
		$bits = '';
		foreach ( str_split( $data ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$out  .= self::ALPHABET[ bindec( $chunk ) ];
		}
		return $out;
	}

	/**
	 * @param string $b32 Base32 (case-insensitive, spaces ignored).
	 * @return string Raw bytes.
	 */
	public static function base32_decode( $b32 ) {
		$b32 = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $b32 ) );
		if ( '' === $b32 ) {
			return '';
		}
		$bits = '';
		$len  = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$pos = strpos( self::ALPHABET, $b32[ $i ] );
			if ( false === $pos ) {
				continue;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( strlen( $byte ) === 8 ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}
}
