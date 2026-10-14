<?php
/**
 * Uaip_Sfw_CBOR — minimal CBOR (RFC 8949) decoder for WebAuthn.
 *
 * Supports what authenticators send: unsigned/negative integers, byte and text
 * strings, arrays, maps, tags (value kept), booleans, null and floats. Byte
 * strings are returned as raw PHP strings. Indefinite lengths are rejected.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_CBOR {

	/** Deepest nesting accepted (defence against hostile input). */
	const MAX_DEPTH = 16;

	/**
	 * Decode one item starting at $offset.
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset In: start; out: first byte after the item.
	 * @return mixed
	 * @throws InvalidArgumentException On malformed input.
	 */
	public static function decode( $data, &$offset = 0 ) {
		return self::item( (string) $data, $offset, 0 );
	}

	/**
	 * @param string $data   Bytes.
	 * @param int    $offset Offset (by reference).
	 * @param int    $depth  Nesting depth.
	 * @return mixed
	 * @throws InvalidArgumentException On malformed input.
	 */
	private static function item( $data, &$offset, $depth ) {
		if ( $depth > self::MAX_DEPTH ) {
			throw new InvalidArgumentException( 'CBOR nesting too deep' );
		}
		$first = ord( self::take( $data, $offset, 1 ) );
		$major = $first >> 5;
		$info  = $first & 0x1f;

		if ( 7 === $major ) {
			switch ( $info ) {
				case 20:
					return false;
				case 21:
					return true;
				case 22:
				case 23:
					return null;
				case 25:
					return self::half( self::take( $data, $offset, 2 ) );
				case 26:
					$v = unpack( 'G', self::take( $data, $offset, 4 ) );
					return $v[1];
				case 27:
					$v = unpack( 'E', self::take( $data, $offset, 8 ) );
					return $v[1];
				default:
					if ( $info < 20 ) {
						return $info; // Unassigned simple value.
					}
					throw new InvalidArgumentException( 'Unsupported CBOR simple value' );
			}
		}

		$len = self::length( $data, $offset, $info );
		switch ( $major ) {
			case 0:
				return $len;
			case 1:
				return -1 - $len;
			case 2:
				return self::take( $data, $offset, $len );
			case 3:
				return self::take( $data, $offset, $len );
			case 4:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$out[] = self::item( $data, $offset, $depth + 1 );
				}
				return $out;
			case 5:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$key = self::item( $data, $offset, $depth + 1 );
					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						throw new InvalidArgumentException( 'Unsupported CBOR map key' );
					}
					$out[ $key ] = self::item( $data, $offset, $depth + 1 );
				}
				return $out;
			case 6:
				return self::item( $data, $offset, $depth + 1 ); // Tag: keep the value.
		}
		throw new InvalidArgumentException( 'Unknown CBOR major type' );
	}

	/**
	 * Argument length for the initial byte's additional info.
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset Offset.
	 * @param int    $info   Additional info.
	 * @return int
	 * @throws InvalidArgumentException On indefinite or oversized lengths.
	 */
	private static function length( $data, &$offset, $info ) {
		if ( $info < 24 ) {
			return $info;
		}
		switch ( $info ) {
			case 24:
				return ord( self::take( $data, $offset, 1 ) );
			case 25:
				$v = unpack( 'n', self::take( $data, $offset, 2 ) );
				return $v[1];
			case 26:
				$v = unpack( 'N', self::take( $data, $offset, 4 ) );
				return $v[1];
			case 27:
				$v = unpack( 'J', self::take( $data, $offset, 8 ) );
				if ( $v[1] < 0 ) {
					throw new InvalidArgumentException( 'CBOR length too large' );
				}
				return $v[1];
		}
		throw new InvalidArgumentException( 'Indefinite or reserved CBOR length' );
	}

	/**
	 * Read $len bytes.
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset Offset.
	 * @param int    $len    Length.
	 * @return string
	 * @throws InvalidArgumentException When the input is too short.
	 */
	private static function take( $data, &$offset, $len ) {
		if ( $len < 0 || $offset + $len > strlen( $data ) ) {
			throw new InvalidArgumentException( 'Truncated CBOR' );
		}
		$out     = (string) substr( $data, $offset, $len );
		$offset += $len;
		return $out;
	}

	/**
	 * IEEE 754 half-precision float.
	 *
	 * @param string $bytes 2 bytes.
	 * @return float
	 */
	private static function half( $bytes ) {
		$h    = unpack( 'n', $bytes )[1];
		$exp  = ( $h >> 10 ) & 0x1f;
		$mant = $h & 0x3ff;
		$sign = ( $h & 0x8000 ) ? -1 : 1;
		if ( 0 === $exp ) {
			return $sign * $mant * pow( 2, -24 );
		}
		if ( 31 === $exp ) {
			return $mant ? NAN : $sign * INF;
		}
		return $sign * ( 1 + $mant / 1024 ) * pow( 2, $exp - 15 );
	}
}
