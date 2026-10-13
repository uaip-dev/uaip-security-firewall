<?php
/**
 * Uaip_Sfw_Crypto — authenticated encryption for secrets at rest (TOTP secrets, the
 * site API secret). AES-256-GCM with a key derived from a wp-config constant
 * (UAIP_SFW_ENCRYPTION_KEY) or the WordPress salts.
 *
 * Ciphertext format: "v1:" . base64( iv(12) . tag(16) . ciphertext ).
 * decrypt() returns legacy plaintext unchanged, so existing values keep working
 * and are upgraded the next time they are written.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Crypto {

	const PREFIX = 'v1:';
	const CIPHER = 'aes-256-gcm';

	/** @return string 32-byte key. */
	private static function key() {
		if ( defined( 'UAIP_SFW_ENCRYPTION_KEY' ) && UAIP_SFW_ENCRYPTION_KEY ) {
			$material = UAIP_SFW_ENCRYPTION_KEY;
		} elseif ( function_exists( 'wp_salt' ) ) {
			$material = wp_salt( 'secure_auth' );
		} else {
			$material = defined( 'AUTH_KEY' ) ? AUTH_KEY : 'uaip-sfw-insecure-fallback';
		}
		return hash( 'sha256', 'uaip-sfw|' . $material, true );
	}

	/** @return bool Whether encryption is available on this host. */
	public static function available() {
		return function_exists( 'openssl_encrypt' ) && in_array( self::CIPHER, openssl_get_cipher_methods(), true );
	}

	/**
	 * @param string $plaintext
	 * @return string Ciphertext (or the plaintext unchanged if OpenSSL is absent).
	 */
	public static function encrypt( $plaintext ) {
		if ( '' === (string) $plaintext || ! self::available() ) {
			return (string) $plaintext;
		}
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( $plaintext, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv, $tag );
		if ( false === $ct ) {
			return (string) $plaintext;
		}
		return self::PREFIX . base64_encode( $iv . $tag . $ct );
	}

	/**
	 * @param string $payload
	 * @return string Plaintext ('' on failure). Legacy (unprefixed) values pass through.
	 */
	public static function decrypt( $payload ) {
		$payload = (string) $payload;
		if ( 0 !== strpos( $payload, self::PREFIX ) ) {
			return $payload; // legacy plaintext / empty
		}
		$raw = base64_decode( substr( $payload, strlen( self::PREFIX ) ), true );
		if ( false === $raw || strlen( $raw ) < 29 ) {
			return '';
		}
		$iv  = substr( $raw, 0, 12 );
		$tag = substr( $raw, 12, 16 );
		$ct  = substr( $raw, 28 );
		$pt  = openssl_decrypt( $ct, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv, $tag );
		return false === $pt ? '' : $pt;
	}
}
