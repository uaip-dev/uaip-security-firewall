<?php
/**
 * Uaip_Sfw_WebAuthn — passkey (WebAuthn Level 2) registration and assertion
 * verification in plain PHP (OpenSSL for ES256/RS256, libsodium for EdDSA).
 *
 * Attestation is not required ("none"): the site only needs to know that the
 * same authenticator signs in later, not who made it. Every ceremony checks the
 * one-time challenge, the origin, the relying-party ID hash, the user-presence
 * flag and the signature; sign-ins also check the signature counter.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_WebAuthn {

	const FLAG_UP = 0x01;
	const FLAG_UV = 0x04;
	const FLAG_AT = 0x40;

	const ALG_ES256 = -7;
	const ALG_EDDSA = -8;
	const ALG_RS256 = -257;

	/** @var string Relying-party ID (the site host). */
	private $rp_id;

	/** @var string[] Accepted origins (scheme://host[:port]). */
	private $origins;

	/**
	 * @param string   $rp_id   Relying-party ID.
	 * @param string[] $origins Accepted origins.
	 */
	public function __construct( $rp_id, array $origins ) {
		$this->rp_id   = strtolower( (string) $rp_id );
		$this->origins = array_values( array_unique( array_map( 'strtolower', $origins ) ) );
	}

	/**
	 * For this WordPress site: RP ID = site host, origins from the site, home and
	 * admin URLs.
	 *
	 * @return Uaip_Sfw_WebAuthn
	 */
	public static function for_site() {
		$origins = array();
		foreach ( array( site_url(), home_url(), admin_url(), wp_login_url() ) as $url ) {
			$origin = self::origin_of( $url );
			if ( '' !== $origin ) {
				$origins[] = $origin;
			}
		}
		return new self( (string) wp_parse_url( site_url(), PHP_URL_HOST ), $origins );
	}

	/**
	 * @param string $url URL.
	 * @return string scheme://host[:port]
	 */
	public static function origin_of( $url ) {
		$p = wp_parse_url( $url );
		if ( empty( $p['scheme'] ) || empty( $p['host'] ) ) {
			return '';
		}
		$port = isset( $p['port'] ) ? (int) $p['port'] : 0;
		$def  = 'https' === strtolower( $p['scheme'] ) ? 443 : 80;
		return strtolower( $p['scheme'] . '://' . $p['host'] ) . ( $port && $port !== $def ? ':' . $port : '' );
	}

	/** @return string */
	public function rp_id() {
		return $this->rp_id;
	}

	/** @return string 32 random bytes, base64url. */
	public static function challenge() {
		return self::b64url_encode( random_bytes( 32 ) );
	}

	/**
	 * Verify a registration (navigator.credentials.create()).
	 *
	 * @param string $client_json_b64 clientDataJSON, base64url.
	 * @param string $attestation_b64 attestationObject, base64url.
	 * @param string $challenge       Expected challenge, base64url.
	 * @return array{id:string,public_key:string,alg:int,sign_count:int,uv:bool}|WP_Error
	 */
	public function verify_registration( $client_json_b64, $attestation_b64, $challenge ) {
		$client = $this->client_data( $client_json_b64, 'webauthn.create', $challenge );
		if ( is_wp_error( $client ) ) {
			return $client;
		}
		try {
			$offset = 0;
			$att    = Uaip_Sfw_CBOR::decode( self::b64url_decode( $attestation_b64 ), $offset );
		} catch ( Exception $e ) {
			return self::error( 'unreadable' );
		}
		if ( ! is_array( $att ) || ! isset( $att['authData'] ) || ! is_string( $att['authData'] ) ) {
			return self::error( 'incomplete' );
		}
		$auth = $this->auth_data( $att['authData'], true );
		if ( is_wp_error( $auth ) ) {
			return $auth;
		}
		return array(
			'id'         => self::b64url_encode( $auth['credential_id'] ),
			'public_key' => $auth['public_key'],
			'alg'        => $auth['alg'],
			'sign_count' => $auth['sign_count'],
			'uv'         => $auth['uv'],
		);
	}

	/**
	 * Verify a sign-in assertion (navigator.credentials.get()).
	 *
	 * @param string $client_json_b64 clientDataJSON, base64url.
	 * @param string $auth_data_b64   authenticatorData, base64url.
	 * @param string $signature_b64   Signature, base64url.
	 * @param string $challenge       Expected challenge, base64url.
	 * @param array  $credential      Stored credential (public_key, alg, sign_count).
	 * @return array{sign_count:int,uv:bool}|WP_Error
	 */
	public function verify_assertion( $client_json_b64, $auth_data_b64, $signature_b64, $challenge, array $credential ) {
		$client = $this->client_data( $client_json_b64, 'webauthn.get', $challenge );
		if ( is_wp_error( $client ) ) {
			return $client;
		}
		$auth_raw = self::b64url_decode( $auth_data_b64 );
		$auth     = $this->auth_data( $auth_raw, false );
		if ( is_wp_error( $auth ) ) {
			return $auth;
		}
		$signed = $auth_raw . hash( 'sha256', $client['raw'], true );
		if ( ! self::verify_signature( (int) $credential['alg'], (string) $credential['public_key'], $signed, self::b64url_decode( $signature_b64 ) ) ) {
			return self::error( 'signature' );
		}
		$stored = (int) $credential['sign_count'];
		if ( ( $stored > 0 || $auth['sign_count'] > 0 ) && $auth['sign_count'] <= $stored ) {
			return self::error( 'counter' );
		}
		return array(
			'sign_count' => $auth['sign_count'],
			'uv'         => $auth['uv'],
		);
	}

	/**
	 * Decode and check clientDataJSON.
	 *
	 * @param string $b64       base64url JSON.
	 * @param string $type      Expected type.
	 * @param string $challenge Expected challenge.
	 * @return array|WP_Error Decoded data with 'raw'.
	 */
	private function client_data( $b64, $type, $challenge ) {
		$raw  = self::b64url_decode( $b64 );
		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) || ! isset( $data['type'], $data['challenge'], $data['origin'] ) ) {
			return self::error( 'incomplete' );
		}
		if ( $type !== $data['type'] ) {
			return self::error( 'type' );
		}
		if ( '' === (string) $challenge || ! hash_equals( (string) $challenge, (string) $data['challenge'] ) ) {
			return self::error( 'challenge' );
		}
		if ( ! in_array( strtolower( (string) $data['origin'] ), $this->origins, true ) ) {
			return self::error( 'origin' );
		}
		if ( ! empty( $data['crossOrigin'] ) ) {
			return self::error( 'cross_origin' );
		}
		$data['raw'] = $raw;
		return $data;
	}

	/**
	 * Parse authenticatorData.
	 *
	 * @param string $raw        Bytes.
	 * @param bool   $attested   Expect attested credential data (registration).
	 * @return array|WP_Error
	 */
	private function auth_data( $raw, $attested ) {
		if ( strlen( $raw ) < 37 ) {
			return self::error( 'short' );
		}
		if ( ! hash_equals( hash( 'sha256', $this->rp_id, true ), substr( $raw, 0, 32 ) ) ) {
			return self::error( 'rp' );
		}
		$flags = ord( $raw[32] );
		if ( ! ( $flags & self::FLAG_UP ) ) {
			return self::error( 'presence' );
		}
		$count = unpack( 'N', substr( $raw, 33, 4 ) )[1];
		$out   = array(
			'sign_count' => (int) $count,
			'uv'         => (bool) ( $flags & self::FLAG_UV ),
		);
		if ( ! $attested ) {
			return $out;
		}
		if ( ! ( $flags & self::FLAG_AT ) || strlen( $raw ) < 55 ) {
			return self::error( 'no_credential' );
		}
		$id_len = unpack( 'n', substr( $raw, 53, 2 ) )[1];
		if ( $id_len < 16 || $id_len > 1023 || strlen( $raw ) < 55 + $id_len ) {
			return self::error( 'credential_id' );
		}
		$out['credential_id'] = substr( $raw, 55, $id_len );
		try {
			$offset = 55 + $id_len;
			$cose   = Uaip_Sfw_CBOR::decode( $raw, $offset );
		} catch ( Exception $e ) {
			return self::error( 'public_key' );
		}
		$key = self::cose_to_key( is_array( $cose ) ? $cose : array() );
		if ( is_wp_error( $key ) ) {
			return $key;
		}
		$out['public_key'] = $key['key'];
		$out['alg']        = $key['alg'];
		return $out;
	}

	/**
	 * COSE public key -> PEM (ES256, RS256) or raw 32-byte key (EdDSA).
	 *
	 * @param array $cose COSE key map.
	 * @return array{key:string,alg:int}|WP_Error
	 */
	public static function cose_to_key( array $cose ) {
		$kty = isset( $cose[1] ) ? (int) $cose[1] : 0;
		$alg = isset( $cose[3] ) ? (int) $cose[3] : 0;
		if ( 2 === $kty && self::ALG_ES256 === $alg && isset( $cose[-1], $cose[-2], $cose[-3] ) && 1 === (int) $cose[-1]
			&& 32 === strlen( $cose[-2] ) && 32 === strlen( $cose[-3] ) ) {
			$der = hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $cose[-2] . $cose[-3];
			return array( 'key' => self::pem( $der ), 'alg' => $alg );
		}
		if ( 3 === $kty && self::ALG_RS256 === $alg && isset( $cose[-1], $cose[-2] ) && strlen( $cose[-1] ) >= 256 ) {
			$rsa = self::der( 0x30, self::der_int( $cose[-1] ) . self::der_int( $cose[-2] ) );
			$der = self::der( 0x30, self::der( 0x30, hex2bin( '06092a864886f70d0101010500' ) ) . self::der( 0x03, "\x00" . $rsa ) );
			return array( 'key' => self::pem( $der ), 'alg' => $alg );
		}
		if ( 1 === $kty && self::ALG_EDDSA === $alg && isset( $cose[-1], $cose[-2] ) && 6 === (int) $cose[-1] && 32 === strlen( $cose[-2] ) ) {
			return array( 'key' => base64_encode( $cose[-2] ), 'alg' => $alg ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- storing a binary public key.
		}
		return self::error( 'unsupported' );
	}

	/**
	 * @param int    $alg       COSE algorithm.
	 * @param string $key       PEM, or base64 Ed25519 key.
	 * @param string $data      Signed data.
	 * @param string $signature Signature.
	 * @return bool
	 */
	public static function verify_signature( $alg, $key, $data, $signature ) {
		if ( self::ALG_EDDSA === $alg ) {
			if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
				return false;
			}
			$pub = base64_decode( $key, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- stored binary public key.
			return false !== $pub && 32 === strlen( $pub ) && 64 === strlen( $signature ) && sodium_crypto_sign_verify_detached( $signature, $data, $pub );
		}
		if ( ! function_exists( 'openssl_verify' ) || ! in_array( $alg, array( self::ALG_ES256, self::ALG_RS256 ), true ) ) {
			return false;
		}
		$pub = openssl_pkey_get_public( $key );
		return false !== $pub && 1 === openssl_verify( $data, $signature, $pub, OPENSSL_ALGO_SHA256 );
	}

	/**
	 * @param string $der DER bytes.
	 * @return string PEM public key.
	 */
	private static function pem( $der ) {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- PEM encoding.
	}

	/**
	 * DER TLV.
	 *
	 * @param int    $tag   Tag byte.
	 * @param string $value Value.
	 * @return string
	 */
	private static function der( $tag, $value ) {
		$len = strlen( $value );
		if ( $len < 128 ) {
			$enc = chr( $len );
		} else {
			$bytes = ltrim( pack( 'N', $len ), "\x00" );
			$enc   = chr( 0x80 | strlen( $bytes ) ) . $bytes;
		}
		return chr( $tag ) . $enc . $value;
	}

	/**
	 * DER INTEGER from unsigned big-endian bytes.
	 *
	 * @param string $bytes Bytes.
	 * @return string
	 */
	private static function der_int( $bytes ) {
		$bytes = ltrim( $bytes, "\x00" );
		if ( '' === $bytes || ( ord( $bytes[0] ) & 0x80 ) ) {
			$bytes = "\x00" . $bytes;
		}
		return self::der( 0x02, $bytes );
	}

	/**
	 * @param string $bin Bytes.
	 * @return string
	 */
	public static function b64url_encode( $bin ) {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- base64url is the WebAuthn wire format.
	}

	/**
	 * @param string $text base64url.
	 * @return string Bytes ('' when invalid).
	 */
	public static function b64url_decode( $text ) {
		$text = strtr( (string) $text, '-_', '+/' );
		$pad  = strlen( $text ) % 4;
		if ( $pad ) {
			$text .= str_repeat( '=', 4 - $pad );
		}
		$out = base64_decode( $text, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- base64url is the WebAuthn wire format.
		return false === $out ? '' : $out;
	}

	/**
	 * Error with a translated message.
	 *
	 * @param string $code Error code.
	 * @return WP_Error
	 */
	private static function error( $code ) {
		$messages = array(
			'unreadable' => __( 'The passkey response could not be read.', 'uaip-security-firewall' ),
			'incomplete' => __( 'The passkey response is incomplete.', 'uaip-security-firewall' ),
			'signature' => __( 'The passkey signature is not valid.', 'uaip-security-firewall' ),
			'counter' => __( 'This passkey may have been copied (its counter went backwards).', 'uaip-security-firewall' ),
			'type' => __( 'Unexpected passkey response type.', 'uaip-security-firewall' ),
			'challenge' => __( 'The passkey request expired. Please try again.', 'uaip-security-firewall' ),
			'origin' => __( 'The passkey was used on a different website address.', 'uaip-security-firewall' ),
			'cross_origin' => __( 'Passkeys cannot be used from an embedded frame here.', 'uaip-security-firewall' ),
			'short' => __( 'The passkey response is too short.', 'uaip-security-firewall' ),
			'rp' => __( 'The passkey belongs to a different website.', 'uaip-security-firewall' ),
			'presence' => __( 'The authenticator did not confirm user presence.', 'uaip-security-firewall' ),
			'no_credential' => __( 'The passkey response has no credential.', 'uaip-security-firewall' ),
			'credential_id' => __( 'The passkey credential ID is not valid.', 'uaip-security-firewall' ),
			'public_key' => __( 'The passkey public key could not be read.', 'uaip-security-firewall' ),
			'unsupported' => __( 'This kind of passkey is not supported. Try a different device or browser.', 'uaip-security-firewall' ),
		);
		return new WP_Error( 'uaip_sfw_webauthn_' . $code, isset( $messages[ $code ] ) ? $messages[ $code ] : $messages['incomplete'] );
	}
}
