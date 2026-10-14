<?php
/**
 * Verify a signed rule bundle from UAIP Security Cloud.
 *
 * The cloud sends {version, payload, sig}: payload is a JSON string and sig an
 * Ed25519 signature over it. Nothing in the payload is used before the
 * signature verifies against UAIP_SFW_RULES_PUBKEY. Older versions are refused
 * (no rollback to a weaker signed bundle) and every rule pattern must compile.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Rules_Feed {

	/** Bundles older than this are refused (replayed old responses). */
	const MAX_AGE = 30 * DAY_IN_SECONDS;

	/**
	 * @param array  $bundle  {version, payload, sig} from the cloud.
	 * @param int    $current Version installed now.
	 * @param string $channel Expected channel.
	 * @param string $pubkey  Base64 public key (defaults to the built-in one).
	 * @return array{version:int,rules:array}|WP_Error
	 */
	public static function verify( array $bundle, $current, $channel = 'waf', $pubkey = UAIP_SFW_RULES_PUBKEY ) {
		$payload = isset( $bundle['payload'] ) && is_string( $bundle['payload'] ) ? $bundle['payload'] : '';
		$sig     = isset( $bundle['sig'] ) && is_string( $bundle['sig'] ) ? base64_decode( $bundle['sig'], true ) : false; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- signature bytes.
		$key     = base64_decode( (string) $pubkey, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- public key bytes.
		if ( '' === $payload || false === $sig || 64 !== strlen( $sig ) || false === $key || 32 !== strlen( $key ) ) {
			return new WP_Error( 'uaip_sfw_feed_unsigned', 'The rule bundle is not signed.' );
		}
		try {
			$ok = sodium_crypto_sign_verify_detached( $sig, $payload, $key );
		} catch ( Exception $e ) {
			$ok = false;
		}
		if ( ! $ok ) {
			return new WP_Error( 'uaip_sfw_feed_bad_signature', 'The rule bundle signature does not verify.' );
		}

		$data = json_decode( $payload, true );
		if ( ! is_array( $data ) || ( $data['channel'] ?? '' ) !== $channel || ! isset( $data['version'], $data['issued'], $data['rules'] ) || ! is_array( $data['rules'] ) ) {
			return new WP_Error( 'uaip_sfw_feed_malformed', 'The rule bundle is malformed.' );
		}
		$version = (int) $data['version'];
		if ( $version < (int) $current ) {
			return new WP_Error( 'uaip_sfw_feed_rollback', 'The rule bundle is older than the installed rules.' );
		}
		if ( (int) $data['issued'] < time() - self::MAX_AGE ) {
			return new WP_Error( 'uaip_sfw_feed_stale', 'The rule bundle is too old.' );
		}

		$rules = array();
		foreach ( $data['rules'] as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['id'] ) || ! isset( $rule['pattern'] ) || ! is_string( $rule['pattern'] ) ) {
				continue;
			}
			$flags = isset( $rule['flags'] ) ? preg_replace( '/[^imsxu]/', '', (string) $rule['flags'] ) : '';
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- testing that a feed pattern compiles.
			if ( false === @preg_match( '~' . str_replace( '~', '\~', $rule['pattern'] ) . '~' . $flags, '' ) ) {
				continue; // never let a broken pattern reach the firewall
			}
			$rule['flags'] = $flags;
			$rules[]       = $rule;
		}
		return array(
			'version' => $version,
			'rules'   => $rules,
		);
	}
}
