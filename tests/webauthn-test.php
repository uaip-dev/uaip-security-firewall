<?php
/**
 * Passkey (WebAuthn) and TOTP tests with a software authenticator. Runs without
 * WordPress (a few WP functions are stubbed). In the dev container:
 *   docker compose -f dev/docker-compose.yml exec wordpress php /uaip-tests/webauthn-test.php
 *
 * @package UaipSecurityFirewall
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
class WP_Error {
	public $code;
	public $message;
	public function __construct( $code = '', $message = '' ) {
		$this->code    = $code;
		$this->message = $message;
	}
	public function get_error_code() {
		return $this->code;
	}
}
function is_wp_error( $x ) {
	return $x instanceof WP_Error;
}
function __( $t ) {
	return $t;
}
function wp_parse_url( $url, $component = -1 ) {
	return parse_url( $url, $component );
}

$root = is_dir( '/var/www/html/wp-content/plugins/uaip-security-firewall' ) ? '/var/www/html/wp-content/plugins/uaip-security-firewall' : dirname( __DIR__ ) . '/plugin';
require $root . '/includes/lib/class-uaip-sfw-cbor.php';
require $root . '/includes/lib/class-uaip-sfw-webauthn.php';
require $root . '/includes/lib/class-uaip-sfw-totp.php';

$failures = 0;
$count    = 0;
function check( $name, $expected, $actual ) {
	global $failures, $count;
	++$count;
	if ( $expected === $actual ) {
		echo "ok   $name\n";
		return;
	}
	++$failures;
	echo "FAIL $name\n  expected: " . json_encode( $expected ) . "\n  actual:   " . json_encode( is_object( $actual ) ? (array) $actual : $actual ) . "\n";
}
function code_of( $r ) {
	return is_wp_error( $r ) ? $r->get_error_code() : 'ok';
}

// --- Tiny CBOR encoder (test side only) ---
function cbor_head( $major, $len ) {
	if ( $len < 24 ) {
		return chr( ( $major << 5 ) | $len );
	}
	if ( $len < 256 ) {
		return chr( ( $major << 5 ) | 24 ) . chr( $len );
	}
	if ( $len < 65536 ) {
		return chr( ( $major << 5 ) | 25 ) . pack( 'n', $len );
	}
	return chr( ( $major << 5 ) | 26 ) . pack( 'N', $len );
}
function cbor( $v ) {
	if ( is_int( $v ) ) {
		return $v >= 0 ? cbor_head( 0, $v ) : cbor_head( 1, -1 - $v );
	}
	if ( $v instanceof Bytes ) {
		return cbor_head( 2, strlen( $v->b ) ) . $v->b;
	}
	if ( is_string( $v ) ) {
		return cbor_head( 3, strlen( $v ) ) . $v;
	}
	if ( is_array( $v ) ) {
		$out = cbor_head( 5, count( $v ) );
		foreach ( $v as $k => $x ) {
			$out .= cbor( $k ) . cbor( $x );
		}
		return $out;
	}
	throw new Exception( 'unsupported' );
}
class Bytes {
	public $b;
	public function __construct( $b ) {
		$this->b = $b;
	}
}

// --- Software authenticator ---
$rp      = 'localhost';
$origin  = 'http://localhost:8097';
$wa      = new Uaip_Sfw_WebAuthn( $rp, array( $origin ) );
$b64     = array( 'Uaip_Sfw_WebAuthn', 'b64url_encode' );

function client_json( $type, $challenge, $origin, $extra = array() ) {
	return json_encode( array( 'type' => $type, 'challenge' => $challenge, 'origin' => $origin ) + $extra );
}
function ec_key() {
	$k = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
	$d = openssl_pkey_get_details( $k );
	return array( $k, array( 1 => 2, 3 => -7, -1 => 1, -2 => new Bytes( $d['ec']['x'] ), -3 => new Bytes( $d['ec']['y'] ) ) );
}
function rsa_key() {
	$k = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048 ) );
	$d = openssl_pkey_get_details( $k );
	return array( $k, array( 1 => 3, 3 => -257, -1 => new Bytes( $d['rsa']['n'] ), -2 => new Bytes( $d['rsa']['e'] ) ) );
}
function auth_data( $rp, $flags, $count, $cred_id = null, $cose = null ) {
	$out = hash( 'sha256', $rp, true ) . chr( $flags ) . pack( 'N', $count );
	if ( null !== $cred_id ) {
		$out .= str_repeat( "\0", 16 ) . pack( 'n', strlen( $cred_id ) ) . $cred_id . cbor( $cose );
	}
	return $out;
}
function register( $wa, $rp, $origin, $cose, $challenge, $flags = 0x45 ) {
	$id  = random_bytes( 32 );
	$att = cbor( array( 'fmt' => 'none', 'attStmt' => array(), 'authData' => new Bytes( auth_data( $rp, $flags, 0, $id, $cose ) ) ) );
	return $wa->verify_registration(
		Uaip_Sfw_WebAuthn::b64url_encode( client_json( 'webauthn.create', $challenge, $origin ) ),
		Uaip_Sfw_WebAuthn::b64url_encode( $att ),
		$challenge
	);
}
function sign_in( $wa, $rp, $origin, $key, $cred, $challenge, $count, $opts = array() ) {
	$client = client_json( 'webauthn.get', isset( $opts['challenge'] ) ? $opts['challenge'] : $challenge, isset( $opts['origin'] ) ? $opts['origin'] : $origin );
	$ad     = auth_data( isset( $opts['rp'] ) ? $opts['rp'] : $rp, isset( $opts['flags'] ) ? $opts['flags'] : 0x05, $count );
	$data   = $ad . hash( 'sha256', $client, true );
	if ( is_string( $key ) ) {
		$sig = sodium_crypto_sign_detached( $data, $key );
	} else {
		openssl_sign( $data, $sig, $key, OPENSSL_ALGO_SHA256 );
	}
	if ( ! empty( $opts['tamper'] ) ) {
		$ad[35] = chr( ord( $ad[35] ) ^ 1 );
	}
	return $wa->verify_assertion( Uaip_Sfw_WebAuthn::b64url_encode( $client ), Uaip_Sfw_WebAuthn::b64url_encode( $ad ), Uaip_Sfw_WebAuthn::b64url_encode( $sig ), $challenge, $cred );
}

echo "--- CBOR\n";
$o = 0;
check( 'decode nested map', array( 'a' => array( 1, -2, 'x' ), 3 => true ), Uaip_Sfw_CBOR::decode( "\xa2\x61a\x83\x01\x21\x61x\x03\xf5", $o ) );
check( 'offset advanced past the item', 10, $o );
$threw = false;
try {
	$o = 0;
	Uaip_Sfw_CBOR::decode( "\x5a\xff\xff\xff\xff", $o );
} catch ( InvalidArgumentException $e ) {
	$threw = true;
}
check( 'truncated byte string rejected', true, $threw );
$threw = false;
try {
	$o = 0;
	Uaip_Sfw_CBOR::decode( str_repeat( "\x81", 40 ) . "\x01", $o );
} catch ( InvalidArgumentException $e ) {
	$threw = true;
}
check( 'deep nesting rejected', true, $threw );

foreach ( array( 'ES256' => 'ec_key', 'RS256' => 'rsa_key' ) as $label => $make ) {
	echo "--- $label passkey\n";
	list( $priv, $cose ) = $make();
	$ch  = Uaip_Sfw_WebAuthn::challenge();
	$reg = register( $wa, $rp, $origin, $cose, $ch );
	check( "$label registration verifies", 'ok', code_of( $reg ) );
	$cred = array( 'public_key' => $reg['public_key'], 'alg' => $reg['alg'], 'sign_count' => 0 );
	$ch2  = Uaip_Sfw_WebAuthn::challenge();
	$res  = sign_in( $wa, $rp, $origin, $priv, $cred, $ch2, 5 );
	check( "$label sign-in verifies", 'ok', code_of( $res ) );
	check( "$label user verification flag read", true, $res['uv'] );
	$cred['sign_count'] = 5;
	check( "$label replayed counter rejected", 'uaip_sfw_webauthn_counter', code_of( sign_in( $wa, $rp, $origin, $priv, $cred, $ch2, 5 ) ) );
	check( "$label wrong challenge rejected", 'uaip_sfw_webauthn_challenge', code_of( sign_in( $wa, $rp, $origin, $priv, $cred, $ch2, 6, array( 'challenge' => 'other' ) ) ) );
	check( "$label other origin rejected", 'uaip_sfw_webauthn_origin', code_of( sign_in( $wa, $rp, $origin, $priv, $cred, $ch2, 6, array( 'origin' => 'https://evil.example' ) ) ) );
	check( "$label other RP ID rejected", 'uaip_sfw_webauthn_rp', code_of( sign_in( $wa, $rp, $origin, $priv, $cred, $ch2, 6, array( 'rp' => 'evil.example' ) ) ) );
	check( "$label no user presence rejected", 'uaip_sfw_webauthn_presence', code_of( sign_in( $wa, $rp, $origin, $priv, $cred, $ch2, 6, array( 'flags' => 0x04 ) ) ) );
	check( "$label tampered data rejected", 'uaip_sfw_webauthn_signature', code_of( sign_in( $wa, $rp, $origin, $priv, $cred, $ch2, 6, array( 'tamper' => true ) ) ) );
	list( $other ) = $make();
	check( "$label signature by another key rejected", 'uaip_sfw_webauthn_signature', code_of( sign_in( $wa, $rp, $origin, $other, $cred, $ch2, 6 ) ) );
}

echo "--- EdDSA passkey\n";
if ( function_exists( 'sodium_crypto_sign_keypair' ) ) {
	$kp   = sodium_crypto_sign_keypair();
	$cose = array( 1 => 1, 3 => -8, -1 => 6, -2 => new Bytes( sodium_crypto_sign_publickey( $kp ) ) );
	$ch   = Uaip_Sfw_WebAuthn::challenge();
	$reg  = register( $wa, $rp, $origin, $cose, $ch );
	check( 'EdDSA registration verifies', 'ok', code_of( $reg ) );
	$cred = array( 'public_key' => $reg['public_key'], 'alg' => $reg['alg'], 'sign_count' => 0 );
	check( 'EdDSA sign-in verifies', 'ok', code_of( sign_in( $wa, $rp, $origin, sodium_crypto_sign_secretkey( $kp ), $cred, Uaip_Sfw_WebAuthn::challenge() === 'x' ? 'x' : ( $c = Uaip_Sfw_WebAuthn::challenge() ), 1 ) ) );
}

echo "--- registration checks\n";
list( $priv, $cose ) = ec_key();
$ch = Uaip_Sfw_WebAuthn::challenge();
check( 'registration without the AT flag rejected', 'uaip_sfw_webauthn_no_credential', code_of( register( $wa, $rp, $origin, $cose, $ch, 0x05 ) ) );
$bad = $cose;
$bad[3] = -36;
check( 'unsupported algorithm rejected', 'uaip_sfw_webauthn_unsupported', code_of( register( $wa, $rp, $origin, $bad, $ch ) ) );
check( 'attestation that is not a map rejected', 'uaip_sfw_webauthn_incomplete', code_of( $wa->verify_registration( Uaip_Sfw_WebAuthn::b64url_encode( client_json( 'webauthn.create', $ch, $origin ) ), 'AAAA', $ch ) ) );
check( 'unreadable attestation rejected', 'uaip_sfw_webauthn_unreadable', code_of( $wa->verify_registration( Uaip_Sfw_WebAuthn::b64url_encode( client_json( 'webauthn.create', $ch, $origin ) ), Uaip_Sfw_WebAuthn::b64url_encode( "\x9f\x01" ), $ch ) ) );
check( 'get-type data used for registration rejected', 'uaip_sfw_webauthn_type', code_of( $wa->verify_registration( Uaip_Sfw_WebAuthn::b64url_encode( client_json( 'webauthn.get', $ch, $origin ) ), 'AAAA', $ch ) ) );
check( 'cross-origin iframe rejected', 'uaip_sfw_webauthn_cross_origin', code_of( $wa->verify_registration( Uaip_Sfw_WebAuthn::b64url_encode( client_json( 'webauthn.create', $ch, $origin, array( 'crossOrigin' => true ) ) ), 'AAAA', $ch ) ) );
check( 'origin_of drops the default port', 'https://example.com', Uaip_Sfw_WebAuthn::origin_of( 'https://example.com:443/wp-admin/' ) );
check( 'origin_of keeps a custom port', 'http://localhost:8097', Uaip_Sfw_WebAuthn::origin_of( 'http://localhost:8097/wp-login.php' ) );

echo "--- TOTP steps\n";
$secret = Uaip_Sfw_TOTP::generate_secret();
$now    = 1792000000;
$code   = Uaip_Sfw_TOTP::code( $secret, $now );
check( 'current code returns its step', intdiv( $now, 30 ), Uaip_Sfw_TOTP::verify_step( $secret, $code, 1, $now ) );
check( 'previous step accepted within the window', intdiv( $now, 30 ) - 1, Uaip_Sfw_TOTP::verify_step( $secret, Uaip_Sfw_TOTP::code( $secret, $now - 30 ), 1, $now ) );
check( 'code from 2 steps ago rejected', false, Uaip_Sfw_TOTP::verify_step( $secret, Uaip_Sfw_TOTP::code( $secret, $now - 60 ), 1, $now ) );
check( 'wrong code rejected', false, Uaip_Sfw_TOTP::verify_step( $secret, '000000' === $code ? '111111' : '000000', 1, $now ) );

echo "\n" . ( $count - $failures ) . "/$count passed\n";
exit( $failures ? 1 : 0 );
