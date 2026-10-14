<?php
/**
 * Signed rule feed tests (Ed25519). Runs without WordPress. A throwaway key
 * pair signs test bundles; the real public key is never needed here.
 *
 * @package UaipSecurityFirewall
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'DAY_IN_SECONDS', 86400 );
define( 'UAIP_SFW_RULES_PUBKEY', '' );
class WP_Error {
	public $code;
	public function __construct( $code = '', $message = '' ) {
		$this->code = $code;
	}
	public function get_error_code() {
		return $this->code;
	}
}
function is_wp_error( $x ) {
	return $x instanceof WP_Error;
}

$root = is_dir( '/var/www/html/wp-content/plugins/uaip-security-firewall' ) ? '/var/www/html/wp-content/plugins/uaip-security-firewall' : dirname( __DIR__ ) . '/plugin';
require $root . '/includes/lib/class-uaip-sfw-rules-feed.php';

$failures = 0;
$count    = 0;
function check( $name, $expected, $actual ) {
	global $failures, $count;
	++$count;
	if ( $expected === $actual ) {
		echo "ok   $name\n";
	} else {
		++$failures;
		echo "FAIL $name: expected " . var_export( $expected, true ) . ', got ' . var_export( $actual, true ) . "\n";
	}
}
function code_of( $r ) {
	return is_wp_error( $r ) ? $r->get_error_code() : 'ok';
}

$kp    = sodium_crypto_sign_keypair();
$sk    = sodium_crypto_sign_secretkey( $kp );
$pk    = base64_encode( sodium_crypto_sign_publickey( $kp ) );
$other = base64_encode( sodium_crypto_sign_publickey( sodium_crypto_sign_keypair() ) );

function bundle( $data, $sk ) {
	$payload = json_encode( $data, JSON_UNESCAPED_SLASHES );
	return array(
		'version' => $data['version'] ?? 0,
		'payload' => $payload,
		'sig'     => base64_encode( sodium_crypto_sign_detached( $payload, $sk ) ),
	);
}
$rule  = array( 'id' => 'fd-1', 'class' => 'sqli', 'score' => 5, 'targets' => array( 'query' ), 'pattern' => 'union\s+select', 'flags' => 'i' );
$good  = array( 'channel' => 'waf', 'tier' => 'free', 'version' => 5, 'issued' => time(), 'rules' => array( $rule ) );
$valid = bundle( $good, $sk );

$r = Uaip_Sfw_Rules_Feed::verify( $valid, 4, 'waf', $pk );
check( 'valid bundle accepted', 'ok', code_of( $r ) );
check( 'valid bundle keeps the rule', 'fd-1', is_array( $r ) ? $r['rules'][0]['id'] : null );
check( 'same version re-install allowed', 'ok', code_of( Uaip_Sfw_Rules_Feed::verify( $valid, 5, 'waf', $pk ) ) );

check( 'wrong key refused', 'uaip_sfw_feed_bad_signature', code_of( Uaip_Sfw_Rules_Feed::verify( $valid, 4, 'waf', $other ) ) );

$tampered            = $valid;
$tampered['payload'] = str_replace( 'union', 'onion', $tampered['payload'] );
check( 'tampered payload refused', 'uaip_sfw_feed_bad_signature', code_of( Uaip_Sfw_Rules_Feed::verify( $tampered, 4, 'waf', $pk ) ) );

$swapped            = $valid;
$swapped['version'] = 99; // outer field is not trusted
$r                  = Uaip_Sfw_Rules_Feed::verify( $swapped, 4, 'waf', $pk );
check( 'outer version ignored, signed one used', 5, is_array( $r ) ? $r['version'] : null );

$unsigned = array( 'version' => 6, 'rules' => array( $rule ) );
check( 'old unsigned format refused', 'uaip_sfw_feed_unsigned', code_of( Uaip_Sfw_Rules_Feed::verify( $unsigned, 4, 'waf', $pk ) ) );
check( 'missing signature refused', 'uaip_sfw_feed_unsigned', code_of( Uaip_Sfw_Rules_Feed::verify( array( 'payload' => $valid['payload'] ), 4, 'waf', $pk ) ) );
check( 'garbage signature refused', 'uaip_sfw_feed_unsigned', code_of( Uaip_Sfw_Rules_Feed::verify( array( 'payload' => $valid['payload'], 'sig' => 'abc' ), 4, 'waf', $pk ) ) );

check( 'rollback to an older version refused', 'uaip_sfw_feed_rollback', code_of( Uaip_Sfw_Rules_Feed::verify( $valid, 6, 'waf', $pk ) ) );
check( 'wrong channel refused', 'uaip_sfw_feed_malformed', code_of( Uaip_Sfw_Rules_Feed::verify( $valid, 4, 'yara', $pk ) ) );

$old = $good;
$old['issued'] = time() - 40 * DAY_IN_SECONDS;
check( 'bundle older than 30 days refused', 'uaip_sfw_feed_stale', code_of( Uaip_Sfw_Rules_Feed::verify( bundle( $old, $sk ), 4, 'waf', $pk ) ) );

$mixed          = $good;
$mixed['rules'] = array( $rule, array( 'id' => 'bad', 'pattern' => '(unclosed' ), array( 'pattern' => 'no-id' ), 'not-a-rule' );
$r              = Uaip_Sfw_Rules_Feed::verify( bundle( $mixed, $sk ), 4, 'waf', $pk );
check( 'broken patterns dropped, good kept', array( 'fd-1' ), is_array( $r ) ? array_column( $r['rules'], 'id' ) : null );

$flags                       = $good;
$flags['rules'][0]['flags']  = 'ie';
$r                           = Uaip_Sfw_Rules_Feed::verify( bundle( $flags, $sk ), 4, 'waf', $pk );
check( 'unknown regex flags stripped (no /e)', 'i', is_array( $r ) ? $r['rules'][0]['flags'] : null );

check( 'built-in key used by default (empty here, so refused)', 'uaip_sfw_feed_unsigned', code_of( Uaip_Sfw_Rules_Feed::verify( $valid, 4 ) ) );

echo "\n" . ( $count - $failures ) . "/$count passed\n";
exit( $failures ? 1 : 0 );
