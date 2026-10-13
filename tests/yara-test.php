<?php
/**
 * YARA ruleset tests: backdoor shapes must match, ordinary plugin code must not.
 * Runs without WordPress. In the dev container:
 *   docker compose -f dev/docker-compose.yml exec wordpress php /uaip-tests/yara-test.php
 *
 * @package UaipSecurityFirewall
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.Security.EscapeOutput

define( 'ABSPATH', __DIR__ . '/' );

$uaip_sfw_root = is_dir( '/var/www/html/wp-content/plugins/uaip-security-firewall' )
	? '/var/www/html/wp-content/plugins/uaip-security-firewall'
	: dirname( __DIR__ ) . '/plugin';
require $uaip_sfw_root . '/includes/lib/class-uaip-sfw-yara-lite.php';

$yara = new Uaip_Sfw_Yara_Lite();
$yara->load_dir( $uaip_sfw_root . '/assets/yara-rules' );

$failures = 0;
$count    = 0;

/**
 * @param string $name     Name.
 * @param mixed  $expected Expected.
 * @param mixed  $actual   Actual.
 */
function check( $name, $expected, $actual ) {
	global $failures, $count;
	++$count;
	if ( $expected === $actual ) {
		echo "ok   $name\n";
		return;
	}
	++$failures;
	echo "FAIL $name\n  expected: " . json_encode( $expected ) . "\n  actual:   " . json_encode( $actual ) . "\n";
}

/**
 * @param string $code PHP source.
 * @return string[] Matched rule names.
 */
function rules_for( $code ) {
	global $yara;
	return array_column( $yara->scan_data( $code ), 'rule' );
}

check( 'all rules parsed', 13, $yara->rule_count() );
check( 'no parse warnings', array(), $yara->warnings() );

echo "--- backdoors (must match)\n";
$bad = array(
	'eval(base64_decode(...))'          => array( '<?php eval(base64_decode("ZWNobyAxOw=="));', 'sfw_eval_decoded' ),
	'@eval(gzinflate(...))'             => array( '<?php @eval( @gzinflate( base64_decode( $x ) ) );', 'sfw_eval_decoded' ),
	'assert(str_rot13(...))'            => array( '<?php assert(str_rot13("riny(\$_CBFG[1])"));', 'sfw_eval_decoded' ),
	'eval($_POST)'                      => array( '<?php eval($_POST["c"]);', 'sfw_eval_request' ),
	'eval(stripslashes($_REQUEST))'     => array( '<?php eval( stripslashes( $_REQUEST["x"] ) );', 'sfw_eval_request' ),
	'system($_GET)'                     => array( '<?php system($_GET["cmd"]);', 'sfw_exec_from_request' ),
	'shell_exec(@$_COOKIE)'             => array( '<?php echo shell_exec( @$_COOKIE["c"] );', 'sfw_exec_from_request' ),
	'$_GET[f]($_GET[x])'                => array( '<?php $_GET["f"]($_GET["x"]);', 'sfw_variable_function_request' ),
	'assert($_REQUEST)'                 => array( '<?php assert($_REQUEST["a"]);', 'sfw_assert_request' ),
	'include $_GET'                     => array( '<?php include $_GET["page"];', 'sfw_include_request' ),
	'require_once($_POST)'              => array( '<?php require_once( $_POST["f"] );', 'sfw_include_request' ),
	'preg_replace /e'                   => array( '<?php preg_replace("/.*/e", $_POST["c"], "");', 'sfw_preg_replace_eval' ),
	'create_function from request'      => array( '<?php $f = create_function("", $_POST["code"]); $f();', 'sfw_create_function_request' ),
	'call_user_func($_GET)'             => array( '<?php call_user_func($_GET["f"], $_GET["a"]);', 'sfw_callback_request' ),
	'encoded blob + eval'               => array( '<?php $p = "' . str_repeat( 'QUJDREVGR0g', 400 ) . '"; eval($d($p));', 'sfw_encoded_blob_eval' ),
	'$GLOBALS obfuscator'               => array( '<?php $GLOBALS["a1b"][3].$GLOBALS["a1b"][7];', 'sfw_globals_obfuscation' ),
	'hex escaped code'                  => array( '<?php $x = "' . str_repeat( '\\x65\\x76\\x61\\x6c', 12 ) . '";', 'sfw_hex_escaped_code' ),
	'FilesMan marker'                   => array( '<?php $default_action = "FilesMan";', 'sfw_known_shell_markers' ),
	'b374k marker'                      => array( '<?php // b374k shell', 'sfw_known_shell_markers' ),
);
foreach ( $bad as $name => $case ) {
	check( $name, true, in_array( $case[1], rules_for( $case[0] ), true ) );
}

echo "--- ordinary plugin code (must not match)\n";
$good = array(
	'base64_decode and eval far apart' => "<?php\n\$img = base64_decode( \$data );\n// Some docs mention eval() as a bad idea.\nfunction x() { return 1; }",
	'call_user_func with a callback'   => '<?php call_user_func( $callback, $args ); call_user_func_array( array( $this, "render" ), $params );',
	'include a template variable'      => '<?php include $template; require_once __DIR__ . "/inc/a.php";',
	'sanitised request read'           => '<?php $page = isset( $_GET["page"] ) ? sanitize_key( $_GET["page"] ) : ""; echo esc_html( $_POST["name"] );',
	'regex with the i flag'            => '<?php preg_replace( "/foo/i", "bar", $s ); preg_replace( "/x/", $r, $s );',
	'exec of a fixed command'          => '<?php exec( "convert " . escapeshellarg( $file ), $out );',
	'base64 image data URI'            => '<?php $logo = "data:image/png;base64,' . str_repeat( 'iVBORw0KGgo', 500 ) . '";',
	'json_decode of POST'              => '<?php $data = json_decode( wp_unslash( $_POST["payload"] ), true );',
	'short hex string'                 => '<?php $sep = "\\x2d\\x2d";',
	'WP-CLI eval command name'         => '<?php WP_CLI::add_command( "eval", "Eval_Command" );',
);
foreach ( $good as $name => $code ) {
	check( $name, array(), rules_for( $code ) );
}

echo "--- matcher behaviour\n";
$strict = new Uaip_Sfw_Yara_Lite();
$strict->load_string( 'rule odd { strings: $a = "x" condition: $a and #a > 2 }' );
check( 'unsupported condition syntax fails closed', array(), array_column( $strict->scan_data( 'xxxx' ), 'rule' ) );
$ok = new Uaip_Sfw_Yara_Lite();
$ok->load_string( 'rule both { strings: $a = "foo" $b = "bar" nocase condition: $a and not $b }' );
check( 'and/not condition true', array( 'both' ), array_column( $ok->scan_data( 'foo' ), 'rule' ) );
check( 'and/not condition false', array(), array_column( $ok->scan_data( 'foo BAR' ), 'rule' ) );

echo "\n" . ( $count - $failures ) . "/$count passed\n";
exit( $failures ? 1 : 0 );
