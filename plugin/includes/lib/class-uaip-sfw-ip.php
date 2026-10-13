<?php
/**
 * Uaip_Sfw_IP — client IP resolution behind proxies/CDNs, and IP/CIDR lists.
 *
 * Uses no WordPress functions so the firewall can also run before WordPress
 * loads. IPv4 and IPv6 are both supported.
 *
 * @package UaipSecurityFirewall
 */

// Block direct web access (also loadable from a standalone early-firewall bootstrap).
if ( ! defined( 'ABSPATH' ) ) {
	if ( ! defined( 'UAIP_SFW_WAF_PREPEND' ) ) {
		exit;
	}
}

class Uaip_Sfw_IP {

	/** Where the visitor's IP comes from. */
	const SOURCES = array( 'remote_addr', 'cloudflare', 'x_forwarded_for', 'x_real_ip' );

	/**
	 * Cloudflare's published edge ranges (https://www.cloudflare.com/ips/). The
	 * CF-Connecting-IP header is only trusted when the connection comes from one
	 * of these, so it cannot be spoofed by connecting to the server directly.
	 */
	const CLOUDFLARE = array(
		'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
		'108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
		'162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
		'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
		'2a06:98c0::/29', '2c0f:f248::/32',
	);

	/**
	 * The visitor's IP address.
	 *
	 * @param array  $server  $_SERVER (or a test double).
	 * @param string $source  One of self::SOURCES.
	 * @param array  $trusted Trusted proxy IPs/CIDRs (for x_forwarded_for / x_real_ip).
	 * @return string Valid IP, or '' when unknown.
	 */
	public static function client( array $server, $source = 'remote_addr', array $trusted = array() ) {
		$remote = self::valid( isset( $server['REMOTE_ADDR'] ) ? $server['REMOTE_ADDR'] : '' );
		if ( '' === $remote ) {
			return '';
		}
		switch ( $source ) {
			case 'cloudflare':
				if ( self::in_list( $remote, self::CLOUDFLARE ) ) {
					$cf = self::valid( isset( $server['HTTP_CF_CONNECTING_IP'] ) ? $server['HTTP_CF_CONNECTING_IP'] : '' );
					if ( '' !== $cf ) {
						return $cf;
					}
				}
				return $remote;

			case 'x_real_ip':
				if ( self::in_list( $remote, $trusted ) ) {
					$real = self::valid( isset( $server['HTTP_X_REAL_IP'] ) ? $server['HTTP_X_REAL_IP'] : '' );
					if ( '' !== $real ) {
						return $real;
					}
				}
				return $remote;

			case 'x_forwarded_for':
				if ( ! self::in_list( $remote, $trusted ) || empty( $server['HTTP_X_FORWARDED_FOR'] ) ) {
					return $remote;
				}
				// Walk right to left: the right-most address that is not one of our
				// own proxies is the client. Anything further left is client-supplied.
				$hops = array_reverse( array_map( 'trim', explode( ',', (string) $server['HTTP_X_FORWARDED_FOR'] ) ) );
				foreach ( $hops as $hop ) {
					$hop = self::valid( $hop );
					if ( '' === $hop ) {
						break;
					}
					if ( ! self::in_list( $hop, $trusted ) ) {
						return $hop;
					}
				}
				return $remote;

			default:
				return $remote;
		}
	}

	/**
	 * Normalised IP or ''. Strips an IPv4 port and IPv6 brackets ("[::1]:443").
	 *
	 * @param mixed $ip Candidate.
	 * @return string
	 */
	public static function valid( $ip ) {
		$ip = trim( (string) $ip );
		if ( preg_match( '/^\[([0-9a-f:.]+)\](?::\d+)?$/i', $ip, $m ) ) {
			$ip = $m[1];
		} elseif ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $ip, $m ) ) {
			$ip = $m[1];
		}
		return false !== filter_var( $ip, FILTER_VALIDATE_IP ) ? strtolower( $ip ) : '';
	}

	/**
	 * Whether an IP matches any entry (single IPs or CIDR ranges).
	 *
	 * @param string $ip   IP.
	 * @param array  $list Entries.
	 * @return bool
	 */
	public static function in_list( $ip, array $list ) {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input just means "no match".
		if ( false === $bin ) {
			return false;
		}
		foreach ( $list as $entry ) {
			if ( self::matches( $bin, (string) $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $bin   Packed IP.
	 * @param string $entry "ip" or "ip/prefix".
	 * @return bool
	 */
	private static function matches( $bin, $entry ) {
		$parts = explode( '/', trim( $entry ), 2 );
		$net   = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid entries never match.
		if ( false === $net || strlen( $net ) !== strlen( $bin ) ) {
			return false;
		}
		$bits = strlen( $bin ) * 8;
		$len  = isset( $parts[1] ) && ctype_digit( $parts[1] ) ? (int) $parts[1] : $bits;
		if ( $len < 0 || $len > $bits ) {
			return false;
		}
		$bytes = intdiv( $len, 8 );
		if ( substr( $bin, 0, $bytes ) !== substr( $net, 0, $bytes ) ) {
			return false;
		}
		$rest = $len % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = chr( ( 0xff << ( 8 - $rest ) ) & 0xff );
		return ( $bin[ $bytes ] & $mask ) === ( $net[ $bytes ] & $mask );
	}

	/**
	 * Parse a textarea of IPs/CIDRs (one per line, commas or spaces allowed;
	 * "#" starts a comment). Returns the valid entries and the rejected lines.
	 *
	 * @param string $text Raw text.
	 * @return array{valid:string[],invalid:string[]}
	 */
	public static function parse_list( $text ) {
		$valid   = array();
		$invalid = array();
		foreach ( preg_split( '/[\r\n]+/', (string) $text ) as $line ) {
			$line = trim( preg_replace( '/#.*$/', '', $line ) );
			if ( '' === $line ) {
				continue;
			}
			foreach ( preg_split( '/[\s,]+/', $line ) as $entry ) {
				if ( self::valid_entry( $entry ) ) {
					$valid[] = strtolower( $entry );
				} else {
					$invalid[] = $entry;
				}
			}
		}
		return array(
			'valid'   => array_values( array_unique( $valid ) ),
			'invalid' => $invalid,
		);
	}

	/**
	 * @param string $entry "ip" or "ip/prefix".
	 * @return bool
	 */
	public static function valid_entry( $entry ) {
		$parts = explode( '/', $entry, 2 );
		if ( false === filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( ! isset( $parts[1] ) ) {
			return true;
		}
		$max = false !== filter_var( $parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 128 : 32;
		return ctype_digit( $parts[1] ) && (int) $parts[1] <= $max;
	}
}
