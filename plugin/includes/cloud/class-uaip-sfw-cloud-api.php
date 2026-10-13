<?php
/**
 * Signed HTTPS client for UAIP Security Cloud.
 *
 * Every request is HMAC-signed with the site's API secret so the cloud can
 * authenticate the site without sending the secret over the wire. The Free
 * tier uses only: register, pull_rules, validate_license, send_event (alerts),
 * and hash-only reputation lookups. Pro adds sample upload & deep scan.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Cloud_API {

	/** @var Uaip_Sfw_Cloud_API */
	private static $instance;

	const OPT_SITE_ID = 'uaip_sfw_site_id';
	const OPT_SECRET  = 'uaip_sfw_site_secret';

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/** @return bool Whether this site has registered with the cloud. */
	public function is_connected() {
		return '' !== (string) get_option( self::OPT_SITE_ID, '' );
	}

	/**
	 * Register the site with UAIP Security Cloud, receiving a site id + secret.
	 *
	 * @param string $email Owner email for alerts.
	 * @return array|WP_Error
	 */
	public function register_site( $email ) {
		$body = array(
			'url'     => home_url(),
			'email'   => sanitize_email( $email ),
			'wp'      => get_bloginfo( 'version' ),
			'version' => UAIP_SFW_VERSION,
		);
		$res = $this->request( 'POST', '/sites/register', $body, false );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		if ( ! empty( $res['site_id'] ) && ! empty( $res['secret'] ) ) {
			update_option( self::OPT_SITE_ID, sanitize_text_field( $res['site_id'] ) );
			update_option( self::OPT_SECRET, Uaip_Sfw_Crypto::encrypt( $res['secret'] ) );
			Uaip_Sfw_Settings::update( array( 'cloud_connected' => true ) );
		}
		return $res;
	}

	/**
	 * Validate a Pro license key.
	 *
	 * @param string $key
	 * @return array|WP_Error {active:bool, plan:string, expires:?string}
	 */
	public function validate_license( $key ) {
		return $this->request( 'POST', '/license/validate', array(
			'key'   => $key,
			'url'   => home_url(),
			'email' => get_option( 'admin_email' ),
		) );
	}

	/**
	 * Release this site's seat for a license key.
	 *
	 * @param string $key
	 * @return array|WP_Error
	 */
	public function deactivate_license( $key ) {
		return $this->request( 'POST', '/license/deactivate', array(
			'key' => $key,
			'url' => home_url(),
		) );
	}

	/**
	 * Pull the signed WAF/YARA/vuln rule bundle.
	 *
	 * @param array $have Current local rule versions.
	 * @return array|WP_Error
	 */
	public function pull_rules( array $have = array() ) {
		return $this->request( 'GET', '/rules', $have );
	}

	/**
	 * Send a security event (attack blocked, malware found, anomaly, …).
	 *
	 * @param string $type
	 * @param array  $data
	 * @return array|WP_Error
	 */
	public function send_event( $type, array $data ) {
		return $this->request( 'POST', '/events', array( 'type' => $type, 'data' => $data ) );
	}

	/**
	 * Heartbeat: periodic health/scan/WAF summary. Drives cloud anomaly
	 * detection & uptime monitoring.
	 *
	 * @param array $payload
	 * @return array|WP_Error
	 */
	public function heartbeat( array $payload ) {
		return $this->request( 'POST', '/heartbeat', $payload );
	}

	/**
	 * Reputation lookup for suspicious files. Free sends HASHES ONLY.
	 *
	 * @param array $hashes
	 * @return array|WP_Error
	 */
	public function lookup_hashes( array $hashes ) {
		return $this->request( 'POST', '/intel/hashes', array( 'hashes' => $hashes ) );
	}

	/**
	 * Resolve an IP to an ISO-3166 country code (Pro geo-blocking).
	 *
	 * @param string $ip
	 * @return array|WP_Error {country:string}
	 */
	public function lookup_country( $ip ) {
		return $this->request( 'GET', '/intel/geo', array( 'ip' => $ip ) );
	}

	/**
	 * Build a signed URL that binds this site to a UAIP Security Cloud account.
	 * The cloud verifies the signature (with the site secret) before binding,
	 * so a site can only be claimed by someone who controls this install.
	 *
	 * @param string $return_url Where the cloud sends the admin back to.
	 * @return string Empty if the site is not connected to the cloud yet.
	 */
	public function connect_url( $return_url ) {
		$site_id = (string) get_option( self::OPT_SITE_ID, '' );
		$secret  = Uaip_Sfw_Crypto::decrypt( get_option( self::OPT_SECRET, '' ) );
		if ( '' === $site_id || '' === $secret ) {
			return '';
		}
		$ts  = (string) time();
		$sig = hash_hmac( 'sha256', $site_id . "\n" . $ts . "\n" . $return_url, $secret );
		return add_query_arg(
			array(
				'site'   => $site_id,
				'ts'     => $ts,
				'return' => $return_url,
				'sig'    => $sig,
			),
			UAIP_SFW_CLOUD_SITE . '/connect'
		);
	}

	/**
	 * Perform a signed request to the cloud.
	 *
	 * @param string $method
	 * @param string $path
	 * @param array  $body
	 * @param bool   $signed Whether to attach the HMAC signature (needs registration).
	 * @return array|WP_Error
	 */
	private function request( $method, $path, array $body = array(), $signed = true ) {
		$url     = UAIP_SFW_CLOUD_URL . $path;
		$payload = wp_json_encode( $body );
		$headers = array( 'Content-Type' => 'application/json', 'Accept' => 'application/json' );

		// What we sign: for GET we send the params as a query string, so sign
		// that exact string (type-safe). For other methods we sign the JSON body.
		$is_get       = ( 'GET' === $method );
		$query        = $is_get ? http_build_query( $body ) : '';
		$sign_payload = $is_get ? $query : $payload;

		if ( $signed ) {
			$site_id = (string) get_option( self::OPT_SITE_ID, '' );
			$secret  = Uaip_Sfw_Crypto::decrypt( get_option( self::OPT_SECRET, '' ) );
			if ( '' === $site_id || '' === $secret ) {
				return new WP_Error( 'uaip_sfw_not_connected', __( 'Site is not connected to UAIP Security Cloud.', 'uaip-security-firewall' ) );
			}
			$ts                        = (string) time();
			$signature                 = hash_hmac( 'sha256', $method . "\n" . $path . "\n" . $ts . "\n" . $sign_payload, $secret );
			$headers['X-UAIP-Site']      = $site_id;
			$headers['X-UAIP-Timestamp'] = $ts;
			$headers['X-UAIP-Signature'] = $signature;
		}

		$args = array(
			'method'  => $method,
			'headers' => $headers,
			'timeout' => 15,
		);
		if ( $is_get ) {
			if ( '' !== $query ) {
				$url .= '?' . $query;
			}
		} else {
			$args['body'] = $payload;
		}

		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = wp_remote_retrieve_response_code( $response );
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error( 'uaip_sfw_cloud_http', sprintf( 'Cloud returned HTTP %d', $code ), $data );
		}
		return is_array( $data ) ? $data : array();
	}
}
