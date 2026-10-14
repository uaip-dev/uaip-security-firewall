<?php
/**
 * Web Application Firewall (Free).
 *
 * Evaluates each request through Uaip_Sfw_WAF_Engine (anomaly scoring) and blocks
 * when the score reaches the threshold. Supports:
 *   - every entry point: front end, admin-ajax.php, admin-post.php, the REST API
 *     (JSON bodies), XML-RPC, uploads; only trusted editors/admins are skipped
 *   - learning mode (detect + log, never block)
 *   - IP/CIDR allowlist and blocklist, and rule exceptions per path
 *   - the real visitor IP behind Cloudflare / reverse proxies (Uaip_Sfw_IP)
 *   - rate limiting without a database write on every request
 *   - fail-open safety (a WAF error must never take the site down)
 *   - per-class block statistics for the Firewall dashboard
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_WAF {

	const STATS_OPTION = 'uaip_sfw_waf_stats';
	const RECENT_MAX   = 50;

	/** @var Uaip_Sfw_WAF_Engine|null */
	private $engine;

	public function register_hooks() {
		add_action( 'uaip_sfw_pull_rules', array( $this, 'pull_rules' ) );

		if ( ! Uaip_Sfw_Settings::get( 'waf_enabled' ) ) {
			return;
		}
		// register_hooks() runs during the plugin's boot on plugins_loaded, so
		// this is the earliest point in plugin mode — inspect synchronously now
		// rather than re-hooking plugins_loaded (which has already passed
		// priority 1). Extended/auto_prepend mode runs even earlier.
		$this->inspect_request();
	}

	/**
	 * Inspect the current request. Fail-open: any internal error is swallowed
	 * so the firewall can never break the site.
	 */
	public function inspect_request() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || 'cli' === PHP_SAPI ) {
			return;
		}
		try {
			// Editors and admins (unfiltered_html) legitimately post HTML, scripts
			// and code, so they are skipped unless the owner asks otherwise.
			// Everyone else is inspected everywhere, including wp-admin,
			// admin-ajax.php and admin-post.php, which anonymous visitors can reach.
			if ( ! Uaip_Sfw_Settings::get( 'waf_inspect_trusted' ) && function_exists( 'is_user_logged_in' ) && is_user_logged_in() && current_user_can( 'unfiltered_html' ) ) {
				return;
			}

			$proxies = Uaip_Sfw_IP::parse_list( (string) Uaip_Sfw_Settings::get( 'trusted_proxies', '' ) );
			$req     = Uaip_Sfw_WAF_Request::from_globals( (string) Uaip_Sfw_Settings::get( 'ip_source', 'remote_addr' ), $proxies['valid'] );
			$learning = 'learn' === Uaip_Sfw_Settings::get( 'waf_action', 'block' );

			if ( $this->in_ip_list( $req->ip, 'waf_allowlist_ips' ) ) {
				return;
			}
			if ( $this->in_ip_list( $req->ip, 'waf_blocklist_ips' ) ) {
				$verdict = array(
					'score'   => 0,
					'block'   => true,
					'classes' => array( 'blocklist' => 0 ),
					'matched' => array(
						array( 'id' => 'ip-blocklist', 'class' => 'blocklist', 'msg' => 'IP address is on the blocklist', 'severity' => 'critical', 'score' => 0, 'sample' => '' ),
					),
				);
				$this->record( $req, $verdict, $learning ? 'detect' : 'block' );
				if ( ! $learning ) {
					$this->block( $req, $verdict );
				}
				return;
			}

			// Rate limiting / bot throttling.
			if ( $this->over_rate_limit( $req ) ) {
				$this->record_rate( $req );
				if ( ! $learning ) {
					$this->block_rate();
				}
			}

			$exceptions = Uaip_Sfw_WAF_Engine::parse_exceptions( (string) Uaip_Sfw_Settings::get( 'waf_exceptions', '' ) );
			$verdict    = $this->engine()->evaluate( $req, $exceptions['valid'] );
			if ( empty( $verdict['matched'] ) ) {
				return;
			}

			$action = ( $verdict['block'] && ! $learning ) ? 'block' : 'detect';

			$this->record( $req, $verdict, $action );

			if ( 'block' === $action ) {
				$this->block( $req, $verdict );
			}
		} catch ( Exception $e ) {
			// Fail open.
			return;
		}
	}

	/** @return Uaip_Sfw_WAF_Engine */
	private function engine() {
		if ( null === $this->engine ) {
			$threshold    = (int) Uaip_Sfw_Settings::get( 'waf_threshold', 5 );
			$this->engine = new Uaip_Sfw_WAF_Engine( $threshold );

			// Bundled rules are the baseline; cloud rules are added on top
			// (override by id) so a pull can only extend coverage, never reduce it.
			$this->engine->load_json( UAIP_SFW_DIR . 'assets/waf-rules/core-rules.json' );
			$cached = get_option( 'uaip_sfw_waf_rules', array() );
			if ( ! empty( $cached ) ) {
				$this->engine->load_array( $cached );
			}
		}
		return $this->engine;
	}

	/** @return int Active rule count (for the dashboard). */
	public function rule_count() {
		return $this->engine()->rule_count();
	}

	/**
	 * Record a detection/block in rolling stats + the audit log.
	 *
	 * @param Uaip_Sfw_WAF_Request $req
	 * @param array          $verdict
	 * @param string         $action 'block'|'detect'
	 */
	private function record( $req, $verdict, $action ) {
		$top = $verdict['matched'][0];

		// Rolling 15-min block counter for the dashboard tile.
		if ( 'block' === $action ) {
			$recent = (int) get_transient( 'uaip_sfw_blocks_15m' ) + 1;
			set_transient( 'uaip_sfw_blocks_15m', $recent, 15 * MINUTE_IN_SECONDS );
			// Surge alert when blocks cross a threshold (throttled inside notifier).
			// The email is translated, so send it once translations can load
			// (the firewall itself runs before init).
			if ( $recent >= 25 ) {
				if ( did_action( 'init' ) ) {
					Uaip_Sfw_Notifier::attack_surge( $recent );
				} else {
					add_action(
						'init',
						static function () use ( $recent ) {
							Uaip_Sfw_Notifier::attack_surge( $recent );
						}
					);
				}
			}
		}

		// Persisted stats: per-class totals + recent ring buffer.
		$stats = get_option( self::STATS_OPTION, array( 'classes' => array(), 'recent' => array() ) );
		foreach ( $verdict['classes'] as $class => $sc ) {
			$stats['classes'][ $class ] = ( isset( $stats['classes'][ $class ] ) ? $stats['classes'][ $class ] : 0 ) + 1;
		}
		array_unshift(
			$stats['recent'],
			array(
				'ts'     => time(),
				'ip'     => $req->ip,
				'class'  => $top['class'],
				'rule'   => $top['id'],
				'msg'    => $top['msg'],
				'score'  => $verdict['score'],
				'action' => $action,
				'uri'    => $this->trim_uri( $req->uri ),
			)
		);
		$stats['recent'] = array_slice( $stats['recent'], 0, self::RECENT_MAX );
		update_option( self::STATS_OPTION, $stats, false );

		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record(
				'block' === $action ? 'attack_blocked' : 'attack_detected',
				array( 'rule' => $top['id'], 'class' => $top['class'], 'score' => $verdict['score'], 'ip' => $req->ip )
			);
		}
	}

	/**
	 * Stop the request with a clean 403 and a support reference.
	 *
	 * @param Uaip_Sfw_WAF_Request $req
	 * @param array          $verdict
	 */
	private function block( $req, $verdict ) {
		$ref = strtoupper( substr( md5( $req->ip . '|' . time() ), 0, 10 ) );

		status_header( 403 );
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}

		// Plain strings (not __()): the firewall runs on plugins_loaded, before
		// the init hook, so translating here would trigger WordPress 6.7+'s
		// "textdomain loaded too early" notice. The standalone auto_prepend
		// loader shows the same page without translation for the same reason.
		$title   = 'Request blocked';
		$message = 'Your request was blocked by UAIP Security Firewall because it matched a malicious pattern.';
		$refline = sprintf(
			'If you believe this is a mistake, contact the site administrator with reference %s.',
			$ref
		);

		// Inline style attributes (not a <style> block): this is a standalone
		// die() response emitted before wp_head, so there is nothing to enqueue
		// against — the same approach the pro auto_prepend loader uses.
		echo '<!doctype html><html><head><meta charset="utf-8"><title>' . esc_html( $title ) . '</title>';
		echo '<meta name="viewport" content="width=device-width, initial-scale=1"></head>';
		echo '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">';
		echo '<div style="background:#fff;border:1px solid #e2e4e7;border-radius:12px;padding:40px;max-width:480px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.06)">';
		echo '<div style="font-size:48px">&#128737;</div>';
		echo '<h1 style="font-size:22px;margin:12px 0">' . esc_html( $title ) . '</h1>';
		echo '<p style="color:#646970;line-height:1.5">' . esc_html( $message ) . '</p>';
		echo '<p style="color:#646970;line-height:1.5">' . esc_html( $refline ) . '</p>';
		echo '<p style="font-size:12px;color:#a7aaad;">Protected by UAIP Security</p>';
		echo '</div></body></html>';
		exit;
	}

	/**
	 * Per-IP request rate limiter (fixed 60-second window).
	 *
	 * Counters live in a persistent object cache or APCu when the host has one.
	 * Without either, only requests that are worth throttling (POSTs, login,
	 * XML-RPC, REST and AJAX calls) are counted, in transients, so ordinary page
	 * views never cause a database write.
	 *
	 * @param Uaip_Sfw_WAF_Request $req
	 * @return bool True when the IP is over the limit.
	 */
	private function over_rate_limit( $req ) {
		$rpm = (int) Uaip_Sfw_Settings::get( 'rate_limit_rpm', 240 );
		// The Settings-page toggle is the master switch; rate_limit_rpm (set on
		// the Firewall page) is the threshold. Either being off disables it.
		if ( ! Uaip_Sfw_Settings::get( 'rate_limit_enabled' ) || $rpm <= 0 || '' === $req->ip ) {
			return false;
		}
		$key = 'uaip_sfw_rl_' . md5( $req->ip ) . '_' . (int) floor( time() / 60 );

		if ( wp_using_ext_object_cache() ) {
			if ( false === wp_cache_add( $key, 0, 'uaip_sfw', 70 ) && false === wp_cache_get( $key, 'uaip_sfw' ) ) {
				return false;
			}
			$count = wp_cache_incr( $key, 1, 'uaip_sfw' );
			return false !== $count && $count > $rpm;
		}
		if ( function_exists( 'apcu_inc' ) && function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
			apcu_add( $key, 0, 70 );
			$count = apcu_inc( $key );
			return false !== $count && $count > $rpm;
		}
		if ( ! $this->is_sensitive( $req ) ) {
			return false;
		}
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, 70 );
		return $count > $rpm;
	}

	/**
	 * Requests worth rate limiting when counting costs a database write.
	 *
	 * @param Uaip_Sfw_WAF_Request $req
	 * @return bool
	 */
	private function is_sensitive( $req ) {
		if ( 'GET' !== $req->method && 'HEAD' !== $req->method ) {
			return true;
		}
		return (bool) preg_match( '#(^|/)(wp-login\.php|xmlrpc\.php|wp-admin/admin-ajax\.php)$|/wp-json(/|$)#', $req->path )
			|| isset( $req->query['rest_route'] );
	}

	/**
	 * Record a rate-limit event.
	 *
	 * @param Uaip_Sfw_WAF_Request $req
	 */
	private function record_rate( $req ) {
		set_transient( 'uaip_sfw_blocks_15m', (int) get_transient( 'uaip_sfw_blocks_15m' ) + 1, 15 * MINUTE_IN_SECONDS );
		$stats = get_option( self::STATS_OPTION, array( 'classes' => array(), 'recent' => array() ) );
		$stats['classes']['ratelimit'] = ( isset( $stats['classes']['ratelimit'] ) ? $stats['classes']['ratelimit'] : 0 ) + 1;
		array_unshift( $stats['recent'], array(
			'ts' => time(), 'ip' => $req->ip, 'class' => 'ratelimit', 'rule' => 'rate-limit',
			'msg' => 'Rate limit exceeded', 'score' => 0, 'action' => 'block', 'uri' => $this->trim_uri( $req->uri ),
		) );
		$stats['recent'] = array_slice( $stats['recent'], 0, self::RECENT_MAX );
		update_option( self::STATS_OPTION, $stats, false );
	}

	/** Send a 429 Too Many Requests response. */
	private function block_rate() {
		status_header( 429 );
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Retry-After: 60' );
		}
		// Plain strings (not __()): the firewall runs on plugins_loaded, before
		// the init hook, so translating here would trigger WordPress 6.7+'s
		// "textdomain loaded too early" notice. The standalone auto_prepend
		// loader shows the same page without translation for the same reason.
		wp_die(
			'Too many requests. Please slow down and try again shortly.',
			'Rate limited',
			array( 'response' => 429 )
		);
	}

	/** @return int Blocks recorded in the last 15 minutes. */
	public function recent_block_count() {
		return (int) get_transient( 'uaip_sfw_blocks_15m' );
	}

	/** @return array Persisted stats. */
	public function stats() {
		return get_option( self::STATS_OPTION, array( 'classes' => array(), 'recent' => array() ) );
	}

	public function clear_stats() {
		delete_option( self::STATS_OPTION );
	}

	/**
	 * Whether an IP is in one of the IP/CIDR list settings.
	 *
	 * @param string $ip      Visitor IP.
	 * @param string $setting 'waf_allowlist_ips' or 'waf_blocklist_ips'.
	 * @return bool
	 */
	private function in_ip_list( $ip, $setting ) {
		$text = (string) Uaip_Sfw_Settings::get( $setting, '' );
		if ( '' === $ip || '' === trim( $text ) ) {
			return false;
		}
		$list = Uaip_Sfw_IP::parse_list( $text );
		return Uaip_Sfw_IP::in_list( $ip, $list['valid'] );
	}

	/** Pull a fresh signed ruleset from the cloud (weekly Free / 5-min Pro). */
	public function pull_rules() {
		// Cloud rule updates are Pro-only; Free uses the bundled ruleset.
		if ( ! Uaip_Sfw_Plugin::instance()->license->is_pro() || ! Uaip_Sfw_Cloud_API::instance()->is_connected() ) {
			return;
		}
		$res = Uaip_Sfw_Cloud_API::instance()->pull_rules( array( 'waf' => get_option( 'uaip_sfw_waf_rules_version', 0 ) ) );
		if ( ! is_wp_error( $res ) && ! empty( $res['waf']['payload'] ) ) {
			$this->apply_feed( $res['waf'] );
		}
	}

	/**
	 * Install a signed rule bundle after verifying it.
	 *
	 * @param array $bundle {version, payload, sig}.
	 * @return true|WP_Error
	 */
	public function apply_feed( array $bundle ) {
		$feed = Uaip_Sfw_Rules_Feed::verify( $bundle, (int) get_option( 'uaip_sfw_waf_rules_version', 0 ) );
		if ( is_wp_error( $feed ) ) {
			update_option( 'uaip_sfw_waf_feed_error', array( 'ts' => time(), 'code' => $feed->get_error_code() ), false );
			return $feed;
		}
		update_option( 'uaip_sfw_waf_rules', $feed['rules'] );
		update_option( 'uaip_sfw_waf_rules_version', $feed['version'] );
		delete_option( 'uaip_sfw_waf_feed_error' );
		// Extended protection (the auto_prepend loader) is a Pro-only feature;
		// the installer class is absent from the free build.
		if ( class_exists( 'Uaip_Sfw_WAF_Installer' ) && Uaip_Sfw_WAF_Installer::is_installed() ) {
			Uaip_Sfw_WAF_Installer::write_config();
		}
		return true;
	}

	/**
	 * Prepare a request URI for persistence in the WAF stats. The firewall
	 * matches on the raw URI (see Uaip_Sfw_WAF_Request), but the copy that is stored
	 * via update_option() is sanitized here (and escaped again on output in the
	 * admin table) so no raw request data is ever persisted or displayed.
	 *
	 * @param string $uri
	 * @return string
	 */
	private function trim_uri( $uri ) {
		$uri = sanitize_text_field( $uri );
		return strlen( $uri ) > 120 ? substr( $uri, 0, 120 ) . '…' : $uri;
	}
}
