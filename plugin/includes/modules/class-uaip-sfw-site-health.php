<?php
/**
 * Security checks shown in Tools → Site Health and as the hardening score.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Site_Health {

	/** Days before a scan counts as stale. */
	const SCAN_MAX_AGE_DAYS = 7;

	public function register_hooks() {
		add_filter( 'site_status_tests', array( $this, 'register_tests' ) );
		add_filter( 'debug_information', array( $this, 'debug_information' ) );
	}

	/**
	 * Every check: [label, callback]. Each callback returns a result array
	 * (status good|recommended|critical, label, description, action).
	 *
	 * @return array<string,callable>
	 */
	private function checks() {
		return array(
			'firewall'      => array( $this, 'check_firewall' ),
			'file_editor'   => array( $this, 'check_file_editor' ),
			'uploads'       => array( $this, 'check_uploads' ),
			'admins_2fa'    => array( $this, 'check_admins_2fa' ),
			'scan'          => array( $this, 'check_scan' ),
			'vulns'         => array( $this, 'check_vulns' ),
			'login'         => array( $this, 'check_login' ),
			'usernames'     => array( $this, 'check_usernames' ),
			'headers'       => array( $this, 'check_headers' ),
			'debug_display' => array( $this, 'check_debug_display' ),
		);
	}

	/**
	 * @param array $tests Site Health tests.
	 * @return array
	 */
	public function register_tests( $tests ) {
		foreach ( $this->checks() as $id => $cb ) {
			$tests['direct'][ 'uaip_sfw_' . $id ] = array(
				'label' => __( 'UAIP Security check', 'uaip-security-firewall' ),
				'test'  => function () use ( $id, $cb ) {
					return $this->site_health_result( $id, call_user_func( $cb ) );
				},
			);
		}
		return $tests;
	}

	/**
	 * All results for the hardening score.
	 *
	 * @return array<string,array>
	 */
	public function results() {
		$out = array();
		foreach ( $this->checks() as $id => $cb ) {
			$out[ $id ] = call_user_func( $cb );
		}
		return $out;
	}

	/**
	 * @param array $results From results().
	 * @return array{passed:int,total:int,percent:int}
	 */
	public static function score( array $results ) {
		$passed = 0;
		foreach ( $results as $r ) {
			$passed += 'good' === $r['status'] ? 1 : 0;
		}
		$total = max( 1, count( $results ) );
		return array(
			'passed'  => $passed,
			'total'   => count( $results ),
			'percent' => (int) round( 100 * $passed / $total ),
		);
	}

	/**
	 * Shape a result for Site Health.
	 *
	 * @param string $id Check id.
	 * @param array  $r  Result.
	 * @return array
	 */
	private function site_health_result( $id, array $r ) {
		$action = '';
		if ( ! empty( $r['action_url'] ) && 'good' !== $r['status'] ) {
			$action = sprintf( '<p><a href="%s">%s</a></p>', esc_url( $r['action_url'] ), esc_html( $r['action_label'] ) );
		}
		return array(
			'label'       => $r['label'],
			'status'      => $r['status'],
			'badge'       => array(
				'label' => __( 'Security', 'uaip-security-firewall' ),
				'color' => 'good' === $r['status'] ? 'blue' : ( 'critical' === $r['status'] ? 'red' : 'orange' ),
			),
			'description' => '<p>' . esc_html( $r['description'] ) . '</p>',
			'actions'     => $action,
			'test'        => 'uaip_sfw_' . $id,
		);
	}

	/**
	 * @param string $status       good|recommended|critical.
	 * @param string $label        Heading.
	 * @param string $description  Details.
	 * @param string $action_url   Fix link.
	 * @param string $action_label Fix label.
	 * @return array
	 */
	private function result( $status, $label, $description, $action_url = '', $action_label = '' ) {
		return compact( 'status', 'label', 'description', 'action_url', 'action_label' );
	}

	/** @return string Hardening page. */
	private function hardening_url() {
		return admin_url( 'admin.php?page=uaip-sfw-hardening' );
	}

	// ------------------------------------------------------------------
	// Checks
	// ------------------------------------------------------------------

	public function check_firewall() {
		$fix = admin_url( 'admin.php?page=uaip-sfw-settings' );
		if ( ! Uaip_Sfw_Settings::get( 'waf_enabled' ) ) {
			return $this->result( 'critical', __( 'The firewall is off', 'uaip-security-firewall' ), __( 'Requests are not checked for attacks such as SQL injection or cross-site scripting.', 'uaip-security-firewall' ), $fix, __( 'Turn on the firewall', 'uaip-security-firewall' ) );
		}
		if ( 'learn' === Uaip_Sfw_Settings::get( 'waf_action' ) ) {
			return $this->result( 'recommended', __( 'The firewall is only watching (learning mode)', 'uaip-security-firewall' ), __( 'Attacks are logged but not blocked. Switch to blocking once the log shows no false alarms.', 'uaip-security-firewall' ), admin_url( 'admin.php?page=uaip-sfw-firewall' ), __( 'Open firewall settings', 'uaip-security-firewall' ) );
		}
		return $this->result( 'good', __( 'The firewall is blocking attacks', 'uaip-security-firewall' ), __( 'Requests are checked against the firewall rules and attacks are refused.', 'uaip-security-firewall' ) );
	}

	public function check_file_editor() {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return $this->result( 'good', __( 'The file editor is turned off', 'uaip-security-firewall' ), __( 'Plugin and theme code cannot be edited from wp-admin.', 'uaip-security-firewall' ) );
		}
		return $this->result( 'recommended', __( 'The plugin and theme file editor is on', 'uaip-security-firewall' ), __( 'Anyone who gets into an administrator account can add code to the site from wp-admin.', 'uaip-security-firewall' ), $this->hardening_url(), __( 'Turn off the file editor', 'uaip-security-firewall' ) );
	}

	public function check_uploads() {
		$harden = Uaip_Sfw_Plugin::instance()->module( 'hardening' );
		$probe  = $harden ? $harden->last_probe() : null;
		if ( $probe && 'runs' === $probe['result'] ) {
			return $this->result( 'critical', __( 'PHP files can run in the uploads folder', 'uaip-security-firewall' ), __( 'A test file uploaded there ran as code. A single bad upload could take over the site.', 'uaip-security-firewall' ), $this->hardening_url(), __( 'Stop scripts running in uploads', 'uaip-security-firewall' ) );
		}
		if ( $probe && 'blocked' === $probe['result'] ) {
			return $this->result( 'good', __( 'Scripts cannot run in the uploads folder', 'uaip-security-firewall' ), __( 'A test file placed in uploads did not run.', 'uaip-security-firewall' ) );
		}
		if ( Uaip_Sfw_Settings::get( 'harden_block_php_uploads' ) && $harden && $harden->php_block_present() && $this->server_reads_htaccess() ) {
			return $this->result( 'good', __( 'Scripts are blocked in the uploads folder', 'uaip-security-firewall' ), __( 'The uploads folder has a rule that stops PHP files from running.', 'uaip-security-firewall' ) );
		}
		return $this->result( 'recommended', __( 'Scripts may be able to run in the uploads folder', 'uaip-security-firewall' ), __( 'Nothing stops a PHP file in uploads from running. Turn on the uploads rule, then run the test on the Hardening page.', 'uaip-security-firewall' ), $this->hardening_url(), __( 'Open hardening', 'uaip-security-firewall' ) );
	}

	/** @return bool Apache or LiteSpeed (both read .htaccess). */
	public function server_reads_htaccess() {
		global $is_apache;
		return (bool) $is_apache;
	}

	public function check_admins_2fa() {
		$twofa = Uaip_Sfw_Plugin::instance()->module( 'twofa' );
		if ( ! $twofa ) {
			return $this->result( 'recommended', __( 'Two-step verification is not available', 'uaip-security-firewall' ), '' );
		}
		$missing = array();
		foreach ( get_users(
			array(
				'role'   => 'administrator',
				'number' => 200,
			)
		) as $admin ) {
			if ( ! in_array( true, $twofa->methods( $admin ), true ) ) {
				$missing[] = $admin->user_login;
			}
		}
		if ( ! $missing ) {
			return $this->result( 'good', __( 'Every administrator uses two-step verification', 'uaip-security-firewall' ), __( 'A stolen administrator password alone is not enough to sign in.', 'uaip-security-firewall' ) );
		}
		return $this->result(
			'recommended',
			/* translators: %d: number of administrators */
			sprintf( _n( '%d administrator signs in with a password only', '%d administrators sign in with a password only', count( $missing ), 'uaip-security-firewall' ), count( $missing ) ),
			/* translators: %s: list of usernames */
			sprintf( __( 'Without a second step: %s. Add a passkey or authenticator app, or require two-step verification for administrators.', 'uaip-security-firewall' ), implode( ', ', array_slice( $missing, 0, 10 ) ) ),
			Uaip_Sfw_Twofa_Page::url(),
			__( 'Set up two-step verification', 'uaip-security-firewall' )
		);
	}

	public function check_scan() {
		$fix     = admin_url( 'admin.php?page=uaip-sfw-scan' );
		$summary = get_option( Uaip_Sfw_Scanner::SUMMARY_OPTION, array() );
		$scanner = Uaip_Sfw_Plugin::instance()->module( 'scanner' );
		$open    = $scanner ? count( $scanner->findings( 'open', 100 ) ) : 0;
		if ( $open ) {
			return $this->result(
				'critical',
				/* translators: %d: number of findings */
				sprintf( _n( 'The malware scan found %d problem', 'The malware scan found %d problems', $open, 'uaip-security-firewall' ), $open ),
				__( 'Review each finding: repair changed WordPress files, delete malware, or mark false alarms as ignored.', 'uaip-security-firewall' ),
				$fix,
				__( 'Review findings', 'uaip-security-firewall' )
			);
		}
		$ts = is_array( $summary ) && isset( $summary['ts'] ) ? (int) $summary['ts'] : 0;
		if ( ! $ts || time() - $ts > self::SCAN_MAX_AGE_DAYS * DAY_IN_SECONDS ) {
			return $this->result( 'recommended', __( 'No recent malware scan', 'uaip-security-firewall' ), __( 'The site has not been scanned in the last week. Scans normally run daily through WP-Cron.', 'uaip-security-firewall' ), $fix, __( 'Scan now', 'uaip-security-firewall' ) );
		}
		return $this->result( 'good', __( 'The latest malware scan is clean', 'uaip-security-firewall' ), __( 'No open findings from the last scan.', 'uaip-security-firewall' ) );
	}

	public function check_vulns() {
		$fix = admin_url( 'admin.php?page=uaip-sfw-vulns' );
		if ( ! Uaip_Sfw_Vulns::enabled() ) {
			return $this->result( 'recommended', __( 'Vulnerability alerts are off', 'uaip-security-firewall' ), __( 'Most hacked WordPress sites run a plugin or theme with a known, already fixed vulnerability. Alerts tell you when one is installed here (opt-in: sends software versions to UAIP Security Cloud).', 'uaip-security-firewall' ), $fix, __( 'Read more and turn on', 'uaip-security-firewall' ) );
		}
		$res   = Uaip_Sfw_Vulns::results();
		$count = 0;
		foreach ( (array) ( $res['items'] ?? array() ) as $it ) {
			$count += count( $it['vulns'] );
		}
		if ( $count ) {
			return $this->result(
				'critical',
				/* translators: %d: number of vulnerabilities */
				sprintf( _n( '%d known vulnerability in installed software', '%d known vulnerabilities in installed software', $count, 'uaip-security-firewall' ), $count ),
				__( 'Update or remove the affected software. Attackers scan for these versions automatically.', 'uaip-security-firewall' ),
				$fix,
				__( 'See what to update', 'uaip-security-firewall' )
			);
		}
		if ( empty( $res['checked_at'] ) || (int) $res['checked_at'] < time() - 3 * DAY_IN_SECONDS ) {
			return $this->result( 'recommended', __( 'The vulnerability check has not run recently', 'uaip-security-firewall' ), __( 'The daily check runs through WP-Cron. Run it by hand to see whether the cloud can be reached.', 'uaip-security-firewall' ), $fix, __( 'Check now', 'uaip-security-firewall' ) );
		}
		return $this->result( 'good', __( 'No known vulnerabilities in installed software', 'uaip-security-firewall' ), __( 'WordPress, plugins and themes were checked against known vulnerabilities in the last day.', 'uaip-security-firewall' ) );
	}

	public function check_login() {
		if ( Uaip_Sfw_Settings::get( 'login_protection' ) ) {
			return $this->result( 'good', __( 'Password guessing is limited', 'uaip-security-firewall' ), __( 'Repeated failed sign-ins trigger a check question and then a lockout.', 'uaip-security-firewall' ) );
		}
		return $this->result( 'recommended', __( 'Password guessing is not limited', 'uaip-security-firewall' ), __( 'Bots can try passwords without being slowed down.', 'uaip-security-firewall' ), admin_url( 'admin.php?page=uaip-sfw-settings' ), __( 'Turn on login protection', 'uaip-security-firewall' ) );
	}

	public function check_usernames() {
		if ( Uaip_Sfw_Settings::get( 'harden_hide_users' ) ) {
			return $this->result( 'good', __( 'Usernames are hidden from visitors', 'uaip-security-firewall' ), __( 'Author scans, the public users list and different sign-in errors do not reveal usernames.', 'uaip-security-firewall' ) );
		}
		return $this->result( 'recommended', __( 'Visitors can find usernames', 'uaip-security-firewall' ), __( 'Bots read usernames from ?author= links and the REST API, then guess only the password.', 'uaip-security-firewall' ), $this->hardening_url(), __( 'Hide usernames', 'uaip-security-firewall' ) );
	}

	public function check_headers() {
		if ( Uaip_Sfw_Settings::get( 'harden_headers' ) ) {
			return $this->result( 'good', __( 'Security headers are sent', 'uaip-security-firewall' ), __( 'Browsers are told not to guess file types, not to show the site in other sites\' frames, and to share less referrer data.', 'uaip-security-firewall' ) );
		}
		return $this->result( 'recommended', __( 'Security headers are not sent', 'uaip-security-firewall' ), __( 'Headers such as X-Frame-Options protect visitors against clickjacking and similar tricks.', 'uaip-security-firewall' ), $this->hardening_url(), __( 'Send security headers', 'uaip-security-firewall' ) );
	}

	public function check_debug_display() {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) {
			return $this->result( 'recommended', __( 'PHP errors are shown to visitors', 'uaip-security-firewall' ), __( 'Error messages can reveal file paths and plugin details. Set WP_DEBUG_DISPLAY to false in wp-config.php on a live site.', 'uaip-security-firewall' ) );
		}
		return $this->result( 'good', __( 'PHP errors are hidden from visitors', 'uaip-security-firewall' ), __( 'Error details are not printed on pages.', 'uaip-security-firewall' ) );
	}

	// ------------------------------------------------------------------
	// Site Health → Info
	// ------------------------------------------------------------------

	/**
	 * @param array $info Debug sections.
	 * @return array
	 */
	public function debug_information( $info ) {
		$s      = Uaip_Sfw_Settings::all();
		$on     = __( 'On', 'uaip-security-firewall' );
		$off    = __( 'Off', 'uaip-security-firewall' );
		$fields = array(
			'version'  => array(
				'label' => __( 'Version', 'uaip-security-firewall' ),
				'value' => UAIP_SFW_VERSION,
			),
			'firewall' => array(
				'label' => __( 'Firewall', 'uaip-security-firewall' ),
				'value' => $s['waf_enabled'] ? ( 'learn' === $s['waf_action'] ? __( 'Learning', 'uaip-security-firewall' ) : __( 'Blocking', 'uaip-security-firewall' ) ) : $off,
				'debug' => $s['waf_enabled'] ? $s['waf_action'] : 'off',
			),
			'ip_source' => array(
				'label' => __( 'Visitor IP source', 'uaip-security-firewall' ),
				'value' => (string) $s['ip_source'],
			),
		);
		foreach ( array( 'harden_disable_editor', 'harden_block_php_uploads', 'harden_hide_users', 'harden_headers', 'harden_hsts', 'harden_disable_xmlrpc', 'harden_hide_version', 'audit_log_enabled' ) as $key ) {
			$fields[ $key ] = array(
				'label' => $key,
				'value' => ! empty( $s[ $key ] ) ? $on : $off,
				'debug' => ! empty( $s[ $key ] ) ? 'on' : 'off',
			);
		}
		$info['uaip-security-firewall'] = array(
			'label'  => 'UAIP Security Firewall',
			'fields' => $fields,
		);
		return $info;
	}
}
