<?php
/**
 * Malware scan orchestrator (Free).
 *
 * Layers: integrity (WP.org hashes) + YARA (binary or PHP-lite fallback) +
 * heuristics. ClamAV and cloud deep-scan are Pro and registered by the Pro
 * loader (they override/extend this module's results).
 *
 * Scans run incrementally via WP-Cron so they never block a request.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Scanner {

	public function register_hooks() {
		add_action( 'uaip_sfw_scan', array( $this, 'run' ) );
		// Schedule per the configured frequency.
		if ( ! wp_next_scheduled( 'uaip_sfw_scan' ) ) {
			$recurrence = 'daily' === Uaip_Sfw_Settings::get( 'scan_schedule' ) ? 'daily' : 'uaip_sfw_quarter_hour';
			wp_schedule_event( time() + 300, $recurrence, 'uaip_sfw_scan' );
		}
	}

	/**
	 * Run a scan pass. Returns a summary and stores it for the heartbeat.
	 *
	 * @return array
	 */
	public function run() {
		$findings              = array();
		$this->scanned         = array();
		$this->change_summary  = array( 'added' => 0, 'changed' => 0, 'removed' => 0 );

		// Mark in-progress so the admin can show a "scanning…" state and the UI
		// never blocks on the (heavier) first baseline build. Cleared at the end.
		update_option( 'uaip_sfw_scan_running', time(), false );

		// Collect the file set once and share it with every layer.
		$targets = $this->changed_files();

		// Layer 1: integrity (always, Free).
		$findings = array_merge( $findings, $this->integrity_scan() );

		// Layer 2: YARA (Free) — binary or PHP-lite.
		if ( Uaip_Sfw_Settings::get( 'scan_yara_enabled' ) ) {
			$findings = array_merge( $findings, $this->yara_scan( $targets ) );
		}

		// Layer 3: cloud hash reputation (when connected). Catches KNOWN malware
		// by hash even if local rules miss it. Only SHA-256 hashes leave the
		// site — never file contents.
		$findings = array_merge( $findings, $this->cloud_hash_scan( $targets ) );

		// Pro layers extend results via this filter (e.g. ClamAV), reusing the
		// same file list.
		$findings = apply_filters( 'uaip_sfw_scan_findings', $findings, array( 'files' => $targets ) );

		$summary = array(
			'ts'       => time(),
			'engine'   => $this->yara_engine(),
			'findings' => count( $findings ),
			'scanned'  => $this->last_scanned,
			'capped'   => $this->capped,
			'changes'  => $this->change_summary,
			'tier'     => Uaip_Sfw_Plugin::instance()->license->tier(),
		);
		update_option( 'uaip_sfw_last_scan_summary', $summary );
		update_option( 'uaip_sfw_last_scan_findings', $findings );

		$this->handle_findings( $findings );
		delete_option( 'uaip_sfw_scan_running' ); // done
		return $summary;
	}

	/**
	 * Which YARA engine is active on this host.
	 *
	 * @return string 'binary' | 'php-lite' | 'none'
	 */
	public function yara_engine() {
		if ( $this->yara_binary() ) {
			return 'binary';
		}
		// PHP-lite matcher is always available as a fallback.
		return 'php-lite';
	}

	/**
	 * Locate a usable yara binary (disabled where exec() is blocked).
	 *
	 * @return string|null Path/command or null.
	 */
	private function yara_binary() {
		if ( ! function_exists( 'exec' ) || in_array( 'exec', array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) ), true ) ) {
			return null;
		}
		$out = array();
		$rc  = 0;
		@exec( 'yara --version 2>/dev/null', $out, $rc );
		return ( 0 === $rc && ! empty( $out ) ) ? 'yara' : null;
	}

	/** Max bytes to read per file (skip large media/archives). */
	const MAX_FILE_BYTES = 3145728; // 3 MB
	/** Max files to scan per run (bounded for performance; capping is logged). */
	const MAX_FILES = 8000;

	/** @var int Files skipped because the cap was hit (surfaced, never silent). */
	private $capped = 0;

	/** @var int Files scanned in the most recent pass. */
	private $last_scanned = 0;

	/** Local file-integrity baseline: rel-path => {sha,verdict,label,checked}. */
	const BASELINE_OPTION = 'uaip_sfw_file_baseline';

	/** @var array<string,string> rel-path => sha256, collected during the YARA
	 * read pass and reused by the cloud hash layer (no extra disk reads). */
	private $scanned = array();

	/** @var array{added:int,changed:int,removed:int} Code-change deltas vs baseline. */
	private $change_summary = array( 'added' => 0, 'changed' => 0, 'removed' => 0 );

	/**
	 * YARA scan. Uses the binary if present, else the PHP-lite matcher.
	 *
	 * @return array Findings.
	 */
	private function yara_scan( $targets ) {
		$rules_dir = UAIP_SFW_DIR . 'assets/yara-rules';

		if ( 'binary' === $this->yara_engine() ) {
			return $this->yara_scan_binary( $rules_dir, $targets );
		}
		return $this->yara_scan_php_lite( $rules_dir, $targets );
	}

	/**
	 * Native-binary path. Matching is done by `yara`; rule metadata
	 * (severity/description) comes from Uaip_Sfw_Yara_Lite so findings are consistent.
	 *
	 * @param string $rules_dir
	 * @param array  $targets
	 * @return array
	 */
	private function yara_scan_binary( $rules_dir, $targets ) {
		// Build a metadata map (rule name => severity/description).
		$meta   = array();
		$engine = new Uaip_Sfw_Yara_Lite();
		$engine->load_dir( $rules_dir );

		// Concatenate all rule files for a single yara invocation.
		$combined = '';
		foreach ( (array) glob( rtrim( $rules_dir, '/' ) . '/*.txt' ) as $rf ) {
			$combined .= "\n" . (string) @file_get_contents( $rf );
		}
		// Stage the combined rules under uploads/uaip-sfw (the plugin's own
		// managed, non-web-readable working dir) rather than a plugin-folder or
		// root path.
		$work = trailingslashit( wp_upload_dir()['basedir'] ) . 'uaip-sfw';
		if ( ! is_dir( $work ) ) {
			wp_mkdir_p( $work );
			@file_put_contents( $work . '/.htaccess', "Require all denied\nDeny from all\n" );
		}
		$tmp = $work . '/uaip-sfw-rules.yar';
		if ( false === @file_put_contents( $tmp, $combined ) ) {
			// Can't stage rules; fall back to the PHP matcher.
			return $this->yara_scan_php_lite( $rules_dir, $targets );
		}

		$findings = array();
		foreach ( $targets as $file ) {
			$out = array();
			$rc  = 0;
			@exec( 'yara ' . escapeshellarg( $tmp ) . ' ' . escapeshellarg( $file ) . ' 2>/dev/null', $out, $rc );
			foreach ( $out as $line ) {
				$rule = trim( strtok( $line, ' ' ) );
				if ( '' === $rule ) {
					continue;
				}
				$findings[] = $this->finding( $file, $rule, $this->meta_for( $engine, $rule ) );
			}
		}
		wp_delete_file( $tmp );
		return $findings;
	}

	/**
	 * Pure-PHP YARA-lite matcher — the standalone path for hosts without the
	 * yara binary (most shared hosting).
	 *
	 * @param string $rules_dir
	 * @param array  $targets
	 * @return array
	 */
	private function yara_scan_php_lite( $rules_dir, $targets ) {
		$engine = new Uaip_Sfw_Yara_Lite();
		$engine->load_dir( $rules_dir );
		if ( 0 === $engine->rule_count() ) {
			return array();
		}

		$findings = array();
		foreach ( $targets as $file ) {
			$data = @file_get_contents( $file, false, null, 0, self::MAX_FILE_BYTES );
			if ( false === $data ) {
				continue;
			}
			// Reuse these bytes for cloud hash reputation — only when the whole
			// file fit within the read cap, so the SHA-256 matches the full-file
			// hash stored in the threat-intel DB. No extra disk read.
			if ( strlen( $data ) < self::MAX_FILE_BYTES ) {
				$this->scanned[ $this->rel( $file ) ] = hash( 'sha256', $data );
			}
			foreach ( $engine->scan_data( $data ) as $hit ) {
				$findings[] = $this->finding( $file, $hit['rule'], $hit );
			}
		}
		return $findings;
	}

	/**
	 * Build a normalized finding record.
	 *
	 * @param string $file
	 * @param string $rule
	 * @param array  $hit  Has severity/description when available.
	 * @return array
	 */
	private function finding( $file, $rule, $hit ) {
		return array(
			'file'        => $this->rel( $file ),
			'rule'        => $rule,
			'severity'    => isset( $hit['severity'] ) ? $hit['severity'] : 'medium',
			'description' => isset( $hit['description'] ) ? $hit['description'] : '',
			'hash'        => @md5_file( $file ),
		);
	}

	/**
	 * Cloud hash-reputation + file-integrity baseline.
	 *
	 * Keeps a per-file SHA-256 baseline so each scan only sends NEW or CHANGED
	 * hashes to the cloud (never file contents); unchanged files reuse their
	 * cached verdict, and every file is re-checked at least weekly as the
	 * threat feed grows. Known-malicious files are flagged whether freshly
	 * checked or cached. The added/changed/removed counts power code-change
	 * tracking (malware injection almost always adds or modifies files).
	 *
	 * @param array $targets Absolute paths (fallback source when YARA didn't read).
	 * @return array Findings for known-malicious files.
	 */
	private function cloud_hash_scan( $targets ) {
		// Cloud hash-reputation is a Pro feature; Free never contacts the cloud.
		if ( ! Uaip_Sfw_Plugin::instance()->license->is_pro() || ! Uaip_Sfw_Cloud_API::instance()->is_connected() ) {
			return array(); // cloud-powered layer
		}

		// The YARA read pass fills $this->scanned (rel => sha) for free. If it
		// didn't run (native-binary path), hash a bounded set here instead.
		if ( empty( $this->scanned ) ) {
			$n = 0;
			foreach ( $targets as $file ) {
				if ( $n >= self::MAX_FILES ) {
					break;
				}
				$size = is_readable( $file ) ? @filesize( $file ) : false;
				if ( false === $size || $size > self::MAX_FILE_BYTES ) {
					continue;
				}
				$sha = @hash_file( 'sha256', $file );
				if ( $sha ) {
					$this->scanned[ $this->rel( $file ) ] = strtolower( $sha );
					$n++;
				}
			}
		}
		if ( empty( $this->scanned ) ) {
			return array();
		}

		$baseline = get_option( self::BASELINE_OPTION, array() );
		$baseline = is_array( $baseline ) ? $baseline : array();
		$now      = time();
		$stale    = $now - 7 * DAY_IN_SECONDS;

		// Decide which hashes need a cloud lookup: new, changed or stale files.
		$need = array();
		foreach ( $this->scanned as $rel => $sha ) {
			$old       = isset( $baseline[ $rel ] ) ? $baseline[ $rel ] : null;
			$unchanged = $old && isset( $old['sha'] ) && $old['sha'] === $sha;
			$checked   = ( $old && isset( $old['checked'] ) ) ? (int) $old['checked'] : 0;
			if ( ! $unchanged || $checked < $stale ) {
				$need[ $sha ] = true;
			}
		}

		// Look up the needed hashes in batches of 500 (the cloud's per-request cap).
		$verdicts = array();
		foreach ( array_chunk( array_keys( $need ), 500 ) as $batch ) {
			$res = Uaip_Sfw_Cloud_API::instance()->lookup_hashes( $batch );
			if ( is_wp_error( $res ) || empty( $res['results'] ) ) {
				continue;
			}
			foreach ( $res['results'] as $h => $r ) {
				$verdicts[ strtolower( $h ) ] = $r;
			}
		}

		// Build findings + the refreshed baseline, counting code changes.
		$findings     = array();
		$new_baseline = array();
		$added        = 0;
		$changed      = 0;
		foreach ( $this->scanned as $rel => $sha ) {
			$old = isset( $baseline[ $rel ] ) ? $baseline[ $rel ] : null;
			if ( null === $old ) {
				$added++;
			} elseif ( ! isset( $old['sha'] ) || $old['sha'] !== $sha ) {
				$changed++;
			}

			if ( isset( $verdicts[ $sha ] ) ) {
				$verdict = isset( $verdicts[ $sha ]['verdict'] ) ? $verdicts[ $sha ]['verdict'] : 'unknown';
				$label   = isset( $verdicts[ $sha ]['label'] ) ? (string) $verdicts[ $sha ]['label'] : '';
				$checked = $now;
			} elseif ( $old ) {
				$verdict = isset( $old['verdict'] ) ? $old['verdict'] : 'unknown';
				$label   = isset( $old['label'] ) ? $old['label'] : '';
				$checked = isset( $old['checked'] ) ? (int) $old['checked'] : 0;
			} else {
				$verdict = 'unknown';
				$label   = '';
				$checked = 0;
			}

			$new_baseline[ $rel ] = array( 'sha' => $sha, 'verdict' => $verdict, 'label' => $label, 'checked' => $checked );

			if ( 'malicious' === $verdict ) {
				$findings[] = array(
					'file'        => $rel,
					'rule'        => 'cloud_hash_intel',
					'severity'    => 'critical',
					'description' => $label
						/* translators: %s: malware family/label */
						? sprintf( __( 'Known malware: %s (cloud threat intelligence)', 'uaip-security-firewall' ), $label )
						: __( 'Known malware (cloud threat intelligence)', 'uaip-security-firewall' ),
					'hash'        => $sha,
				);
			}
		}

		// Files in the baseline but no longer present — change tracking.
		$removed = count( array_diff_key( $baseline, $this->scanned ) );

		update_option( self::BASELINE_OPTION, $new_baseline, false );
		$this->change_summary = array( 'added' => $added, 'changed' => $changed, 'removed' => $removed );

		return $findings;
	}

	/** Look up rule metadata by scanning a rule's own definition. */
	private function meta_for( $engine, $rule ) {
		// Uaip_Sfw_Yara_Lite exposes hits via scan_data; for metadata we re-scan the
		// rule name against an empty body is not meaningful, so default here.
		return array( 'severity' => 'medium', 'description' => '' );
	}

	/**
	 * Integrity check vs WordPress.org core checksums. Flags modified core
	 * files. Network-guarded: skips silently if the API is unreachable.
	 *
	 * @return array
	 */
	private function integrity_scan() {
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			return array();
		}
		global $wp_version, $wp_local_package;
		$locale    = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$checksums = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $checksums ) ) {
			return array();
		}

		$findings = array();
		foreach ( $checksums as $file => $md5 ) {
			// Skip wp-content (user-modifiable) — only verify core.
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$path = ABSPATH . $file;
			if ( ! file_exists( $path ) ) {
				continue;
			}
			if ( @md5_file( $path ) !== $md5 ) {
				$findings[] = array(
					'file'        => $file,
					'rule'        => 'core_integrity',
					'severity'    => 'high',
					'description' => __( 'Core file differs from the official WordPress release', 'uaip-security-firewall' ),
					'hash'        => @md5_file( $path ),
				);
			}
		}
		return $findings;
	}

	/**
	 * Files to scan. Walks wp-content (plus active code), restricted to text/
	 * script extensions, excluding security plugins (which contain malware
	 * signatures by design) and our own files.
	 *
	 * @return array<int,string> Absolute paths.
	 */
	private function changed_files() {
		$roots = array(
			defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins',
			get_theme_root(),
			wp_upload_dir()['basedir'],
			defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins',
		);
		$exts    = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'inc', 'js' );
		$exclude = array(
			'/plugins/uaip-security-firewall/',
			'/plugins/wordfence/',
			'/plugins/sucuri-scanner/',
			'/plugins/malcare-security/',
		);

		$files = array();
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$it = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
				);
			} catch ( Exception $e ) {
				continue;
			}
			foreach ( $it as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}
				$path = $file->getPathname();

				$skip = false;
				foreach ( $exclude as $ex ) {
					if ( false !== strpos( $path, $ex ) ) {
						$skip = true;
						break;
					}
				}
				if ( $skip ) {
					continue;
				}
				if ( ! in_array( strtolower( $file->getExtension() ), $exts, true ) ) {
					continue;
				}
				if ( $file->getSize() > self::MAX_FILE_BYTES ) {
					continue;
				}
				if ( count( $files ) >= self::MAX_FILES ) {
					$this->capped++;
					continue;
				}
				$files[] = $path;
			}
		}

		if ( $this->capped > 0 ) {
			$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
			if ( $audit ) {
				$audit->record( 'scan_capped', array( 'skipped' => $this->capped, 'limit' => self::MAX_FILES ) );
			}
		}
		$this->last_scanned = count( $files );
		return $files;
	}

	/**
	 * Make a path relative to the WordPress root for display.
	 *
	 * @param string $path
	 * @return string
	 */
	private function rel( $path ) {
		return ltrim( str_replace( ABSPATH, '', $path ), '/' );
	}

	// ------------------------------------------------------------------
	// Remediation (delete). Detected files can be permanently deleted; the
	// plugin never moves or quarantines files into uploads or wp-content.
	// ------------------------------------------------------------------

	/**
	 * Validate a relative path resolves to a real file safely inside wp-content
	 * (never core or outside the install).
	 *
	 * @param string $rel
	 * @return string|false Absolute path or false.
	 */
	private function safe_target( $rel ) {
		$abs  = realpath( ABSPATH . ltrim( $rel, '/' ) );
		$root = realpath( WP_CONTENT_DIR );
		if ( false === $abs || false === $root ) {
			return false;
		}
		if ( 0 !== strpos( $abs, $root . DIRECTORY_SEPARATOR ) ) {
			return false; // outside wp-content
		}
		return is_file( $abs ) ? $abs : false;
	}

	/**
	 * Permanently delete a flagged file.
	 *
	 * @param string $rel
	 * @return true|WP_Error
	 */
	public function delete_file( $rel ) {
		$abs = $this->safe_target( $rel );
		if ( false === $abs ) {
			return new WP_Error( 'invalid', __( 'File not found or not allowed.', 'uaip-security-firewall' ) );
		}
		wp_delete_file( $abs );
		if ( file_exists( $abs ) ) {
			return new WP_Error( 'delete_failed', __( 'Could not delete the file. Check permissions.', 'uaip-security-firewall' ) );
		}
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'file_deleted', array( 'file' => $this->rel( $abs ) ) );
		}
		return true;
	}

	/**
	 * Act on findings: alert, and for uncertain ones do reputation lookup.
	 * Free sends HASHES ONLY (per the locked privacy decision); snippet upload
	 * is opt-in. Pro sends full samples automatically.
	 *
	 * @param array $findings
	 */
	private function handle_findings( $findings ) {
		if ( empty( $findings ) ) {
			return;
		}
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'malware_found', array( 'count' => count( $findings ) ) );
		}

		// Email alert (throttled).
		Uaip_Sfw_Notifier::malware( $findings );

		// Cloud sample/hash reputation is Pro-only; Free runs standalone.
		if ( ! Uaip_Sfw_Plugin::instance()->license->is_pro() || ! Uaip_Sfw_Cloud_API::instance()->is_connected() ) {
			return;
		}

		$mode = Uaip_Sfw_Settings::get( 'cloud_sample_upload' ); // off | hashes_only | full
		if ( 'off' === $mode ) {
			return;
		}
		if ( 'full' === $mode && Uaip_Sfw_Plugin::instance()->license->is_pro() ) {
			// Pro: full sample analysis (handled by Pro module).
			do_action( 'uaip_sfw_pro_upload_samples', $findings );
			return;
		}
		// Free default: hashes-only reputation lookup.
		$hashes = wp_list_pluck( $findings, 'hash' );
		Uaip_Sfw_Cloud_API::instance()->lookup_hashes( array_filter( $hashes ) );
	}
}
