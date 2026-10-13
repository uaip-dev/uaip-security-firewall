<?php
/**
 * Malware and integrity scanner (Free).
 *
 * A scan is a resumable job that runs in short steps, driven by WP-Cron and,
 * while the Scan page is open, by the page itself, so it works on any host and
 * never blocks a visitor's request:
 *
 *   1. walk   — list every PHP-type file of the install, folder by folder.
 *   2. check  — new or changed files only (plus a weekly full pass): integrity
 *               against wordpress.org for core and wordpress.org plugins,
 *               unexpected files in core folders, the site root, wp-content and
 *               uploads, and the YARA ruleset (pure PHP, works everywhere).
 *   3. finish — count removed files, resolve fixed findings, alert on new ones.
 *
 * The file baseline and findings live in custom tables (Uaip_Sfw_DB).
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the scanner's own custom tables (baseline + findings); caching does not apply to a work queue.

class Uaip_Sfw_Scanner {

	const JOB_OPTION     = 'uaip_sfw_scan_job';
	const SUMMARY_OPTION = 'uaip_sfw_last_scan_summary';
	const LAST_FULL      = 'uaip_sfw_last_full_scan';
	const LOCK           = 'uaip_sfw_scan_lock';

	/** Bytes read per file; larger files are listed but not content-scanned. */
	const MAX_FILE_BYTES = 3145728;

	/** Files content-checked per database batch. */
	const BATCH = 100;

	/** Re-hash every file at least this often (mtimes can be faked). */
	const FULL_EVERY = WEEK_IN_SECONDS;

	/** A job with no progress for this long is considered dead and restarted. */
	const STALE_AFTER = 30 * MINUTE_IN_SECONDS;

	/** PHP-type extensions worth scanning. */
	const EXTS = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'pht', 'phar', 'inc' );

	/** wp-content files WordPress itself loads (drop-ins); anything else there is unexpected. */
	const DROPINS = array(
		'index.php', 'advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php', 'install.php',
		'maintenance.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php',
		'blog-inactive.php', 'blog-suspended.php',
	);

	/** Plugins whose own signature files would look like malware. */
	const SKIP_PLUGINS = array( 'uaip-security-firewall', 'wordfence', 'sucuri-scanner', 'malcare-security', 'ninjafirewall', 'all-in-one-wp-security-and-firewall', 'better-wp-security', 'shield-security' );

	/** @var Uaip_Sfw_Yara_Lite|null */
	private $yara;

	public function register_hooks() {
		add_action( 'uaip_sfw_scan', array( $this, 'scheduled_start' ) );
		add_action( 'uaip_sfw_scan_step', array( $this, 'cron_step' ) );
		if ( ! wp_next_scheduled( 'uaip_sfw_scan' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'uaip_sfw_scan' );
		}
	}

	// ------------------------------------------------------------------
	// Job control
	// ------------------------------------------------------------------

	/** Daily cron: start a scan unless one is running. */
	public function scheduled_start() {
		$this->start();
	}

	/** Cron continuation of a running scan. */
	public function cron_step() {
		$this->step( 20 );
	}

	/**
	 * Start a scan.
	 *
	 * @param bool|null $full Force a full re-hash (null = automatic, weekly).
	 * @return bool False when a scan is already running.
	 */
	public function start( $full = null ) {
		if ( $this->is_running() ) {
			return false;
		}
		Uaip_Sfw_DB::maybe_upgrade();
		if ( null === $full ) {
			$full = ( time() - (int) get_option( self::LAST_FULL, 0 ) ) > self::FULL_EVERY;
		}
		$roots = array( wp_normalize_path( untrailingslashit( ABSPATH ) ) );
		foreach ( array( WP_CONTENT_DIR, WP_PLUGIN_DIR ) as $dir ) {
			$dir = wp_normalize_path( untrailingslashit( $dir ) );
			if ( 0 !== strpos( $dir . '/', $roots[0] . '/' ) ) {
				$roots[] = $dir; // Content or plugins moved outside the WordPress folder.
			}
		}
		$job = array(
			'id'            => time(),
			'started'       => time(),
			'progress_at'   => time(),
			'phase'         => 'walk',
			'queue'         => $roots,
			'full'          => (bool) $full,
			'first'         => ! get_option( self::SUMMARY_OPTION ),
			'dirs'          => 0,
			'files'         => 0,
			'to_check'      => 0,
			'checked'       => 0,
			'added'         => 0,
			'changed'       => 0,
			'new_findings'  => array(),
			'rules_version' => $this->rules_version(),
		);
		update_option( self::JOB_OPTION, $job, false );
		wp_schedule_single_event( time(), 'uaip_sfw_scan_step' );
		return true;
	}

	/** @return bool */
	public function is_running() {
		$job = get_option( self::JOB_OPTION );
		return is_array( $job ) && ( time() - (int) $job['progress_at'] ) < self::STALE_AFTER;
	}

	/**
	 * Run the scan for up to $budget seconds.
	 *
	 * @param int $budget Seconds.
	 * @return array Progress (see progress()).
	 */
	public function step( $budget = 10 ) {
		$job = get_option( self::JOB_OPTION );
		if ( ! is_array( $job ) ) {
			return $this->progress();
		}
		// One step at a time (cron and the Scan page may both try).
		if ( ! add_option( self::LOCK, time(), '', false ) ) {
			if ( time() - (int) get_option( self::LOCK ) < 120 ) {
				return $this->progress();
			}
			update_option( self::LOCK, time(), false );
		}
		$deadline = microtime( true ) + max( 2, (int) $budget );
		$limit    = (int) ini_get( 'max_execution_time' );
		if ( $limit > 0 ) {
			$deadline = min( $deadline, microtime( true ) + max( 2, $limit - 10 ) );
		}

		try {
			while ( microtime( true ) < $deadline && 'done' !== $job['phase'] ) {
				if ( 'walk' === $job['phase'] ) {
					$job = $this->walk( $job, $deadline );
				} elseif ( 'check' === $job['phase'] ) {
					$job = $this->check( $job, $deadline );
				} elseif ( 'finish' === $job['phase'] ) {
					$job = $this->finish( $job );
				}
				$job['progress_at'] = time();
			}
		} catch ( Exception $e ) {
			$job['progress_at'] = time(); // Keep going next step; one bad file must not stop the scan.
		}

		if ( 'done' === $job['phase'] ) {
			delete_option( self::JOB_OPTION );
		} else {
			update_option( self::JOB_OPTION, $job, false );
			if ( ! wp_next_scheduled( 'uaip_sfw_scan_step' ) ) {
				wp_schedule_single_event( time() + 5, 'uaip_sfw_scan_step' );
			}
		}
		delete_option( self::LOCK );
		return $this->progress();
	}

	/**
	 * Progress for the Scan page.
	 *
	 * @return array{running:bool,phase:string,percent:int,files:int,checked:int,to_check:int}
	 */
	public function progress() {
		$job = get_option( self::JOB_OPTION );
		if ( ! is_array( $job ) ) {
			return array(
				'running'  => false,
				'phase'    => 'done',
				'percent'  => 100,
				'files'    => 0,
				'checked'  => 0,
				'to_check' => 0,
			);
		}
		// Walking is roughly the first fifth of the work.
		$percent = 'walk' === $job['phase'] ? min( 19, (int) $job['dirs'] / 50 ) : 20 + ( $job['to_check'] ? (int) floor( 79 * $job['checked'] / max( 1, $job['to_check'] ) ) : 79 );
		return array(
			'running'  => true,
			'phase'    => (string) $job['phase'],
			'percent'  => (int) min( 99, $percent ),
			'files'    => (int) $job['files'],
			'checked'  => (int) $job['checked'],
			'to_check' => (int) $job['to_check'],
		);
	}

	// ------------------------------------------------------------------
	// Phase 1: walk
	// ------------------------------------------------------------------

	/**
	 * List folders breadth-first and record PHP-type files in the baseline.
	 *
	 * @param array $job      Job.
	 * @param float $deadline microtime() deadline.
	 * @return array Job.
	 */
	private function walk( array $job, $deadline ) {
		$batch = array();
		while ( $job['queue'] && microtime( true ) < $deadline ) {
			$dir     = array_shift( $job['queue'] );
			$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable folders are skipped.
			++$job['dirs'];
			if ( false === $entries ) {
				continue;
			}
			foreach ( $entries as $name ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$path = $dir . '/' . $name;
				if ( is_link( $path ) ) {
					continue; // Never follow links (loops, other sites).
				}
				if ( is_dir( $path ) ) {
					if ( ! $this->skip_dir( $path, $name ) ) {
						$job['queue'][] = $path;
					}
					continue;
				}
				$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
				if ( in_array( $ext, self::EXTS, true ) ) {
					$batch[] = $path;
					if ( count( $batch ) >= 500 ) {
						$job = $this->record_files( $job, $batch );
						$batch = array();
					}
				}
			}
		}
		if ( $batch ) {
			$job = $this->record_files( $job, $batch );
		}
		if ( ! $job['queue'] ) {
			global $wpdb;
			$table           = Uaip_Sfw_DB::files();
			$job['to_check'] = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE seen_run = %d AND dirty = 1', $table, $job['id'] ) );
			$job['phase']    = 'check';
		}
		return $job;
	}

	/**
	 * Whether to skip a folder.
	 *
	 * @param string $path Absolute path.
	 * @param string $name Folder name.
	 * @return bool
	 */
	private function skip_dir( $path, $name ) {
		if ( in_array( $name, array( '.git', '.svn', 'node_modules' ), true ) ) {
			return true;
		}
		$plugins = wp_normalize_path( untrailingslashit( WP_PLUGIN_DIR ) );
		if ( dirname( $path ) === $plugins && in_array( $name, self::SKIP_PLUGINS, true ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Add/refresh baseline rows for a batch of files. Unchanged files only get
	 * their "seen" mark; new and changed ones are queued for checking.
	 *
	 * @param array    $job   Job.
	 * @param string[] $paths Absolute paths.
	 * @return array Job.
	 */
	private function record_files( array $job, array $paths ) {
		global $wpdb;
		$table = Uaip_Sfw_DB::files();
		$rows  = array();
		foreach ( $paths as $path ) {
			$rel                  = $this->rel( $path );
			$rows[ sha1( $rel ) ] = array(
				'rel'   => $rel,
				'size'  => (int) @filesize( $path ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- vanished files read as 0.
				'mtime' => (int) @filemtime( $path ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			);
		}
		$hashes       = array_keys( $rows );
		$placeholders = implode( ',', array_fill( 0, count( $hashes ), '%s' ) );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $placeholders is a list of %s placeholders, one per hash.
		$existing = $wpdb->get_results( $wpdb->prepare( "SELECT path_hash, size, mtime, rules_version, scanned_at FROM %i WHERE path_hash IN ({$placeholders})", array_merge( array( $table ), $hashes ) ), OBJECT_K );

		$unchanged = array();
		foreach ( $rows as $hash => $row ) {
			$old = isset( $existing[ $hash ] ) ? $existing[ $hash ] : null;
			++$job['files'];
			if ( $old && ! $job['full'] && (int) $old->size === $row['size'] && (int) $old->mtime === $row['mtime']
				&& $old->rules_version === $job['rules_version'] && (int) $old->scanned_at > 0 ) {
				$unchanged[] = $hash;
				continue;
			}
			if ( $old ) {
				$wpdb->update(
					$table,
					array( 'size' => $row['size'], 'mtime' => $row['mtime'], 'seen_run' => $job['id'], 'dirty' => 1 ),
					array( 'path_hash' => $hash ),
					array( '%d', '%d', '%d', '%d' ),
					array( '%s' )
				);
			} else {
				$wpdb->insert(
					$table,
					array(
						'path_hash' => $hash,
						'path'      => $row['rel'],
						'area'      => $this->area( $row['rel'] ),
						'size'      => $row['size'],
						'mtime'     => $row['mtime'],
						'seen_run'  => $job['id'],
						'dirty'     => 1,
						'is_new'    => 1,
					),
					array( '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d' )
				);
			}
		}
		if ( $unchanged ) {
			$in = implode( ',', array_fill( 0, count( $unchanged ), '%s' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- $in is a list of %s placeholders, one per hash; the values are passed as one merged array.
			$wpdb->query( $wpdb->prepare( "UPDATE %i SET seen_run = %d, dirty = 0 WHERE path_hash IN ({$in})", array_merge( array( $table, $job['id'] ), $unchanged ) ) );
		}
		return $job;
	}

	// ------------------------------------------------------------------
	// Phase 2: check
	// ------------------------------------------------------------------

	/**
	 * Check queued files in batches until the deadline.
	 *
	 * @param array $job      Job.
	 * @param float $deadline microtime() deadline.
	 * @return array Job.
	 */
	private function check( array $job, $deadline ) {
		global $wpdb;
		$table = Uaip_Sfw_DB::files();
		while ( microtime( true ) < $deadline ) {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT path_hash, path, area, size, sha256, is_new FROM %i WHERE seen_run = %d AND dirty = 1 LIMIT %d', $table, $job['id'], self::BATCH ) );
			if ( ! $rows ) {
				$job['phase'] = 'finish';
				return $job;
			}
			foreach ( $rows as $row ) {
				$job = $this->check_file( $job, $row );
				++$job['checked'];
				if ( microtime( true ) >= $deadline ) {
					break;
				}
			}
		}
		return $job;
	}

	/**
	 * Integrity + content checks for one file.
	 *
	 * @param array  $job Job.
	 * @param object $row Baseline row.
	 * @return array Job.
	 */
	private function check_file( array $job, $row ) {
		global $wpdb;
		$abs  = $this->abs( $row->path );
		$done = array(
			'dirty'         => 0,
			'is_new'        => 0,
			'scanned_at'    => time(),
			'scanned_run'   => $job['id'],
			'rules_version' => $job['rules_version'],
		);
		$data = is_file( $abs ) && (int) $row->size <= self::MAX_FILE_BYTES ? @file_get_contents( $abs ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file read for scanning.
		if ( false === $data ) {
			$wpdb->update( Uaip_Sfw_DB::files(), $done, array( 'path_hash' => $row->path_hash ) );
			return $job;
		}
		$sha         = hash( 'sha256', $data );
		$done['sha256'] = $sha;
		if ( (int) $row->is_new ) {
			++$job['added'];
		} elseif ( '' !== $row->sha256 && $row->sha256 !== $sha ) {
			++$job['changed'];
		}

		$official = false;
		$findings = $this->integrity_findings( $row->path, $row->area, md5( $data ), $official );
		if ( ! $official && Uaip_Sfw_Settings::get( 'scan_yara_enabled' ) ) {
			foreach ( $this->yara()->scan_data( $data ) as $hit ) {
				$findings[] = array(
					'rule'        => (string) $hit['rule'],
					'kind'        => 'malware',
					'severity'    => isset( $hit['severity'] ) ? (string) $hit['severity'] : 'medium',
					'description' => isset( $hit['description'] ) ? (string) $hit['description'] : '',
					'fix'         => $this->can_delete( $row->path ) ? 'delete' : '',
				);
			}
		}
		/**
		 * Filters the findings for one scanned file (e.g. the Pro ClamAV module).
		 *
		 * @param array  $findings Findings (rule, kind, severity, description, fix).
		 * @param string $abs      Absolute path.
		 * @param string $data     File contents.
		 * @param bool   $official Whether it is an unmodified official file.
		 */
		$findings = (array) apply_filters( 'uaip_sfw_file_findings', $findings, $abs, $data, $official );
		foreach ( $findings as $f ) {
			if ( $this->save_finding( $job['id'], $row->path, $sha, $f ) ) {
				$job['new_findings'][] = array(
					'file'        => $row->path,
					'rule'        => $f['rule'],
					'severity'    => $f['severity'],
					'description' => $f['description'],
				);
			}
		}
		$wpdb->update( Uaip_Sfw_DB::files(), $done, array( 'path_hash' => $row->path_hash ) );
		return $job;
	}

	/**
	 * Integrity findings for a file. Sets $official when the file is an
	 * unmodified official core/plugin file (no content scan needed).
	 *
	 * @param string $rel      Stored path.
	 * @param string $area     Area.
	 * @param string $md5      File md5.
	 * @param bool   $official Out: official and unmodified.
	 * @return array Findings.
	 */
	private function integrity_findings( $rel, $area, $md5, &$official ) {
		$out  = array();
		$core = Uaip_Sfw_Integrity::core();
		$base = basename( $rel );

		if ( is_array( $core ) && isset( $core[ $rel ] ) ) {
			if ( strtolower( $core[ $rel ] ) === $md5 ) {
				$official = true;
				return $out;
			}
			$out[] = $this->make( 'core_modified', 'integrity', 'high', __( 'This WordPress core file differs from the official release.', 'uaip-security-firewall' ), 'repair' );
			return $out;
		}

		switch ( $area ) {
			case 'core':
				if ( is_array( $core ) ) {
					$out[] = $this->make( 'core_unknown', 'unknown', 'high', __( 'This file is not part of WordPress but sits in a core folder (wp-admin or wp-includes).', 'uaip-security-firewall' ), 'delete' );
				}
				break;
			case 'root':
				if ( is_array( $core ) && 'wp-config.php' !== $base ) {
					$out[] = $this->make( 'root_unknown', 'unknown', 'medium', __( 'Unexpected PHP file in the site root. Check that you or a plugin put it there.', 'uaip-security-firewall' ), 'delete' );
				}
				break;
			case 'content':
				if ( dirname( $this->abs( $rel ) ) === wp_normalize_path( untrailingslashit( WP_CONTENT_DIR ) ) && ! in_array( $base, self::DROPINS, true ) ) {
					$out[] = $this->make( 'content_unknown', 'unknown', 'medium', __( 'Unexpected PHP file directly in wp-content (not a WordPress drop-in).', 'uaip-security-firewall' ), 'delete' );
				}
				break;
			case 'uploads':
				$out[] = $this->make( 'uploads_php', 'suspicious', 'high', __( 'PHP file in the uploads folder. Uploads should only contain media; PHP here is a common sign of a backdoor.', 'uaip-security-firewall' ), 'delete' );
				break;
			case 'plugin':
				$plugin = $this->plugin_of( $rel );
				if ( $plugin ) {
					$sums = Uaip_Sfw_Integrity::plugin( $plugin['slug'], $plugin['version'] );
					if ( is_array( $sums ) ) {
						if ( isset( $sums[ $plugin['file'] ] ) ) {
							if ( in_array( $md5, $sums[ $plugin['file'] ], true ) ) {
								$official = true;
								return $out;
							}
							$out[] = $this->make( 'plugin_modified', 'integrity', 'high', __( 'This plugin file differs from the official wordpress.org release.', 'uaip-security-firewall' ), 'repair' );
						} else {
							$out[] = $this->make( 'plugin_unknown', 'unknown', 'medium', __( 'This file is not part of the official wordpress.org release of the plugin.', 'uaip-security-firewall' ), 'delete' );
						}
					}
				}
				break;
		}
		return $out;
	}

	/**
	 * @param string $rule Rule.
	 * @param string $kind Kind.
	 * @param string $sev  Severity.
	 * @param string $desc Description.
	 * @param string $fix  repair|delete|''.
	 * @return array
	 */
	private function make( $rule, $kind, $sev, $desc, $fix ) {
		return array(
			'rule'        => $rule,
			'kind'        => $kind,
			'severity'    => $sev,
			'description' => $desc,
			'fix'         => $fix,
		);
	}

	/**
	 * Store a finding. Returns true when it is new (or came back) and open.
	 *
	 * @param int    $run  Job id.
	 * @param string $rel  Path.
	 * @param string $sha  File SHA-256.
	 * @param array  $f    Finding.
	 * @return bool
	 */
	private function save_finding( $run, $rel, $sha, array $f ) {
		global $wpdb;
		$table = Uaip_Sfw_DB::findings();
		$fkey  = sha1( $rel . '|' . $f['rule'] );
		$old = $wpdb->get_row( $wpdb->prepare( 'SELECT id, status, file_hash FROM %i WHERE fkey = %s', $table, $fkey ) );
		$now = time();
		if ( ! $old ) {
			$wpdb->insert(
				$table,
				array(
					'fkey'        => $fkey,
					'path_hash'   => sha1( $rel ),
					'path'        => $rel,
					'rule'        => $f['rule'],
					'kind'        => $f['kind'],
					'severity'    => $f['severity'],
					'description' => $f['description'],
					'file_hash'   => $sha,
					'fix'         => $f['fix'],
					'status'      => 'open',
					'first_seen'  => $now,
					'last_seen'   => $now,
					'seen_run'    => $run,
				)
			);
			return true;
		}
		// An ignored finding stays ignored only while the file is unchanged.
		$status = ( 'ignored' === $old->status && $old->file_hash === $sha ) ? 'ignored' : 'open';
		$wpdb->update(
			$table,
			array(
				'severity'    => $f['severity'],
				'description' => $f['description'],
				'file_hash'   => $sha,
				'fix'         => $f['fix'],
				'status'      => $status,
				'last_seen'   => $now,
				'seen_run'    => $run,
			),
			array( 'id' => (int) $old->id )
		);
		return 'open' === $status && 'open' !== $old->status;
	}

	// ------------------------------------------------------------------
	// Phase 3: finish
	// ------------------------------------------------------------------

	/**
	 * @param array $job Job.
	 * @return array Job (phase done).
	 */
	private function finish( array $job ) {
		global $wpdb;
		$files = Uaip_Sfw_DB::files();
		$finds = Uaip_Sfw_DB::findings();
		$removed = (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE seen_run <> %d', $files, $job['id'] ) );
		// Findings resolve when their file was re-checked without the finding, or is gone.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'resolved' WHERE status IN ('open','ignored') AND seen_run <> %d
				AND ( path_hash IN ( SELECT path_hash FROM %i WHERE scanned_run = %d ) OR path_hash NOT IN ( SELECT path_hash FROM %i ) )",
				$finds,
				$job['id'],
				$files,
				$job['id'],
				$files
			)
		);
		$open  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'open'", $finds ) );
		$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $files ) );

		$summary = array(
			'ts'       => time(),
			'engine'   => 'php-lite',
			'findings' => $open,
			'scanned'  => (int) $job['checked'],
			'files'    => $total,
			'capped'   => 0,
			'full'     => (bool) $job['full'],
			'baseline' => (bool) $job['first'],
			'duration' => time() - (int) $job['started'],
			'changes'  => $job['first']
				? array( 'added' => 0, 'changed' => 0, 'removed' => 0 )
				: array( 'added' => (int) $job['added'], 'changed' => (int) $job['changed'], 'removed' => $removed ),
			'tier'     => Uaip_Sfw_Plugin::instance()->license->tier(),
		);
		update_option( self::SUMMARY_OPTION, $summary, false );
		if ( $job['full'] ) {
			update_option( self::LAST_FULL, time(), false );
		}

		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'scan_completed', array( 'files' => $total, 'checked' => (int) $job['checked'], 'open' => $open ) );
		}
		if ( $job['new_findings'] ) {
			if ( $audit ) {
				$audit->record( 'malware_found', array( 'count' => count( $job['new_findings'] ) ) );
			}
			Uaip_Sfw_Notifier::malware( $job['new_findings'] );
		}
		$job['phase'] = 'done';
		return $job;
	}

	// ------------------------------------------------------------------
	// Findings and actions (Scan page)
	// ------------------------------------------------------------------

	/**
	 * Findings by status.
	 *
	 * @param string $status open|ignored|resolved.
	 * @param int    $limit  Max rows.
	 * @return array<int,object>
	 */
	public function findings( $status = 'open', $limit = 500 ) {
		global $wpdb;
		if ( get_option( Uaip_Sfw_DB::VERSION_OPTION ) !== Uaip_Sfw_DB::VERSION ) {
			return array();
		}
		$table = Uaip_Sfw_DB::findings();
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM %i WHERE status = %s ORDER BY FIELD(severity,'critical','high','medium','low'), last_seen DESC LIMIT %d", $table, $status, $limit ) );
	}

	/**
	 * Act on a finding.
	 *
	 * @param int    $id     Finding id.
	 * @param string $action repair|delete|ignore|unignore.
	 * @return true|WP_Error
	 */
	public function act( $id, $action ) {
		global $wpdb;
		$table = Uaip_Sfw_DB::findings();
		$f = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE id = %d', $table, $id ) );
		if ( ! $f ) {
			return new WP_Error( 'uaip_sfw_finding', __( 'That finding no longer exists. Run a new scan.', 'uaip-security-firewall' ) );
		}
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		switch ( $action ) {
			case 'ignore':
			case 'unignore':
				$wpdb->update( $table, array( 'status' => 'ignore' === $action ? 'ignored' : 'open' ), array( 'id' => (int) $f->id ) );
				return true;
			case 'repair':
				if ( 'repair' !== $f->fix ) {
					break;
				}
				$res = Uaip_Sfw_Integrity::repair( $f->path );
				if ( true === $res ) {
					$this->mark_path_resolved( $f->path );
					if ( $audit ) {
						$audit->record( 'file_repaired', array( 'file' => $f->path ) );
					}
				}
				return $res;
			case 'delete':
				if ( 'delete' !== $f->fix ) {
					break;
				}
				$res = $this->delete_file( $f->path );
				if ( true === $res ) {
					$this->mark_path_resolved( $f->path );
				}
				return $res;
		}
		return new WP_Error( 'uaip_sfw_action', __( 'That action is not available for this finding.', 'uaip-security-firewall' ) );
	}

	/**
	 * @param string $rel Path.
	 */
	private function mark_path_resolved( $rel ) {
		global $wpdb;
		$wpdb->update( Uaip_Sfw_DB::findings(), array( 'status' => 'resolved' ), array( 'path_hash' => sha1( $rel ) ) );
		$wpdb->update( Uaip_Sfw_DB::files(), array( 'dirty' => 1, 'scanned_at' => 0 ), array( 'path_hash' => sha1( $rel ) ) );
		$summary = get_option( self::SUMMARY_OPTION );
		if ( is_array( $summary ) ) {
			$summary['findings'] = count( $this->findings( 'open' ) );
			update_option( self::SUMMARY_OPTION, $summary, false );
		}
	}

	/**
	 * Whether a file may be deleted: inside the install, never wp-config.php, the
	 * root index.php or an official core file (those are repaired instead).
	 *
	 * @param string $rel Stored path.
	 * @return bool
	 */
	private function can_delete( $rel ) {
		$abs = $this->abs( $rel );
		if ( in_array( $rel, array( 'wp-config.php', 'index.php', 'wp-settings.php', 'wp-load.php', 'wp-blog-header.php' ), true ) ) {
			return false;
		}
		$core = Uaip_Sfw_Integrity::core();
		if ( is_array( $core ) && isset( $core[ $rel ] ) ) {
			return false;
		}
		return false !== $this->safe_target( $abs );
	}

	/**
	 * Resolve a path to a real file inside the WordPress folder or content folder.
	 *
	 * @param string $abs Absolute path.
	 * @return string|false
	 */
	private function safe_target( $abs ) {
		$real = realpath( $abs );
		if ( false === $real || ! is_file( $real ) ) {
			return false;
		}
		$real = wp_normalize_path( $real );
		foreach ( array( ABSPATH, WP_CONTENT_DIR ) as $root ) {
			$root = realpath( $root );
			if ( false !== $root && 0 === strpos( $real, trailingslashit( wp_normalize_path( $root ) ) ) ) {
				return $real;
			}
		}
		return false;
	}

	/**
	 * Permanently delete a flagged file.
	 *
	 * @param string $rel Stored path.
	 * @return true|WP_Error
	 */
	public function delete_file( $rel ) {
		if ( ! $this->can_delete( $rel ) ) {
			return new WP_Error( 'uaip_sfw_delete', __( 'This file cannot be deleted from here.', 'uaip-security-firewall' ) );
		}
		$abs = $this->safe_target( $this->abs( $rel ) );
		wp_delete_file( $abs );
		if ( file_exists( $abs ) ) {
			return new WP_Error( 'uaip_sfw_delete_failed', __( 'Could not delete the file. Check permissions.', 'uaip-security-firewall' ) );
		}
		$audit = Uaip_Sfw_Plugin::instance()->module( 'audit_log' );
		if ( $audit ) {
			$audit->record( 'file_deleted', array( 'file' => $rel ) );
		}
		return true;
	}

	// ------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------

	/** @return Uaip_Sfw_Yara_Lite */
	private function yara() {
		if ( null === $this->yara ) {
			$this->yara = new Uaip_Sfw_Yara_Lite();
			$this->yara->load_dir( UAIP_SFW_DIR . 'assets/yara-rules' );
		}
		return $this->yara;
	}

	/** @return string Changes when the rules or this scanner change (forces a re-check). */
	private function rules_version() {
		$hash = '';
		foreach ( (array) glob( UAIP_SFW_DIR . 'assets/yara-rules/*.txt' ) as $file ) {
			$hash .= (string) @md5_file( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		return substr( md5( UAIP_SFW_VERSION . '|' . $hash ), 0, 16 );
	}

	/** @return string 'php-lite' (the pure-PHP YARA engine; no external binary). */
	public function yara_engine() {
		return 'php-lite';
	}

	/**
	 * Stored path: relative to the WordPress folder when inside it.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	private function rel( $abs ) {
		$abs  = wp_normalize_path( $abs );
		$root = wp_normalize_path( trailingslashit( ABSPATH ) );
		return 0 === strpos( $abs, $root ) ? substr( $abs, strlen( $root ) ) : $abs;
	}

	/**
	 * @param string $rel Stored path.
	 * @return string Absolute path.
	 */
	private function abs( $rel ) {
		return ( '/' === substr( $rel, 0, 1 ) || preg_match( '#^[a-z]:/#i', $rel ) ) ? $rel : wp_normalize_path( ABSPATH . $rel );
	}

	/**
	 * Which part of the install a file belongs to.
	 *
	 * @param string $rel Stored path.
	 * @return string core|root|plugin|mu|theme|uploads|content|other
	 */
	private function area( $rel ) {
		$abs = $this->abs( $rel );
		$map = array(
			'uploads' => wp_upload_dir( null, false )['basedir'],
			'plugin'  => WP_PLUGIN_DIR,
			'mu'      => WPMU_PLUGIN_DIR,
			'theme'   => get_theme_root(),
			'content' => WP_CONTENT_DIR,
		);
		foreach ( $map as $area => $dir ) {
			if ( 0 === strpos( $abs, trailingslashit( wp_normalize_path( $dir ) ) ) ) {
				return $area;
			}
		}
		if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
			return 'core';
		}
		return false === strpos( $rel, '/' ) ? 'root' : 'other';
	}

	/**
	 * Plugin slug/version/inner path of a file in the plugins folder.
	 *
	 * @param string $rel Stored path.
	 * @return array{slug:string,version:string,file:string}|null
	 */
	private function plugin_of( $rel ) {
		static $versions = null;
		$base  = trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) );
		$abs   = $this->abs( $rel );
		$inner = substr( $abs, strlen( $base ) );
		$slash = strpos( $inner, '/' );
		if ( false === $slash ) {
			return null;
		}
		if ( null === $versions ) {
			$versions = Uaip_Sfw_Integrity::plugins();
		}
		$slug = substr( $inner, 0, $slash );
		return isset( $versions[ $slug ] ) ? array( 'slug' => $slug, 'version' => $versions[ $slug ], 'file' => substr( $inner, $slash + 1 ) ) : null;
	}
}
