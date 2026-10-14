<?php
/**
 * UAIP Security → Activity Log: filters, paging, CSV export, retention.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Activity_Page {

	const SLUG     = 'uaip-sfw-audit';
	const PER_PAGE = 50;

	/** Rows per CSV export. */
	const EXPORT_MAX = 50000;

	/** @var Uaip_Sfw_Audit_Log */
	private $log;

	/**
	 * @param Uaip_Sfw_Audit_Log $log Log.
	 */
	public function __construct( $log ) {
		$this->log = $log;
	}

	public function register_hooks() {
		add_action( 'admin_post_uaip_sfw_activity_export', array( $this, 'export' ) );
	}

	/** @return string Severity class used by the dashboard styles. */
	public static function dot( $severity ) {
		if ( 'critical' === $severity || 'warning' === $severity ) {
			return 'high';
		}
		return 'notice' === $severity ? 'mid' : 'low';
	}

	/**
	 * Filters from the query string.
	 *
	 * @return array
	 */
	private function filters() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only list filters.
		$get = function ( $k ) {
			return isset( $_GET[ $k ] ) ? sanitize_text_field( wp_unslash( $_GET[ $k ] ) ) : '';
		};
		$f = array(
			'category' => sanitize_key( $get( 'cat' ) ),
			'type'     => sanitize_key( $get( 'type' ) ),
			'actor'    => sanitize_user( $get( 'actor' ), true ),
			'ip'       => Uaip_Sfw_IP::valid( $get( 'ip' ) ) ? $get( 'ip' ) : '',
			'search'   => $get( 's' ),
			'from_day' => preg_match( '/^\d{4}-\d{2}-\d{2}$/', $get( 'from' ) ) ? $get( 'from' ) : '',
			'to_day'   => preg_match( '/^\d{4}-\d{2}-\d{2}$/', $get( 'to' ) ) ? $get( 'to' ) : '',
			'page'     => max( 1, absint( $get( 'paged' ) ) ),
		);
		// phpcs:enable
		$f['from'] = $f['from_day'] ? $this->day_ts( $f['from_day'], false ) : 0;
		$f['to']   = $f['to_day'] ? $this->day_ts( $f['to_day'], true ) : 0;
		return $f;
	}

	/**
	 * Start or end of a day in the site's time zone.
	 *
	 * @param string $day Y-m-d.
	 * @param bool   $end End of day.
	 * @return int
	 */
	private function day_ts( $day, $end ) {
		try {
			$d = new DateTimeImmutable( $day . ( $end ? ' 23:59:59' : ' 00:00:00' ), wp_timezone() );
			return $d->getTimestamp();
		} catch ( Exception $e ) {
			return 0;
		}
	}

	/**
	 * Query-string args for links that keep the filters.
	 *
	 * @param array $f Filters.
	 * @return array
	 */
	private function link_args( array $f ) {
		return array_filter(
			array(
				'cat'   => $f['category'],
				'type'  => $f['type'],
				'actor' => $f['actor'],
				'ip'    => $f['ip'],
				's'     => $f['search'],
				'from'  => $f['from_day'],
				'to'    => $f['to_day'],
			),
			'strlen'
		);
	}

	/** Handle clear and retention forms. */
	private function handle_post() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( isset( $_POST['uaip_sfw_clear_audit'] ) && check_admin_referer( 'uaip_sfw_activity' ) ) {
			$removed = $this->log->clear();
			/* translators: %d: number of entries removed */
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( sprintf( _n( 'Activity log cleared (%d entry removed).', 'Activity log cleared (%d entries removed).', $removed, 'uaip-security-firewall' ), $removed ) ) . '</p></div>';
		}
		if ( isset( $_POST['uaip_sfw_retention'] ) && check_admin_referer( 'uaip_sfw_activity' ) ) {
			$days = max( 1, min( 3650, absint( wp_unslash( $_POST['uaip_sfw_retention'] ) ) ) );
			Uaip_Sfw_Settings::update( array( 'audit_retention_days' => $days ) );
			$this->log->prune();
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Retention saved. Older entries were removed.', 'uaip-security-firewall' ) . '</p></div>';
		}
	}

	/** Page body (the admin class prints the wrap and header). */
	public function render_body() {
		$this->handle_post();
		$f   = $this->filters();
		$res = $this->log->query( array_merge( $f, array( 'per_page' => self::PER_PAGE ) ) );

		if ( ! Uaip_Sfw_Audit_Log::enabled() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The activity log is switched off, so no new events are recorded. Turn it on under UAIP Security → Settings.', 'uaip-security-firewall' ) . '</p></div>';
		}

		$this->render_filters( $f );

		echo '<div class="uaip-sfw-card">';
		$base = admin_url( 'admin.php?page=' . self::SLUG );
		echo '<div class="uaip-sfw-activity-bar"><span class="uaip-sfw-activity-count">';
		/* translators: %s: number of entries */
		echo esc_html( sprintf( _n( '%s entry', '%s entries', $res['total'], 'uaip-security-firewall' ), number_format_i18n( $res['total'] ) ) );
		echo '</span>';
		if ( $res['total'] ) {
			$export = wp_nonce_url( add_query_arg( array_merge( array( 'action' => 'uaip_sfw_activity_export' ), $this->link_args( $f ) ), admin_url( 'admin-post.php' ) ), 'uaip_sfw_activity_export' );
			echo '<a class="button" href="' . esc_url( $export ) . '"><span class="dashicons dashicons-download"></span> ' . esc_html__( 'Export CSV', 'uaip-security-firewall' ) . '</a>';
		}
		echo '</div>';

		if ( ! $res['rows'] ) {
			echo '<p class="uaip-sfw-empty">' . esc_html( $this->link_args( $f ) ? __( 'No entries match these filters.', 'uaip-security-firewall' ) : __( 'No events recorded yet.', 'uaip-security-firewall' ) ) . '</p>';
		} else {
			echo '<table class="widefat striped uaip-sfw-table uaip-sfw-activity-table"><thead><tr>';
			foreach ( array( __( 'When', 'uaip-security-firewall' ), __( 'Event', 'uaip-security-firewall' ), __( 'About', 'uaip-security-firewall' ), __( 'Details', 'uaip-security-firewall' ), __( 'By', 'uaip-security-firewall' ), __( 'IP', 'uaip-security-firewall' ) ) as $h ) {
				echo '<th scope="col">' . esc_html( $h ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $res['rows'] as $e ) {
				$filter = function ( $key, $value ) use ( $base ) {
					return esc_url( add_query_arg( $key, rawurlencode( $value ), $base ) );
				};
				echo '<tr>';
				printf(
					'<td><span title="%s">%s</span></td>',
					esc_attr( wp_date( 'Y-m-d H:i:s', $e['ts'] ) ),
					esc_html( $this->when( $e['ts'] ) )
				);
				printf(
					'<td><a class="uaip-sfw-ev-type uaip-sfw-ev-%s" href="%s">%s</a></td>',
					esc_attr( self::dot( $e['severity'] ) ),
					$filter( 'type', $e['type'] ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in the closure.
					esc_html( Uaip_Sfw_Audit_Log::label( $e['type'] ) )
				);
				echo '<td>' . esc_html( $e['object'] ) . '</td>';
				echo '<td class="uaip-sfw-activity-details">' . esc_html( Uaip_Sfw_Audit_Log::details( $e ) ) . '</td>';
				echo '<td>' . ( '' !== $e['actor'] ? '<a href="' . $filter( 'actor', $e['actor'] ) . '">' . esc_html( $e['actor'] ) . '</a>' : '<span class="description">' . esc_html__( 'visitor', 'uaip-security-firewall' ) . '</span>' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in the closure.
				echo '<td>' . ( '' !== $e['ip'] ? '<a href="' . $filter( 'ip', $e['ip'] ) . '"><code>' . esc_html( $e['ip'] ) . '</code></a>' : '' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in the closure.
				echo '</tr>';
			}
			echo '</tbody></table>';
			$pages = (int) ceil( $res['total'] / self::PER_PAGE );
			if ( $pages > 1 ) {
				echo '<div class="tablenav"><div class="tablenav-pages">';
				echo wp_kses_post(
					paginate_links(
						array(
							'base'    => add_query_arg( 'paged', '%#%', add_query_arg( $this->link_args( $f ), $base ) ),
							'format'  => '',
							'current' => $f['page'],
							'total'   => $pages,
						)
					)
				);
				echo '</div></div>';
			}
		}
		echo '</div>';

		if ( current_user_can( 'manage_options' ) ) {
			$this->render_manage();
		}
	}

	/**
	 * @param int $ts Timestamp.
	 * @return string
	 */
	private function when( $ts ) {
		if ( time() - $ts < DAY_IN_SECONDS ) {
			/* translators: %s: human-readable time difference, e.g. "2 minutes" */
			return sprintf( __( '%s ago', 'uaip-security-firewall' ), human_time_diff( $ts ) );
		}
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts );
	}

	/**
	 * @param array $f Filters.
	 */
	private function render_filters( array $f ) {
		echo '<form method="get" class="uaip-sfw-card uaip-sfw-activity-filters">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::SLUG ) . '">';
		echo '<label>' . esc_html__( 'Category', 'uaip-security-firewall' ) . ' <select name="cat"><option value="">' . esc_html__( 'All', 'uaip-security-firewall' ) . '</option>';
		foreach ( Uaip_Sfw_Audit_Log::categories() as $k => $label ) {
			echo '<option value="' . esc_attr( $k ) . '"' . selected( $f['category'], $k, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select></label>';
		echo '<label>' . esc_html__( 'Event', 'uaip-security-firewall' ) . ' <select name="type"><option value="">' . esc_html__( 'All', 'uaip-security-firewall' ) . '</option>';
		$labels = Uaip_Sfw_Audit_Log::labels();
		asort( $labels );
		foreach ( $labels as $k => $label ) {
			echo '<option value="' . esc_attr( $k ) . '"' . selected( $f['type'], $k, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select></label>';
		echo '<label>' . esc_html__( 'User', 'uaip-security-firewall' ) . ' <input type="text" name="actor" size="12" value="' . esc_attr( $f['actor'] ) . '"></label>';
		echo '<label>IP <input type="text" name="ip" size="14" value="' . esc_attr( $f['ip'] ) . '"></label>';
		echo '<label>' . esc_html__( 'From', 'uaip-security-firewall' ) . ' <input type="date" name="from" value="' . esc_attr( $f['from_day'] ) . '"></label>';
		echo '<label>' . esc_html__( 'To', 'uaip-security-firewall' ) . ' <input type="date" name="to" value="' . esc_attr( $f['to_day'] ) . '"></label>';
		echo '<label>' . esc_html__( 'Search', 'uaip-security-firewall' ) . ' <input type="search" name="s" size="16" value="' . esc_attr( $f['search'] ) . '"></label>';
		echo '<button type="submit" class="button button-primary">' . esc_html__( 'Filter', 'uaip-security-firewall' ) . '</button>';
		if ( $this->link_args( $f ) ) {
			echo ' <a class="button-link" href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Reset', 'uaip-security-firewall' ) . '</a>';
		}
		echo '</form>';
	}

	/** Retention and clear. */
	private function render_manage() {
		echo '<div class="uaip-sfw-card uaip-sfw-activity-manage"><h2>' . esc_html__( 'Keep and clear', 'uaip-security-firewall' ) . '</h2>';
		echo '<form method="post" class="uaip-sfw-inline-form">';
		wp_nonce_field( 'uaip_sfw_activity' );
		echo '<label>' . esc_html__( 'Keep entries for', 'uaip-security-firewall' ) . ' <input type="number" name="uaip_sfw_retention" min="1" max="3650" class="small-text" value="' . esc_attr( (string) (int) Uaip_Sfw_Settings::get( 'audit_retention_days', 90 ) ) . '"> ' . esc_html__( 'days', 'uaip-security-firewall' ) . '</label> ';
		echo '<button type="submit" class="button">' . esc_html__( 'Save', 'uaip-security-firewall' ) . '</button></form>';
		/* translators: %s: maximum number of entries */
		echo '<p class="description">' . esc_html( sprintf( __( 'Older entries are removed once a day. The log never keeps more than %s entries.', 'uaip-security-firewall' ), number_format_i18n( Uaip_Sfw_Audit_Log::MAX_ROWS ) ) ) . '</p>';
		echo '<form method="post" data-confirm="' . esc_attr__( 'Delete every entry in the activity log on this site?', 'uaip-security-firewall' ) . '">';
		wp_nonce_field( 'uaip_sfw_activity' );
		echo '<button type="submit" name="uaip_sfw_clear_audit" value="1" class="button button-link-delete">' . esc_html__( 'Clear the log', 'uaip-security-firewall' ) . '</button></form></div>';
	}

	/** Stream matching rows as CSV. */
	public function export() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to export the activity log.', 'uaip-security-firewall' ), 403 );
		}
		check_admin_referer( 'uaip_sfw_activity_export' );
		$f = $this->filters();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="activity-log-' . gmdate( 'Y-m-d' ) . '.csv"' );
		header( 'X-Content-Type-Options: nosniff' );
		// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- streaming to the response, not the file system.
		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, array( 'time_utc', 'event', 'label', 'category', 'severity', 'about', 'details', 'user', 'ip' ) );
		$per = 1000;
		for ( $page = 1; ( $page - 1 ) * $per < self::EXPORT_MAX; $page++ ) {
			$res = $this->log->query( array_merge( $f, array( 'page' => $page, 'per_page' => $per ) ) );
			foreach ( $res['rows'] as $e ) {
				fputcsv(
					$out,
					array_map(
						array( $this, 'csv_cell' ),
						array( gmdate( 'Y-m-d H:i:s', $e['ts'] ), $e['type'], Uaip_Sfw_Audit_Log::label( $e['type'] ), $e['category'], $e['severity'], $e['object'], Uaip_Sfw_Audit_Log::details( $e ), $e['actor'], $e['ip'] )
					)
				);
			}
			if ( count( $res['rows'] ) < $per ) {
				break;
			}
		}
		fclose( $out );
		// phpcs:enable
		exit;
	}

	/**
	 * Stop spreadsheet formula injection.
	 *
	 * @param string $v Value.
	 * @return string
	 */
	public function csv_cell( $v ) {
		$v = (string) $v;
		return ( '' !== $v && false !== strpos( "=+-@\t\r", $v[0] ) ) ? "'" . $v : $v;
	}
}
