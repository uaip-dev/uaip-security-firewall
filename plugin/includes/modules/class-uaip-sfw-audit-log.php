<?php
/**
 * Activity log: security-relevant events in the plugin's own table, with a
 * retention period, filters and CSV export (see Uaip_Sfw_Activity_Page).
 *
 * Pro also mirrors new rows to the cloud through the heartbeat.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Audit_Log {

	/** Option used before the table existed (imported once, then removed). */
	const LEGACY_OPTION = 'uaip_sfw_audit_events';

	/** Daily clean-up hook. */
	const PRUNE_HOOK = 'uaip_sfw_activity_prune';

	/** Hard cap so a long attack cannot grow the table without limit. */
	const MAX_ROWS = 100000;

	/** Site options worth logging when they change. */
	const WATCHED_OPTIONS = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'blog_public', 'blogname' );

	public function register_hooks() {
		add_action( self::PRUNE_HOOK, array( $this, 'prune' ) );
		if ( ! wp_next_scheduled( self::PRUNE_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::PRUNE_HOOK );
		}
		if ( ! self::enabled() ) {
			return;
		}

		// Sign-in.
		add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		add_action( 'wp_logout', array( $this, 'on_logout' ) );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 2 );

		// Users.
		add_action( 'user_register', array( $this, 'on_user_register' ) );
		add_action( 'delete_user', array( $this, 'on_delete_user' ) );
		add_action( 'set_user_role', array( $this, 'on_role' ), 10, 3 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );
		add_action( 'after_password_reset', array( $this, 'on_password_reset' ) );
		add_action( 'wp_create_application_password', array( $this, 'on_app_password_created' ), 10, 2 );
		add_action( 'wp_delete_application_password', array( $this, 'on_app_password_deleted' ), 10, 2 );

		// Plugins, themes, core.
		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ) );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ) );
		add_action( 'deleted_plugin', array( $this, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'switch_theme', array( $this, 'on_theme_switched' ) );
		add_action( 'deleted_theme', array( $this, 'on_theme_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrade' ), 10, 2 );
		add_action( '_core_updated_successfully', array( $this, 'on_core_updated' ) );

		// Settings.
		add_action( 'updated_option', array( $this, 'on_option' ), 10, 3 );
	}

	/** @return bool Logging switched on. */
	public static function enabled() {
		return (bool) Uaip_Sfw_Settings::get( 'audit_log_enabled' );
	}

	// ------------------------------------------------------------------
	// Event catalogue
	// ------------------------------------------------------------------

	/**
	 * Category and severity (info, notice, warning, critical) of each event.
	 * Untranslated, so the firewall can log before init.
	 */
	const TYPES = array(
		'login_success'            => array( 'login', 'info' ),
		'logout'                   => array( 'login', 'info' ),
		'login_failed'             => array( 'login', 'notice' ),
		'twofa_failed'             => array( 'login', 'notice' ),
		'recovery_code_used'       => array( 'login', 'warning' ),
		'breached_password_block'  => array( 'login', 'warning' ),
		'twofa_enabled'            => array( 'users', 'info' ),
		'twofa_disabled'           => array( 'users', 'warning' ),
		'user_created'             => array( 'users', 'notice' ),
		'user_deleted'             => array( 'users', 'warning' ),
		'user_role_changed'        => array( 'users', 'warning' ),
		'password_changed'         => array( 'users', 'info' ),
		'password_reset'           => array( 'users', 'notice' ),
		'email_changed'            => array( 'users', 'notice' ),
		'app_password_created'     => array( 'users', 'notice' ),
		'app_password_deleted'     => array( 'users', 'info' ),
		'plugin_installed'         => array( 'software', 'notice' ),
		'plugin_updated'           => array( 'software', 'info' ),
		'plugin_activated'         => array( 'software', 'notice' ),
		'plugin_deactivated'       => array( 'software', 'notice' ),
		'plugin_deleted'           => array( 'software', 'notice' ),
		'theme_installed'          => array( 'software', 'notice' ),
		'theme_updated'            => array( 'software', 'info' ),
		'theme_switched'           => array( 'software', 'notice' ),
		'theme_deleted'            => array( 'software', 'notice' ),
		'core_updated'             => array( 'software', 'info' ),
		'option_changed'           => array( 'settings', 'notice' ),
		'plugin_settings_changed'  => array( 'settings', 'notice' ),
		'attack_blocked'           => array( 'firewall', 'warning' ),
		'attack_detected'          => array( 'firewall', 'notice' ),
		'scan_completed'           => array( 'scanner', 'info' ),
		'malware_found'            => array( 'scanner', 'critical' ),
		'file_repaired'            => array( 'scanner', 'notice' ),
		'file_deleted'             => array( 'scanner', 'notice' ),
	);

	/** @return array<string,string> Event labels. */
	public static function labels() {
		return array(
			'login_success'            => __( 'Signed in', 'uaip-security-firewall' ),
			'logout'                   => __( 'Signed out', 'uaip-security-firewall' ),
			'login_failed'             => __( 'Failed sign-in', 'uaip-security-firewall' ),
			'twofa_failed'             => __( 'Wrong two-step code', 'uaip-security-firewall' ),
			'recovery_code_used'       => __( 'Recovery code used', 'uaip-security-firewall' ),
			'breached_password_block'  => __( 'Common password refused', 'uaip-security-firewall' ),
			'twofa_enabled'            => __( 'Two-step method added', 'uaip-security-firewall' ),
			'twofa_disabled'           => __( 'Two-step method removed', 'uaip-security-firewall' ),
			'user_created'             => __( 'User created', 'uaip-security-firewall' ),
			'user_deleted'             => __( 'User deleted', 'uaip-security-firewall' ),
			'user_role_changed'        => __( 'User role changed', 'uaip-security-firewall' ),
			'password_changed'         => __( 'Password changed', 'uaip-security-firewall' ),
			'password_reset'           => __( 'Password reset', 'uaip-security-firewall' ),
			'email_changed'            => __( 'Email address changed', 'uaip-security-firewall' ),
			'app_password_created'     => __( 'Application password created', 'uaip-security-firewall' ),
			'app_password_deleted'     => __( 'Application password deleted', 'uaip-security-firewall' ),
			'plugin_installed'         => __( 'Plugin installed', 'uaip-security-firewall' ),
			'plugin_updated'           => __( 'Plugin updated', 'uaip-security-firewall' ),
			'plugin_activated'         => __( 'Plugin activated', 'uaip-security-firewall' ),
			'plugin_deactivated'       => __( 'Plugin deactivated', 'uaip-security-firewall' ),
			'plugin_deleted'           => __( 'Plugin deleted', 'uaip-security-firewall' ),
			'theme_installed'          => __( 'Theme installed', 'uaip-security-firewall' ),
			'theme_updated'            => __( 'Theme updated', 'uaip-security-firewall' ),
			'theme_switched'           => __( 'Theme switched', 'uaip-security-firewall' ),
			'theme_deleted'            => __( 'Theme deleted', 'uaip-security-firewall' ),
			'core_updated'             => __( 'WordPress updated', 'uaip-security-firewall' ),
			'option_changed'           => __( 'Site setting changed', 'uaip-security-firewall' ),
			'plugin_settings_changed'  => __( 'Security settings changed', 'uaip-security-firewall' ),
			'attack_blocked'           => __( 'Attack blocked', 'uaip-security-firewall' ),
			'attack_detected'          => __( 'Attack detected (learning mode)', 'uaip-security-firewall' ),
			'scan_completed'           => __( 'Scan finished', 'uaip-security-firewall' ),
			'malware_found'            => __( 'Malware found', 'uaip-security-firewall' ),
			'file_repaired'            => __( 'File repaired', 'uaip-security-firewall' ),
			'file_deleted'             => __( 'File deleted', 'uaip-security-firewall' ),
		);
	}

	/**
	 * @param string $type Type.
	 * @return string
	 */
	public static function label( $type ) {
		$labels = self::labels();
		return isset( $labels[ $type ] ) ? $labels[ $type ] : ucwords( str_replace( '_', ' ', $type ) );
	}

	/** @return array<string,string> Category labels. */
	public static function categories() {
		return array(
			'login'    => __( 'Sign-in', 'uaip-security-firewall' ),
			'users'    => __( 'Users', 'uaip-security-firewall' ),
			'software' => __( 'Plugins, themes & core', 'uaip-security-firewall' ),
			'settings' => __( 'Settings', 'uaip-security-firewall' ),
			'firewall' => __( 'Firewall', 'uaip-security-firewall' ),
			'scanner'  => __( 'Scanner', 'uaip-security-firewall' ),
		);
	}

	/**
	 * @param string $type Type.
	 * @return array{0:string,1:string} Category, severity.
	 */
	public static function type_info( $type ) {
		return isset( self::TYPES[ $type ] ) ? self::TYPES[ $type ] : array( 'other', 'info' );
	}

	// ------------------------------------------------------------------
	// Writing
	// ------------------------------------------------------------------

	/**
	 * Record an event.
	 *
	 * @param string   $type     Event type (see TYPES).
	 * @param array    $data     Details; never put secrets here.
	 * @param string   $object   What it is about (user login, plugin, file…).
	 * @param int|null $actor_id Who did it; defaults to the current user.
	 */
	public function record( $type, array $data = array(), $object = '', $actor_id = null ) {
		if ( ! self::enabled() ) {
			return;
		}
		$actor_id = null === $actor_id ? get_current_user_id() : (int) $actor_id;
		$actor    = $actor_id ? get_userdata( $actor_id ) : false;
		if ( '' === $object ) {
			$object = $this->object_from( $data );
		}
		list( $category, $severity ) = self::type_info( $type );
		$row = array(
			'ts'       => time(),
			'type'     => substr( $type, 0, 40 ),
			'category' => $category,
			'severity' => $severity,
			'actor_id' => $actor_id,
			'actor'    => $actor ? substr( $actor->user_login, 0, 60 ) : '',
			'ip'       => substr( (string) Uaip_Sfw_Settings::visitor_ip(), 0, 45 ),
			'object'   => mb_substr( (string) $object, 0, 190 ),
			'data'     => (string) wp_json_encode( $data ),
		);
		global $wpdb;
		$wpdb->insert( Uaip_Sfw_DB::activity(), $row, array( '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- the plugin's own log table.
		$row['id'] = (int) $wpdb->insert_id;

		/**
		 * After an activity-log row is written.
		 *
		 * @param array $row Row.
		 */
		do_action( 'uaip_sfw_activity_recorded', $row );
	}

	/**
	 * A readable object for older callers that only pass data.
	 *
	 * @param array $data Data.
	 * @return string
	 */
	private function object_from( array $data ) {
		foreach ( array( 'plugin', 'theme', 'file', 'option' ) as $k ) {
			if ( ! empty( $data[ $k ] ) && is_scalar( $data[ $k ] ) ) {
				return (string) $data[ $k ];
			}
		}
		if ( ! empty( $data['user'] ) && is_numeric( $data['user'] ) ) {
			$u = get_userdata( (int) $data['user'] );
			return $u ? $u->user_login : '#' . (int) $data['user'];
		}
		return '';
	}

	/** @param int $user_id User. */
	private function login_of( $user_id ) {
		$u = get_userdata( (int) $user_id );
		return $u ? $u->user_login : '#' . (int) $user_id;
	}

	// ------------------------------------------------------------------
	// Event hooks
	// ------------------------------------------------------------------

	/**
	 * @param string       $login Login.
	 * @param WP_User|null $user  User.
	 */
	public function on_login( $login, $user = null ) {
		$uid = $user instanceof WP_User ? $user->ID : 0;
		$this->record( 'login_success', array(), $login, $uid );
		if ( $user instanceof WP_User && user_can( $user, 'manage_options' ) ) {
			Uaip_Sfw_Notifier::admin_login( $user, Uaip_Sfw_Settings::visitor_ip() );
		}
	}

	/** @param int $user_id User. */
	public function on_logout( $user_id = 0 ) {
		$uid = $user_id ? (int) $user_id : get_current_user_id();
		if ( $uid ) {
			$this->record( 'logout', array(), $this->login_of( $uid ), $uid );
		}
	}

	/**
	 * @param string        $username Attempted username.
	 * @param WP_Error|null $error    Error.
	 */
	public function on_login_failed( $username, $error = null ) {
		$code = $error instanceof WP_Error ? $error->get_error_code() : '';
		if ( 'uaip_sfw_2fa_invalid' === $code ) {
			return; // Recorded as twofa_failed by the two-step module.
		}
		if ( 'uaip_sfw_bad_login' === $code ) {
			$data = $error->get_error_data();
			$code = is_array( $data ) && isset( $data['reason'] ) ? $data['reason'] : $code;
		}
		$this->record( 'login_failed', array( 'reason' => sanitize_key( (string) $code ) ), sanitize_user( (string) $username, true ), 0 );
	}

	/** @param int $user_id New user. */
	public function on_user_register( $user_id ) {
		$u = get_userdata( $user_id );
		$this->record( 'user_created', array( 'role' => $u ? implode( ',', $u->roles ) : '' ), $this->login_of( $user_id ) );
	}

	/** @param int $user_id User being deleted. */
	public function on_delete_user( $user_id ) {
		$u = get_userdata( $user_id );
		$this->record( 'user_deleted', array( 'role' => $u ? implode( ',', $u->roles ) : '' ), $this->login_of( $user_id ) );
	}

	/**
	 * @param int      $user_id   User.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Old roles.
	 */
	public function on_role( $user_id, $role, $old_roles = array() ) {
		$old_roles = (array) $old_roles;
		if ( ! $old_roles || array( $role ) === array_values( $old_roles ) ) {
			return; // New user (logged as user_created) or nothing changed.
		}
		$this->record( 'user_role_changed', array( 'from' => implode( ',', $old_roles ), 'to' => (string) $role ), $this->login_of( $user_id ) );
	}

	/**
	 * @param int     $user_id  User.
	 * @param WP_User $old_user Before the update.
	 */
	public function on_profile_update( $user_id, $old_user = null ) {
		$new = get_userdata( $user_id );
		if ( ! $new || ! $old_user instanceof WP_User ) {
			return;
		}
		if ( $new->user_pass !== $old_user->user_pass ) {
			$this->record( 'password_changed', array(), $new->user_login );
		}
		if ( $new->user_email !== $old_user->user_email ) {
			$this->record( 'email_changed', array( 'from' => $old_user->user_email, 'to' => $new->user_email ), $new->user_login );
		}
	}

	/** @param WP_User $user User. */
	public function on_password_reset( $user ) {
		if ( $user instanceof WP_User ) {
			$this->record( 'password_reset', array(), $user->user_login, $user->ID );
		}
	}

	/**
	 * @param int   $user_id User.
	 * @param array $item    Application password (no secret).
	 */
	public function on_app_password_created( $user_id, $item = array() ) {
		$this->record( 'app_password_created', array( 'name' => isset( $item['name'] ) ? (string) $item['name'] : '' ), $this->login_of( $user_id ) );
	}

	/**
	 * @param int   $user_id User.
	 * @param array $item    Application password.
	 */
	public function on_app_password_deleted( $user_id, $item = array() ) {
		$this->record( 'app_password_deleted', array( 'name' => isset( $item['name'] ) ? (string) $item['name'] : '' ), $this->login_of( $user_id ) );
	}

	/** @param string $plugin Plugin file. */
	public function on_plugin_activated( $plugin ) {
		$this->record( 'plugin_activated', $this->plugin_data( $plugin ), $plugin );
	}

	/** @param string $plugin Plugin file. */
	public function on_plugin_deactivated( $plugin ) {
		$this->record( 'plugin_deactivated', $this->plugin_data( $plugin ), $plugin );
	}

	/**
	 * @param string $plugin  Plugin file.
	 * @param bool   $deleted Deleted.
	 */
	public function on_plugin_deleted( $plugin, $deleted = true ) {
		if ( $deleted ) {
			$this->record( 'plugin_deleted', array(), $plugin );
		}
	}

	/** @param string $name Theme name. */
	public function on_theme_switched( $name ) {
		$this->record( 'theme_switched', array(), (string) $name );
	}

	/**
	 * @param string $stylesheet Theme.
	 * @param bool   $deleted    Deleted.
	 */
	public function on_theme_deleted( $stylesheet, $deleted = true ) {
		if ( $deleted ) {
			$this->record( 'theme_deleted', array(), (string) $stylesheet );
		}
	}

	/**
	 * Installs and updates of plugins and themes.
	 *
	 * @param WP_Upgrader $upgrader Upgrader.
	 * @param array       $extra    Details.
	 */
	public function on_upgrade( $upgrader, $extra = array() ) {
		$type   = isset( $extra['type'] ) ? $extra['type'] : '';
		$action = isset( $extra['action'] ) ? $extra['action'] : '';
		if ( 'plugin' === $type ) {
			if ( 'install' === $action && $upgrader instanceof Plugin_Upgrader ) {
				$file = (string) $upgrader->plugin_info();
				if ( '' !== $file ) {
					$this->record( 'plugin_installed', $this->plugin_data( $file ), $file );
				}
			} elseif ( 'update' === $action ) {
				$files = isset( $extra['plugins'] ) ? (array) $extra['plugins'] : ( isset( $extra['plugin'] ) ? array( $extra['plugin'] ) : array() );
				foreach ( $files as $file ) {
					$this->record( 'plugin_updated', $this->plugin_data( $file ), $file );
				}
			}
		} elseif ( 'theme' === $type ) {
			if ( 'install' === $action && $upgrader instanceof Theme_Upgrader ) {
				$theme = $upgrader->theme_info();
				if ( $theme instanceof WP_Theme ) {
					$this->record( 'theme_installed', array( 'version' => $theme->get( 'Version' ) ), $theme->get_stylesheet() );
				}
			} elseif ( 'update' === $action ) {
				$themes = isset( $extra['themes'] ) ? (array) $extra['themes'] : ( isset( $extra['theme'] ) ? array( $extra['theme'] ) : array() );
				foreach ( $themes as $slug ) {
					$t = wp_get_theme( $slug );
					$this->record( 'theme_updated', array( 'version' => $t->exists() ? $t->get( 'Version' ) : '' ), $slug );
				}
			}
		}
	}

	/** @param string $version New version. */
	public function on_core_updated( $version ) {
		$this->record( 'core_updated', array( 'version' => (string) $version ), 'WordPress' );
	}

	/**
	 * Site settings and this plugin's own settings.
	 *
	 * @param string $option Option.
	 * @param mixed  $old    Old value.
	 * @param mixed  $value  New value.
	 */
	public function on_option( $option, $old, $value ) {
		if ( Uaip_Sfw_Settings::OPTION === $option ) {
			// Fill defaults on both sides so a newly stored default is not a change.
			$old     = wp_parse_args( is_array( $old ) ? $old : array(), Uaip_Sfw_Settings::defaults() );
			$value   = wp_parse_args( is_array( $value ) ? $value : array(), Uaip_Sfw_Settings::defaults() );
			$changed = array();
			foreach ( array_unique( array_merge( array_keys( $old ), array_keys( $value ) ) ) as $k ) {
				if ( ! isset( $old[ $k ], $value[ $k ] ) || maybe_serialize( $old[ $k ] ) !== maybe_serialize( $value[ $k ] ) ) {
					$changed[] = $k;
				}
			}
			if ( $changed ) {
				// Keys only: some values (alert email, licence) are private.
				$this->record( 'plugin_settings_changed', array( 'keys' => $changed ), 'UAIP Security Firewall' );
			}
			return;
		}
		if ( in_array( $option, self::WATCHED_OPTIONS, true ) && is_scalar( $old ) && is_scalar( $value ) && (string) $old !== (string) $value ) {
			$this->record( 'option_changed', array( 'from' => mb_substr( (string) $old, 0, 200 ), 'to' => mb_substr( (string) $value, 0, 200 ) ), $option );
		}
	}

	/**
	 * Name and version of an installed plugin.
	 *
	 * @param string $file Plugin file.
	 * @return array
	 */
	private function plugin_data( $file ) {
		$path = WP_PLUGIN_DIR . '/' . $file;
		if ( ! is_readable( $path ) ) {
			return array();
		}
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$d = get_plugin_data( $path, false, false );
		return array(
			'name'    => (string) $d['Name'],
			'version' => (string) $d['Version'],
		);
	}

	// ------------------------------------------------------------------
	// Reading
	// ------------------------------------------------------------------

	/**
	 * Rows matching filters, newest first.
	 *
	 * @param array $args category, type, actor, ip, search, from, to (timestamps), page, per_page.
	 * @return array{rows:array,total:int}
	 */
	public function query( array $args = array() ) {
		global $wpdb;
		$args  = wp_parse_args(
			$args,
			array(
				'category' => '',
				'type'     => '',
				'actor'    => '',
				'ip'       => '',
				'search'   => '',
				'from'     => 0,
				'to'       => 0,
				'page'     => 1,
				'per_page' => 50,
			)
		);
		$cat    = (string) $args['category'];
		$type   = (string) $args['type'];
		$actor  = (string) $args['actor'];
		$ip     = (string) $args['ip'];
		$search = (string) $args['search'];
		$like   = '%' . $wpdb->esc_like( $search ) . '%';
		$from   = (int) $args['from'];
		$to     = (int) $args['to'] ? (int) $args['to'] : PHP_INT_MAX;
		$per    = max( 1, min( 5000, (int) $args['per_page'] ) );
		$offset = ( max( 1, (int) $args['page'] ) - 1 ) * $per;
		$table  = Uaip_Sfw_DB::activity();

		// One fixed statement: an empty filter value switches its condition off.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own log table.
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE (%s = '' OR category = %s) AND (%s = '' OR type = %s) AND (%s = '' OR actor = %s) AND (%s = '' OR ip = %s) AND (%s = '' OR object LIKE %s OR actor LIKE %s OR data LIKE %s) AND ts >= %d AND ts <= %d",
				$table, $cat, $cat, $type, $type, $actor, $actor, $ip, $ip, $search, $like, $like, $like, $from, $to
			)
		);
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM %i WHERE (%s = '' OR category = %s) AND (%s = '' OR type = %s) AND (%s = '' OR actor = %s) AND (%s = '' OR ip = %s) AND (%s = '' OR object LIKE %s OR actor LIKE %s OR data LIKE %s) AND ts >= %d AND ts <= %d ORDER BY id DESC LIMIT %d OFFSET %d",
				$table, $cat, $cat, $type, $type, $actor, $actor, $ip, $ip, $search, $like, $like, $like, $from, $to, $per, $offset
			),
			ARRAY_A
		);
		// phpcs:enable

		return array(
			'rows'  => array_map( array( $this, 'shape' ), (array) $rows ),
			'total' => $total,
		);
	}

	/**
	 * @param int $limit Rows.
	 * @return array Newest first.
	 */
	public function recent( $limit = 50 ) {
		$res = $this->query( array( 'per_page' => $limit ) );
		return $res['rows'];
	}

	/**
	 * Rows after an id, oldest first (cloud sync).
	 *
	 * @param int $id    Last synced id.
	 * @param int $limit Rows.
	 * @return array
	 */
	public function since_id( $id, $limit = 50 ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own log table.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE id > %d ORDER BY id ASC LIMIT %d', Uaip_Sfw_DB::activity(), (int) $id, (int) $limit ), ARRAY_A );
		return array_map( array( $this, 'shape' ), (array) $rows );
	}

	/**
	 * Decode a row.
	 *
	 * @param array $r Raw row.
	 * @return array
	 */
	public function shape( $r ) {
		$data = json_decode( (string) $r['data'], true );
		return array(
			'id'       => (int) $r['id'],
			'ts'       => (int) $r['ts'],
			'type'     => (string) $r['type'],
			'category' => (string) $r['category'],
			'severity' => (string) $r['severity'],
			'user'     => (int) $r['actor_id'],
			'actor'    => (string) $r['actor'],
			'ip'       => (string) $r['ip'],
			'object'   => (string) $r['object'],
			'data'     => is_array( $data ) ? $data : array(),
		);
	}

	/**
	 * One-line details for a row.
	 *
	 * @param array $e Shaped row.
	 * @return string
	 */
	public static function details( array $e ) {
		$d = $e['data'];
		switch ( $e['type'] ) {
			case 'user_role_changed':
			case 'email_changed':
			case 'option_changed':
				/* translators: 1: old value, 2: new value */
				return sprintf( __( '%1$s → %2$s', 'uaip-security-firewall' ), isset( $d['from'] ) ? $d['from'] : '', isset( $d['to'] ) ? $d['to'] : '' );
			case 'plugin_settings_changed':
				/* translators: %s: list of setting keys */
				return sprintf( __( 'Changed: %s', 'uaip-security-firewall' ), implode( ', ', (array) ( isset( $d['keys'] ) ? $d['keys'] : array() ) ) );
			case 'attack_blocked':
			case 'attack_detected':
				/* translators: 1: rule id, 2: attack class, 3: score */
				return sprintf( __( 'Rule %1$s (%2$s), score %3$d', 'uaip-security-firewall' ), isset( $d['rule'] ) ? $d['rule'] : '?', isset( $d['class'] ) ? $d['class'] : '', isset( $d['score'] ) ? (int) $d['score'] : 0 );
			case 'scan_completed':
				/* translators: 1: files checked, 2: open findings */
				return sprintf( __( '%1$d files checked, %2$d open findings', 'uaip-security-firewall' ), isset( $d['checked'] ) ? (int) $d['checked'] : 0, isset( $d['open'] ) ? (int) $d['open'] : 0 );
		}
		$parts = array();
		foreach ( $d as $k => $v ) {
			if ( 'user' === $k || 'ip' === $k || '' === $v || null === $v ) {
				continue;
			}
			$parts[] = $k . ': ' . ( is_scalar( $v ) ? (string) $v : implode( ', ', array_map( 'strval', (array) $v ) ) );
		}
		return implode( ' · ', $parts );
	}

	// ------------------------------------------------------------------
	// Maintenance
	// ------------------------------------------------------------------

	/** Drop rows past the retention period and above the hard cap. */
	public function prune() {
		global $wpdb;
		$table = Uaip_Sfw_DB::activity();
		$days  = max( 1, (int) Uaip_Sfw_Settings::get( 'audit_retention_days', 90 ) );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own log table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE ts < %d', $table, time() - $days * DAY_IN_SECONDS ) );
		$max = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MAX(id) FROM %i', $table ) );
		if ( $max > self::MAX_ROWS ) {
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE id <= %d', $table, $max - self::MAX_ROWS ) );
		}
		// phpcs:enable
	}

	/**
	 * Empty the log.
	 *
	 * @return int Rows removed.
	 */
	public function clear() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own log table.
		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Uaip_Sfw_DB::activity() ) );
	}

	/** Move events from the old option into the table (once). */
	public static function import_legacy() {
		$events = get_option( self::LEGACY_OPTION, null );
		if ( null === $events ) {
			return;
		}
		global $wpdb;
		foreach ( (array) $events as $e ) {
			if ( empty( $e['type'] ) ) {
				continue;
			}
			list( $category, $severity ) = self::type_info( (string) $e['type'] );
			$data = isset( $e['data'] ) && is_array( $e['data'] ) ? $e['data'] : array();
			$uid  = isset( $e['user'] ) ? (int) $e['user'] : 0;
			$u    = $uid ? get_userdata( $uid ) : false;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- one-time import into the plugin's own table.
			$wpdb->insert(
				Uaip_Sfw_DB::activity(),
				array(
					'ts'       => isset( $e['ts'] ) ? (int) $e['ts'] : time(),
					'type'     => substr( (string) $e['type'], 0, 40 ),
					'category' => $category,
					'severity' => $severity,
					'actor_id' => $uid,
					'actor'    => $u ? $u->user_login : '',
					'ip'       => isset( $e['ip'] ) ? substr( (string) $e['ip'], 0, 45 ) : '',
					'object'   => '',
					'data'     => (string) wp_json_encode( $data ),
				),
				array( '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s' )
			);
		}
		delete_option( self::LEGACY_OPTION );
	}
}
