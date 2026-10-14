<?php
/**
 * UAIP Security → Vulnerabilities: opt-in, results, data credits.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_Vulns_Page {

	const SLUG = 'uaip-sfw-vulns';

	/** @var Uaip_Sfw_Vulns */
	private $vulns;

	/**
	 * @param Uaip_Sfw_Vulns $vulns Module.
	 */
	public function __construct( $vulns ) {
		$this->vulns = $vulns;
	}

	/** Handle the opt-in, opt-out and check-now forms. */
	private function handle_post() {
		if ( ! current_user_can( 'manage_options' ) || ! isset( $_POST['uaip_sfw_vulns_action'] ) || ! check_admin_referer( 'uaip_sfw_vulns' ) ) {
			return;
		}
		$action = sanitize_key( wp_unslash( $_POST['uaip_sfw_vulns_action'] ) );
		if ( 'enable' === $action ) {
			$res = $this->vulns->enable();
			$this->notice( is_wp_error( $res ) ? 'error' : 'success', is_wp_error( $res )
				/* translators: %s: error message */
				? sprintf( __( 'Vulnerability alerts could not be turned on: %s', 'uaip-security-firewall' ), $res->get_error_message() )
				: __( 'Vulnerability alerts are on. The first check is done.', 'uaip-security-firewall' ) );
		} elseif ( 'disable' === $action ) {
			$this->vulns->disable();
			$this->notice( 'success', __( 'Vulnerability alerts are off. Nothing more is sent.', 'uaip-security-firewall' ) );
		} elseif ( 'check' === $action ) {
			$res = $this->vulns->run();
			if ( is_wp_error( $res ) ) {
				/* translators: %s: error message */
				$this->notice( 'error', sprintf( __( 'The check failed: %s', 'uaip-security-firewall' ), $res->get_error_message() ) );
			}
		}
	}

	/**
	 * @param string $type success|error.
	 * @param string $msg  Message.
	 */
	private function notice( $type, $msg ) {
		echo '<div class="notice notice-' . esc_attr( $type ) . ' is-dismissible"><p>' . esc_html( $msg ) . '</p></div>';
	}

	/**
	 * @param string $action Action.
	 * @param string $label  Button label.
	 * @param string $class  Button class.
	 */
	private function button( $action, $label, $class ) {
		echo '<form method="post" class="uaip-sfw-inline-form">';
		wp_nonce_field( 'uaip_sfw_vulns' );
		echo '<button type="submit" name="uaip_sfw_vulns_action" value="' . esc_attr( $action ) . '" class="button ' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	/** Page body (the admin class prints the wrap and header). */
	public function render_body() {
		$this->handle_post();
		if ( ! Uaip_Sfw_Vulns::enabled() ) {
			$this->render_optin();
			return;
		}
		$res = Uaip_Sfw_Vulns::results();

		echo '<div class="uaip-sfw-card"><div class="uaip-sfw-activity-bar"><span>';
		if ( ! empty( $res['checked_at'] ) ) {
			/* translators: 1: time since the check, 2: number of items */
			echo esc_html( sprintf( __( 'Checked %1$s ago: WordPress, plugins and themes (%2$d items).', 'uaip-security-firewall' ), human_time_diff( (int) $res['checked_at'] ), (int) $res['checked'] ) );
		} else {
			echo esc_html__( 'Not checked yet.', 'uaip-security-firewall' );
		}
		echo '</span>';
		$this->button( 'check', __( 'Check now', 'uaip-security-firewall' ), 'button-secondary' );
		echo '</div>';
		if ( ! empty( $res['error'] ) ) {
			/* translators: %s: error */
			echo '<div class="notice notice-warning inline"><p>' . esc_html( sprintf( __( 'The last check failed (%s). The results below are from the previous successful check.', 'uaip-security-firewall' ), $res['error'] ) ) . '</p></div>';
		}

		$items = isset( $res['items'] ) ? $res['items'] : array();
		if ( ! $items && ! empty( $res['checked_at'] ) ) {
			echo '<p class="uaip-sfw-vulns-clean"><span class="dashicons dashicons-yes-alt"></span> ' . esc_html__( 'No known vulnerabilities in the installed versions.', 'uaip-security-firewall' ) . '</p>';
		}
		if ( $items ) {
			echo '<table class="widefat striped uaip-sfw-table"><thead><tr><th>' . esc_html__( 'Software', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Issue', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Severity', 'uaip-security-firewall' ) . '</th><th>' . esc_html__( 'Fixed in', 'uaip-security-firewall' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $items as $it ) {
				$update = 'core' === $it['type'] ? admin_url( 'update-core.php' ) : admin_url( 'plugin' === $it['type'] ? 'plugins.php' : 'themes.php' );
				foreach ( $it['vulns'] as $v ) {
					echo '<tr><td><strong>' . esc_html( $it['name'] ) . '</strong> ' . esc_html( $it['version'] ) . '</td><td>';
					echo '' !== $v['link'] ? '<a href="' . esc_url( $v['link'] ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $v['title'] ) . '</a>' : esc_html( $v['title'] );
					echo '' !== $v['cve'] ? ' <code>' . esc_html( $v['cve'] ) . '</code>' : '';
					echo '</td><td><span class="uaip-sfw-sev uaip-sfw-sev-' . esc_attr( 'unknown' === $v['severity'] ? 'low' : $v['severity'] ) . '">' . esc_html( ucfirst( $v['severity'] ) ) . ( null !== $v['cvss'] ? ' ' . esc_html( number_format_i18n( $v['cvss'], 1 ) ) : '' ) . '</span></td>';
					echo '<td>' . ( '' !== $v['fixed_in'] ? esc_html( $v['fixed_in'] ) : '<span class="description">' . esc_html__( 'no fix yet', 'uaip-security-firewall' ) . '</span>' ) . '</td>';
					echo '<td>' . ( '' !== $v['fixed_in'] ? '<a class="button button-small" href="' . esc_url( $update ) . '">' . esc_html__( 'Update', 'uaip-security-firewall' ) . '</a>' : '' ) . '</td></tr>';
				}
			}
			echo '</tbody></table>';
			$unfixed = false;
			foreach ( $items as $it ) {
				foreach ( $it['vulns'] as $v ) {
					$unfixed = $unfixed || '' === $v['fixed_in'];
				}
			}
			if ( $unfixed ) {
				echo '<p class="description">' . esc_html__( 'With no fix yet, consider turning the software off or replacing it until the author releases one.', 'uaip-security-firewall' ) . '</p>';
			}
		}
		if ( ! empty( $res['credits'] ) ) {
			echo '<div class="uaip-sfw-credits"><strong>' . esc_html__( 'Data sources', 'uaip-security-firewall' ) . '</strong>';
			foreach ( $res['credits'] as $credit ) {
				echo '<p>' . esc_html( $credit ) . '</p>';
			}
			echo '</div>';
		}
		echo '</div>';

		echo '<div class="uaip-sfw-card"><h2>' . esc_html__( 'Turn off', 'uaip-security-firewall' ) . '</h2><p>' . esc_html__( 'Stops the daily check and deletes the results stored on this site.', 'uaip-security-firewall' ) . '</p>';
		$this->button( 'disable', __( 'Turn off vulnerability alerts', 'uaip-security-firewall' ), 'button-link-delete' );
		echo '</div>';
	}

	/** Explain exactly what is sent before anything is. */
	private function render_optin() {
		echo '<div class="uaip-sfw-card uaip-sfw-optin">';
		echo '<h2><span class="dashicons dashicons-warning"></span> ' . esc_html__( 'Know when installed software has a security hole', 'uaip-security-firewall' ) . '</h2>';
		echo '<p>' . esc_html__( 'Once a day, and after each update, this site asks UAIP Security Cloud whether its WordPress, plugin and theme versions have known vulnerabilities. You get an email when a new one is found, and the results appear here and in your weekly summary.', 'uaip-security-firewall' ) . '</p>';
		echo '<h3>' . esc_html__( 'What is sent', 'uaip-security-firewall' ) . '</h3><ul class="uaip-sfw-list">';
		echo '<li>' . esc_html__( 'Once, to register: this site\'s address and its WordPress and plugin versions.', 'uaip-security-firewall' ) . '</li>';
		echo '<li>' . esc_html__( 'Each check: the WordPress version, and the folder name (slug) and version of every installed plugin and theme.', 'uaip-security-firewall' ) . '</li>';
		echo '<li>' . esc_html__( 'Nothing else: no users, emails, content, visitor IP addresses or settings.', 'uaip-security-firewall' ) . '</li></ul>';
		echo '<h3>' . esc_html__( 'Where it goes', 'uaip-security-firewall' ) . '</h3>';
		echo '<p>' . esc_html__( 'UAIP Security Cloud (security.uaip.dev) matches the list against public vulnerability data from WPVulnerability.net and Wordfence Intelligence. To keep that data current it looks up plugin and theme names and versions at WPVulnerability.net, without your site address.', 'uaip-security-firewall' ) . ' ';
		echo '<a href="' . esc_url( UAIP_SFW_CLOUD_SITE . '/privacy' ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Privacy policy', 'uaip-security-firewall' ) . '</a> · <a href="' . esc_url( UAIP_SFW_CLOUD_SITE . '/terms' ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Terms', 'uaip-security-firewall' ) . '</a></p>';
		echo '<p>' . esc_html__( 'Free, no account needed. You can turn it off at any time.', 'uaip-security-firewall' ) . '</p>';
		$this->button( 'enable', __( 'Turn on vulnerability alerts', 'uaip-security-firewall' ), 'button-primary' );
		echo '</div>';
	}
}
