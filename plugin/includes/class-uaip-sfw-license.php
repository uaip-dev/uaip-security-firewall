<?php
/**
 * License & tier resolution.
 *
 * Tier is FREE unless ALL of the following are true:
 *   1. The Pro package is installed (the /pro folder ships only in the paid download).
 *   2. A license key is stored.
 *   3. The license validated against UAIP Security Cloud and is active & unexpired.
 *
 * Validation is cached so we never hit the network on every request.
 *
 * @package UaipSecurityFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Uaip_Sfw_License {

	const TIER_FREE = 'free';
	const TIER_PRO  = 'pro';

	const OPT_KEY   = 'uaip_sfw_license_key';
	const OPT_STATE = 'uaip_sfw_license_state'; // cached validation result

	/** @return string self::TIER_FREE|self::TIER_PRO */
	public function tier() {
		return $this->is_pro() ? self::TIER_PRO : self::TIER_FREE;
	}

	/** @return bool */
	public function is_pro() {
		if ( $this->is_dev_pro() ) {
			return true;
		}
		if ( ! UAIP_SFW_HAS_PRO_PACKAGE ) {
			return false;
		}
		$state = $this->state();
		if ( empty( $state['active'] ) ) {
			return false;
		}
		// Enforce expiry locally — don't wait for the next cloud revalidation.
		if ( $this->is_expired_state( $state ) ) {
			return false;
		}
		return true;
	}

	/**
	 * @param array $state
	 * @return bool
	 */
	private function is_expired_state( $state ) {
		return ! empty( $state['expires'] ) && strtotime( $state['expires'] ) < time();
	}

	/** @return bool Whether the stored license has passed its expiry date. */
	public function is_expired() {
		return $this->is_expired_state( $this->state() );
	}

	/**
	 * Reconcile the effective tier each load. On a Pro -> Free transition
	 * (expiry, cancellation, refund) halt Pro: clear premium rule caches and
	 * flag an admin notice so the next request loads only Free protections.
	 */
	public function enforce_tier() {
		$current = $this->is_pro() ? self::TIER_PRO : self::TIER_FREE;
		$last    = get_option( 'uaip_sfw_active_tier', self::TIER_FREE );

		if ( self::TIER_PRO === $last && self::TIER_FREE === $current ) {
			// Downgraded — premium rules pulled from the cloud are no longer
			// licensed; drop them so only bundled + free-tier rules apply.
			delete_option( 'uaip_sfw_waf_rules' );
			delete_option( 'uaip_sfw_waf_rules_version' );
			update_option( 'uaip_sfw_downgraded_notice', 1 );
			do_action( 'uaip_sfw_tier_downgraded' );
		} elseif ( self::TIER_FREE === $last && self::TIER_PRO === $current ) {
			delete_option( 'uaip_sfw_downgraded_notice' );
			do_action( 'uaip_sfw_tier_upgraded' );
		}

		update_option( 'uaip_sfw_active_tier', $current );
	}

	/**
	 * Developer flag to simulate an active Pro license locally. Requires the
	 * Pro package to be present. DEV ONLY — never enable in production.
	 *
	 * Hardening: even with the constant set and the Pro files present, the
	 * override is refused on a production environment. This stops the flag from
	 * being abused as a license bypass on a live site if a Pro package leaks.
	 * A developer must explicitly run as local/development (WP_ENVIRONMENT_TYPE)
	 * AND set the constant AND have the Pro files — three independent gates.
	 *
	 * @return bool
	 */
	public function is_dev_pro() {
		// BUILD:PROD-STRIP-START — the production Pro build (bin/build.sh)
		// replaces this whole block with `return false;` so the developer
		// override does not exist in customer-facing code at all.
		if ( ! defined( 'UAIP_SFW_DEV_PRO' ) || ! UAIP_SFW_DEV_PRO || ! UAIP_SFW_HAS_PRO_PACKAGE ) {
			return false;
		}
		// wp_get_environment_type() defaults to 'production' (WP 5.5+), so this
		// is fail-safe: the override only works where the site is explicitly a
		// local/development/staging environment.
		if ( function_exists( 'wp_get_environment_type' ) && 'production' === wp_get_environment_type() ) {
			return false;
		}
		return true;
		// BUILD:PROD-STRIP-END
	}

	/** @return string */
	public function key() {
		return (string) get_option( self::OPT_KEY, '' );
	}

	/**
	 * Cached license state. Re-validates against the cloud at most daily.
	 *
	 * @return array{active:bool,plan:string,expires:?string,checked_at:int}
	 */
	public function state() {
		if ( $this->is_dev_pro() ) {
			return array( 'active' => true, 'plan' => 'pro-dev', 'expires' => null, 'checked_at' => time() );
		}
		$state = get_option( self::OPT_STATE, array() );
		$fresh = is_array( $state ) && isset( $state['checked_at'] )
			&& ( time() - (int) $state['checked_at'] ) < DAY_IN_SECONDS;

		if ( $fresh ) {
			return $state;
		}
		return $this->revalidate();
	}

	/**
	 * Hit UAIP Security Cloud to validate the stored key. Falls back to the last
	 * known state on network failure so a flaky connection never silently
	 * downgrades a paying customer mid-cycle.
	 *
	 * @return array
	 */
	public function revalidate() {
		$key      = $this->key();
		$previous = get_option( self::OPT_STATE, array() );

		if ( '' === $key ) {
			$state = array( 'active' => false, 'plan' => self::TIER_FREE, 'expires' => null, 'checked_at' => time() );
			update_option( self::OPT_STATE, $state );
			return $state;
		}

		$result = Uaip_Sfw_Cloud_API::instance()->validate_license( $key );

		if ( is_wp_error( $result ) ) {
			// Network/transient error: keep prior state, just stamp the time.
			$state               = is_array( $previous ) ? $previous : array( 'active' => false, 'plan' => self::TIER_FREE, 'expires' => null );
			$state['checked_at'] = time();
			update_option( self::OPT_STATE, $state );
			return $state;
		}

		$state = array(
			'active'     => ! empty( $result['active'] ),
			'plan'       => isset( $result['plan'] ) ? $result['plan'] : self::TIER_PRO,
			'expires'    => isset( $result['expires'] ) ? $result['expires'] : null,
			'reason'     => isset( $result['reason'] ) ? $result['reason'] : null,
			'seats'      => isset( $result['seats'] ) ? $result['seats'] : null,
			'is_local'   => ! empty( $result['is_local'] ),
			'checked_at' => time(),
		);
		update_option( self::OPT_STATE, $state );
		return $state;
	}

	/**
	 * Store and immediately validate a new license key.
	 *
	 * @param string $key
	 * @return array New state.
	 */
	public function activate( $key ) {
		update_option( self::OPT_KEY, sanitize_text_field( $key ) );
		return $this->revalidate();
	}

	public function deactivate() {
		$key = $this->key();
		// Release the seat in the cloud so it can be reused elsewhere.
		if ( '' !== $key && Uaip_Sfw_Cloud_API::instance()->is_connected() ) {
			Uaip_Sfw_Cloud_API::instance()->deactivate_license( $key );
		}
		delete_option( self::OPT_KEY );
		delete_option( self::OPT_STATE );
	}
}
