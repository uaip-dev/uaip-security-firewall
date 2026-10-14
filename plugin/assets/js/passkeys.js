/* UAIP Security Firewall: passkey sign-in and registration. */
( function () {
	'use strict';

	function fromB64url( s ) {
		s = s.replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( s.length % 4 ) {
			s += '=';
		}
		var bin = atob( s );
		var out = new Uint8Array( bin.length );
		for ( var i = 0; i < bin.length; i++ ) {
			out[ i ] = bin.charCodeAt( i );
		}
		return out.buffer;
	}

	function toB64url( buf ) {
		var bytes = new Uint8Array( buf );
		var bin = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			bin += String.fromCharCode( bytes[ i ] );
		}
		return btoa( bin ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function supported() {
		return !! ( window.PublicKeyCredential && navigator.credentials );
	}

	function descriptors( ids ) {
		return ( ids || [] ).map( function ( id ) {
			return { type: 'public-key', id: fromB64url( id ) };
		} );
	}

	// Sign-in step: run the assertion, fill the hidden fields, submit.
	var login = document.getElementById( 'uaip-sfw-passkey-login' );
	if ( login ) {
		var opts = JSON.parse( login.getAttribute( 'data-options' ) || '{}' );
		var form = login.form;
		if ( ! supported() ) {
			login.parentNode.style.display = 'none';
		}
		login.addEventListener( 'click', function () {
			login.disabled = true;
			navigator.credentials.get( {
				publicKey: {
					challenge: fromB64url( opts.challenge ),
					rpId: opts.rpId,
					allowCredentials: descriptors( opts.allow ),
					userVerification: 'preferred',
					timeout: 120000
				}
			} ).then( function ( cred ) {
				form.elements.uaip_sfw_wa_id.value = toB64url( cred.rawId );
				form.elements.uaip_sfw_wa_client.value = toB64url( cred.response.clientDataJSON );
				form.elements.uaip_sfw_wa_auth.value = toB64url( cred.response.authenticatorData );
				form.elements.uaip_sfw_wa_sig.value = toB64url( cred.response.signature );
				form.elements.uaip_sfw_code.value = '';
				form.submit();
			} ).catch( function () {
				login.disabled = false;
				var p = document.createElement( 'p' );
				p.className = 'uaip-sfw-2fa-error';
				p.setAttribute( 'role', 'alert' );
				p.textContent = opts.error;
				var old = form.querySelector( '.uaip-sfw-2fa-error' );
				if ( old ) {
					old.remove();
				}
				login.insertAdjacentElement( 'afterend', p );
			} );
		} );
	}

	// Profile page: create and register a new passkey.
	var add = document.getElementById( 'uaip-sfw-passkey-add' );
	if ( add ) {
		var btn = document.getElementById( 'uaip-sfw-passkey-create' );
		var msg = add.querySelector( '.uaip-sfw-passkey-msg' );
		var ajax = add.getAttribute( 'data-ajax' );
		var nonce = add.getAttribute( 'data-nonce' );

		var post = function ( data ) {
			var body = new FormData();
			body.append( '_ajax_nonce', nonce );
			Object.keys( data ).forEach( function ( k ) {
				body.append( k, data[ k ] );
			} );
			return fetch( ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
				return r.json();
			} );
		};
		var fail = function ( text ) {
			btn.disabled = false;
			msg.textContent = text || add.getAttribute( 'data-failed' );
			msg.classList.add( 'is-error' );
		};

		if ( ! supported() ) {
			btn.disabled = true;
			msg.textContent = add.getAttribute( 'data-unsupported' );
		}
		btn.addEventListener( 'click', function () {
			btn.disabled = true;
			msg.textContent = '';
			msg.classList.remove( 'is-error' );
			post( { action: 'uaip_sfw_passkey_options' } ).then( function ( res ) {
				if ( ! res || ! res.success ) {
					throw new Error( '' );
				}
				var o = res.data;
				return navigator.credentials.create( {
					publicKey: {
						challenge: fromB64url( o.challenge ),
						rp: o.rp,
						user: { id: fromB64url( o.user.id ), name: o.user.name, displayName: o.user.displayName },
						pubKeyCredParams: [
							{ type: 'public-key', alg: -7 },
							{ type: 'public-key', alg: -8 },
							{ type: 'public-key', alg: -257 }
						],
						excludeCredentials: descriptors( o.exclude ),
						authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
						attestation: 'none',
						timeout: 120000
					}
				} );
			} ).then( function ( cred ) {
				return post( {
					action: 'uaip_sfw_passkey_register',
					client: toB64url( cred.response.clientDataJSON ),
					attestation: toB64url( cred.response.attestationObject ),
					name: document.getElementById( 'uaip-sfw-passkey-name' ).value
				} );
			} ).then( function ( res ) {
				if ( res && res.success ) {
					window.location.href = add.getAttribute( 'data-done' );
					return;
				}
				fail( res && res.data && res.data.message );
			} ).catch( function () {
				fail();
			} );
		} );
	}
}() );
