/* UAIP Security admin helpers */
( function () {
	'use strict';

	document.addEventListener( 'click', function ( e ) {
		var btn = e.target.closest( '.uaip-sfw-copy' );
		if ( ! btn ) {
			return;
		}
		e.preventDefault();
		var text = btn.getAttribute( 'data-clip' ) || '';
		var done = function () {
			var label = btn.textContent;
			btn.textContent = 'Copied!';
			setTimeout( function () { btn.textContent = label; }, 1500 );
		};
		if ( navigator.clipboard && navigator.clipboard.writeText ) {
			navigator.clipboard.writeText( text ).then( done ).catch( done );
		} else {
			var ta = document.createElement( 'textarea' );
			ta.value = text;
			document.body.appendChild( ta );
			ta.select();
			try { document.execCommand( 'copy' ); } catch ( err ) {}
			document.body.removeChild( ta );
			done();
		}
	} );

	// Forms that need a confirmation (data-confirm="Question?").
	document.addEventListener( 'submit', function ( e ) {
		var form = e.target;
		var ask  = form && form.getAttribute ? form.getAttribute( 'data-confirm' ) : null;
		if ( ask && ! window.confirm( ask ) ) {
			e.preventDefault();
		}
	} );

	// Scan progress: drive the scan in short steps while the page is open, so it
	// finishes even when WP-Cron is slow or disabled, then reload with results.
	var bar = document.getElementById( 'uaip-sfw-scan-progress' );
	if ( bar && window.fetch ) {
		var fill  = bar.querySelector( '.uaip-sfw-progress-fill' );
		var label = bar.querySelector( '.uaip-sfw-progress-label' );
		var tick  = function () {
			var body = new window.FormData();
			body.append( 'action', 'uaip_sfw_scan_step' );
			body.append( '_ajax_nonce', bar.getAttribute( 'data-nonce' ) );
			window.fetch( bar.getAttribute( 'data-ajax' ), { method: 'POST', credentials: 'same-origin', body: body } )
				.then( function ( r ) { return r.json(); } )
				.then( function ( res ) {
					var p = res && res.data ? res.data : null;
					if ( ! p || ! p.running ) {
						window.location.reload();
						return;
					}
					if ( fill ) {
						fill.style.width = p.percent + '%';
					}
					if ( label && p.text ) {
						label.textContent = p.text;
					}
					setTimeout( tick, 1500 );
				} )
				.catch( function () { setTimeout( tick, 5000 ); } );
		};
		setTimeout( tick, 500 );
	}

	// Auto-advance focus on the verification code field.
	var code = document.querySelector( '.uaip-sfw-code-input' );
	if ( code ) {
		code.focus();
		code.addEventListener( 'input', function () {
			this.value = this.value.replace( /\D/g, '' ).slice( 0, 6 );
		} );
	}
}() );
