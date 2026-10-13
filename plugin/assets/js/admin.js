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

	// Auto-advance focus on the verification code field.
	var code = document.querySelector( '.uaip-sfw-code-input' );
	if ( code ) {
		code.focus();
		code.addEventListener( 'input', function () {
			this.value = this.value.replace( /\D/g, '' ).slice( 0, 6 );
		} );
	}
}() );
