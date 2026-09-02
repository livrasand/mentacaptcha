(function () {
	function shortenWithMiddleEllipsis(text, length) {
		if (!text) return text;
		var max = length || 14;
		if (text.length <= max) return text;
		if (max < 4) return text.slice(0, max);

		var ellipsis = '\u2026'; // …
		var keep = max - 1; // reserve 1 char for the ellipsis
		var half = Math.floor(keep / 2);
		var front = half;
		var back = keep - half;
		return text.slice(0, front) + ellipsis + text.slice(text.length - back);
	}

	var COPY_ICON =
		'<svg width="16" height="16" viewBox="0 -960 960 960" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M360-240q-33 0-56.5-23.5T280-320v-480q0-33 23.5-56.5T360-880h360q33 0 56.5 23.5T800-800v480q0 33-23.5 56.5T720-240H360Zm0-80h360v-480H360v480ZM200-80q-33 0-56.5-23.5T120-160v-560h80v560h440v80H200Z"/></svg>';

	function build(container) {
		if (container.getAttribute('data-identifier-init') === '') return;

		var identifier = container.getAttribute('data-identifier');
		if (!identifier) {
			container.setAttribute('data-identifier-init', '');
			return;
		}

		var shorten = container.getAttribute('data-shorten') !== 'false';
		var shortenLength = parseInt(container.getAttribute('data-shorten-length') || '', 10);
		var what = container.getAttribute('data-what') || '';

		var display = shorten
			? shortenWithMiddleEllipsis(identifier, shortenLength)
			: identifier;

		var span = document.createElement('span');
		span.textContent = display;

		var button = document.createElement('button');
		button.type = 'button';
		button.className = 'square';
		button.setAttribute('aria-label', 'Copy ' + (what ? what + ' ' : '') + identifier);
		button.setAttribute('data-copy', identifier);
		if (what) button.setAttribute('data-copy-what', what);
		button.innerHTML = COPY_ICON;

		// Only shorten visually when the full value fits; otherwise CSS truncates.
		if (span.textContent.length < identifier.length) {
			span.title = identifier;
		}

		container.textContent = '';
		container.appendChild(span);
		container.appendChild(button);

		container.setAttribute('data-identifier-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('[data-identifier]')
			: document.querySelectorAll('[data-identifier]');
		var copyRoot = root || document;
		for (var i = 0; i < list.length; i++) {
			build(list[i]);
			if (window.MentaCopy) window.MentaCopy.initAll(copyRoot);
		}
	}

	if (typeof document !== 'undefined') {
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', function () {
				initAll(document);
			});
		} else {
			initAll(document);
		}
	}

	window.MentaIdentifier = { shorten: shortenWithMiddleEllipsis, initAll: initAll };
})();
