(function () {
	function copyValue(value, button, what) {
		function showFeedback(ok) {
			if (!button) return;

			var original = button.getAttribute('data-copy-original');
			var label = button.getAttribute('aria-label') || button.textContent || '';
			if (original === null) original = label;

			if (ok) {
				button.textContent = (what ? what + ' ' : '') + 'Copied';
				button.setAttribute('aria-label', (what ? what + ' ' : '') + value + ' copied');
			} else {
				button.textContent = 'Copy failed';
				button.setAttribute('aria-label', 'Could not copy ' + (what || 'value') + '. Please copy manually.');
			}

			button.classList.add(ok ? 'copied' : 'error');
			window.setTimeout(function () {
				button.textContent = original;
				button.setAttribute('aria-label', original);
				button.classList.remove('copied', 'error');
			}, 1500);
		}

		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard
				.writeText(value)
				.then(function () {
					showFeedback(true);
				})
				.catch(function () {
					showFeedback(false);
				});
			return;
		}

		// Fallback for browsers without the async Clipboard API
		try {
			var ta = document.createElement('textarea');
			ta.value = value;
			ta.setAttribute('readonly', '');
			ta.style.position = 'absolute';
			ta.style.left = '-9999px';
			document.body.appendChild(ta);
			ta.select();
			var ok = document.execCommand('copy');
			document.body.removeChild(ta);
			showFeedback(ok);
		} catch (e) {
			showFeedback(false);
		}
	}

	function init(button) {
		if (button.getAttribute('data-copy-init') === '') return;

		var value =
			button.getAttribute('data-copy') ||
			(button.getAttribute('data-copy-target') &&
				document.querySelector(button.getAttribute('data-copy-target')));
		var what = button.getAttribute('data-copy-what') || '';

		if (value === null || value === undefined) {
			button.setAttribute('data-copy-init', '');
			return;
		}

		button.classList.add('square');
		button.setAttribute('data-copy-original', button.getAttribute('aria-label') || button.textContent || '');

		button.addEventListener('click', function (e) {
			e.preventDefault();
			copyValue(value, button, what);
		});

		button.setAttribute('data-copy-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('[data-copy]')
			: document.querySelectorAll('[data-copy]');
		for (var i = 0; i < list.length; i++) init(list[i]);
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

	window.MentaCopy = { copy: copyValue, init: init, initAll: initAll };
})();
