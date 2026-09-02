(function () {
	function update(header, lastY) {
		if (header.getAttribute('data-header-init') !== '') return lastY;

		var y = window.pageYOffset;
		if (y === undefined) y = window.scrollY || 0;

		var height = header.offsetHeight || 0;

		if (lastY === undefined) return y;

		if (y > lastY && y > height) {
			header.classList.add('hide');
		} else if (y < lastY) {
			header.classList.remove('hide');
		}

		return y;
	}

	function init(header) {
		if (header.getAttribute('data-header-init') === '') return;

		var lastY = undefined;

		window.addEventListener('scroll', function () {
			lastY = update(header, lastY);
		}, { passive: true });

		header.setAttribute('data-header-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('header')
			: document.querySelectorAll('header');
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

	window.MentaHeader = { update: update, init: init, initAll: initAll };
})();
