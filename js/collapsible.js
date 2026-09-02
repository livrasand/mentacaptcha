(function () {
	function toggle(collapsible, header, force) {
		var wrapper = collapsible.querySelector('.wrapper');
		if (!wrapper) return;

		var expanded =
			force !== undefined ? force : !wrapper.classList.contains('expanded');

		wrapper.classList.toggle('expanded', expanded);

		if (header) {
			header.setAttribute('aria-expanded', String(expanded));
			var btn = header.querySelector('.square');
			if (btn) btn.setAttribute('aria-expanded', String(expanded));
		}
	}

	function init(collapsible) {
		if (collapsible.getAttribute('data-collapsible-init') === '') return;

		var header = collapsible.querySelector('.header');
		if (!header) {
			collapsible.setAttribute('data-collapsible-init', '');
			return;
		}

		if (!header.hasAttribute('role')) header.setAttribute('role', 'button');
		if (!header.hasAttribute('tabindex')) header.setAttribute('tabindex', '0');
		if (!header.hasAttribute('aria-expanded'))
			header.setAttribute('aria-expanded', 'false');

		header.addEventListener('click', function (e) {
			e.preventDefault();
			toggle(collapsible, header);
		});

		header.addEventListener('keydown', function (e) {
			if (e.key === 'Enter' || e.key === ' ') {
				e.preventDefault();
				toggle(collapsible, header);
			}
		});

		collapsible.setAttribute('data-collapsible-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('.collapsible')
			: document.querySelectorAll('.collapsible');
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

	window.MentaCollapsible = { toggle: toggle, init: init, initAll: initAll };
})();
