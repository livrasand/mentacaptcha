(function () {
	var WARNING_ICON =
		'<svg width="24" height="24" viewBox="0 -960 960 960" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M109-120q-11 0-20-5.5T75-140q-5-9-5-20t5-20l371-640q11-20 34-20t34 20l371 640q5 9 5 20t-5 20q-5 9-14 14.5t-20 5.5H109Zm69-80h604L480-720 178-200Zm302-40q17 0 28.5-11.5T520-280q0-17-11.5-28.5T480-320q-17 0-28.5 11.5T440-280q0 17 11.5 28.5T480-240Zm0-120q17 0 28.5-11.5T520-400v-120q0-17-11.5-28.5T480-560q-17 0-28.5 11.5T440-520v120q0 17 11.5 28.5T480-360Z"/></svg>';

	function build(container) {
		if (container.getAttribute('data-warning-init') === '') return;

		var iconSize = container.getAttribute('data-icon-size') || '24px';

		container.innerHTML = WARNING_ICON.replace('width="24"', 'width="' + iconSize + '"').replace(
			'height="24"',
			'height="' + iconSize + '"'
		);

		container.setAttribute('data-warning-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('[data-warning-icon]')
			: document.querySelectorAll('[data-warning-icon]');
		for (var i = 0; i < list.length; i++) {
			build(list[i]);
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

	window.MentaWarning = { initAll: initAll };
})();
