(function () {
	var AUTORENEW_ICON =
		'<svg width="20" height="20" viewBox="0 -960 960 960" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M221-319q-20-35-30.5-76.5T180-480q0-125 87.5-212.5T480-780h26l-52-52 56-56 148 148-148 148-56-56 52-52h-26q-92 0-156 64t-64 156q0 34 8.5 66.5T367-362l-54 43h-92v-80l0 80Zm-41 159v-60h168v60H180Zm300-20q92 0 156-64t64-156q0-34-8.5-66.5T593-598l54-43h133v80h-80v60h-80v-60h80v-80h-60l80-80 80 80h-100v160H220v-60h80v-80h-80v-60h260q-125 0-212.5 87.5T180-480q0 55 16 103t45 87l-1 28-60 62Zm300 20v-60h168v60H480Z"/></svg>';

	function iconFor(size) {
		return AUTORENEW_ICON.replace('width="20"', 'width="' + size + '"').replace(
			'height="20"',
			'height="' + size + '"'
		);
	}

	function handler(container) {
		var fnName = container.getAttribute('data-generate');
		if (fnName && typeof window[fnName] === 'function') {
			return window[fnName].bind(null, container);
		}
		var eventName = container.getAttribute('data-generate-eventname') || 'menta:generate';
		return function () {
			var input = container.querySelector('input');
			container.dispatchEvent(
				new CustomEvent(eventName, {
					detail: {
						container: container,
						input: input,
						value: input ? input.value : undefined
					},
					bubbles: true
				})
			);
		};
	}

	function build(container) {
		if (container.getAttribute('data-form-key-init') === '') return;

		var input = container.querySelector('input');
		if (!input) {
			container.setAttribute('data-form-key-init', '');
			return;
		}

		var initialValue = container.getAttribute('data-value');
		if (initialValue !== null) input.value = initialValue;

		var button = container.querySelector('button');
		if (button) {
			var label = container.getAttribute('data-generate-label');
			if (label) button.setAttribute('aria-label', label);
			if (!button.querySelector('svg') && !button.textContent.trim()) {
				var size = container.getAttribute('data-icon-size') || '20px';
				button.insertAdjacentHTML('afterbegin', iconFor(size));
			}
			button.addEventListener('click', handler(container));
		}

		container.setAttribute('data-form-key-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('[data-form-key]')
			: document.querySelectorAll('[data-form-key]');
		for (var i = 0; i < list.length; i++) build(list[i]);
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

	window.MentaFormKey = { initAll: initAll };
})();
