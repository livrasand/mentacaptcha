(function () {
	function create(container, options) {
		return new IntersectionObserver(function (entries) {
			var intersecting = false;
			for (var i = 0; i < entries.length; i++) {
				if (entries[i].isIntersecting) {
					intersecting = true;
					break;
				}
			}
			if (!intersecting) return;

			container.dispatchEvent(
				new CustomEvent('menta:load-more', {
					detail: { container: container },
					bubbles: true
				})
			);
		}, options);
	}

	function init(container) {
		if (container.getAttribute('data-infinite-scroll-init') === '') return;

		var target = container.querySelector('.intersection-observer-target');
		if (!target) {
			container.setAttribute('data-infinite-scroll-init', '');
			return;
		}

		var rootMargin = container.getAttribute('data-root-margin') || '300px';
		var threshold = parseFloat(
			container.getAttribute('data-threshold') || '0'
		);

		var observer = create(container, { rootMargin: rootMargin, threshold: threshold });

		if (container.getAttribute('data-disabled') === '') {
			container._mentaObserver = observer;
			container.setAttribute('data-infinite-scroll-init', '');
			return;
		}

		observer.observe(target);
		container._mentaObserver = observer;
		container.setAttribute('data-infinite-scroll-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('[data-infinite-scroll]')
			: document.querySelectorAll('[data-infinite-scroll]');
		for (var i = 0; i < list.length; i++) init(list[i]);
	}

	// Allow toggling observation while a container is active (disabled / re-enable).
	function setDisabled(container, disabled) {
		var observer = container._mentaObserver;
		if (!observer) return;
		var target = container.querySelector('.intersection-observer-target');
		if (disabled) {
			if (target) observer.unobserve(target);
		} else {
			if (target) observer.observe(target);
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

	window.MentaInfiniteScroll = {
		initAll: initAll,
		setDisabled: setDisabled
	};
})();
