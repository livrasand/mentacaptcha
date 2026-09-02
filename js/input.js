(function () {
	var DECIMALS_ICON = 8;
	var DECIMALS_CURRENCY = 8;
	var DECIMALS_NUMBER = 0;

	function fixUndefinedValue(value) {
		// Prevent "undefined" string from entering the field.
		return value === undefined || value === null || value === 'undefined'
			? ''
			: value;
	}

	function exponentToPlainNumberString(value) {
		// Expand scientific notation produced by Number.prototype.toString for
		// very large / very small values into a plain decimal string.
		var str = String(value);
		var eIndex = str.toLowerCase().indexOf('e');
		if (eIndex === -1) return str;

		var sign = str.charAt(0) === '-' ? '-' : '';
		var body = sign ? str.slice(1, eIndex) : str.slice(0, eIndex);
		var exp = parseInt(str.slice(eIndex + 1), 10);
		var negative = exp < 0;
		exp = Math.abs(exp);

		var dot = body.indexOf('.');
		var whole = dot === -1 ? body : body.slice(0, dot);
		var frac = dot === -1 ? '' : body.slice(dot + 1);
		var digits = whole + frac;
		var pointAt = whole.length;

		if (!negative) {
			var target = pointAt + exp;
			if (target >= digits.length) {
				return sign + digits + '0'.repeat(target - digits.length);
			}
			return sign + digits.slice(0, target) + '.' + digits.slice(target);
		}

		var finalPos = pointAt - exp;
		if (finalPos <= 0) {
			return sign + '0.' + '0'.repeat(-finalPos) + digits;
		}
		return sign + digits.slice(0, finalPos) + '.' + digits.slice(finalPos);
	}

	function toStringWrapDecimals(number, wrapDecimals) {
		if (number.toString().indexOf('e') !== -1) {
			return exponentToPlainNumberString(number);
		}
		var string = String(number);
		var dot = string.indexOf('.');
		if (dot === -1 || string.length - dot - 1 <= wrapDecimals) {
			return string;
		}
		return string.slice(0, dot + 1) + string.slice(dot + 1, dot + 1 + wrapDecimals);
	}

	function isDecimalsFormat(value, wrapDecimals) {
		return new RegExp('^\\d*(\\.\\d{0,' + wrapDecimals + '})?$').test(value);
	}

	function formatNumber(value, wrapDecimals) {
		var num = Number(value);
		if (isNaN(num)) return '';
		return Number(toStringWrapDecimals(num, wrapDecimals)).toLocaleString('en', {
			useGrouping: false,
			maximumFractionDigits: wrapDecimals
		});
	}

	function build(container) {
		if (container.getAttribute('data-input-field-init') === '') return;

		// The observable field is the native control inside the wrapper.
		var input =
			container.querySelector('input') ||
			container.querySelector('textarea') ||
			container.querySelector('select');

		if (!input) {
			container.setAttribute('data-input-field-init', '');
			return;
		}

		var inputType = container.getAttribute('data-input-type') || 'number';
		var wrapDecimals =
			inputType === 'icp'
				? DECIMALS_ICON
				: parseInt(container.getAttribute('data-decimals') || '', 10);

		if (isNaN(wrapDecimals)) {
			wrapDecimals = inputType === 'currency' ? DECIMALS_CURRENCY : DECIMALS_NUMBER;
		}
		if (inputType !== 'icp' && inputType !== 'currency' && inputType !== 'number') {
			wrapDecimals = DECIMALS_NUMBER;
		}

		var isFormatted = inputType === 'icp' || inputType === 'currency';

		// Save a reference to any existing single property wrappers.
		var existingOnInput = input.oninput;
		var existingOnBlur = input.onblur;

		input.oninput = function (event) {
			handleInput(input, wrapDecimals, isFormatted);
			if (existingOnInput) existingOnInput.call(input, event);
		};
		input.onblur = function (event) {
			handleBlur(input, wrapDecimals, isFormatted);
			if (existingOnBlur) existingOnBlur.call(input, event);
		};

		// Re-hydrate the field.
		var initialValue = container.getAttribute('data-value');
		var safe = fixUndefinedValue(initialValue);
		if (isFormatted) {
			input.value = safe === '' ? '' : formatNumber(safe, wrapDecimals);
		} else {
			input.value = safe;
		}
		input.removeAttribute('value');

		var required = container.getAttribute('data-required') === '';
		if (required) input.setAttribute('aria-required', 'true');

		if (container.getAttribute('data-autofocus') === '' || input.hasAttribute('autofocus')) {
			setTimeout(function () {
				input.focus();
			}, 0);
		}

		container.setAttribute('data-input-field-init', '');
	}

	function handleInput(input, wrapDecimals, isFormatted) {
		if (!isFormatted) return;
		var raw = input.value;
		if (!isDecimalsFormat(raw, wrapDecimals)) {
			// Reject the edit and fall back to the last accepted value.
			restoreFromValidValue(input);
			return;
		}
		input._mentaLastValid = raw;
		if (raw === '') return;
		// Preserve a trailing decimal separator so the user can keep typing.
		if (/\.$/.test(raw)) return;
		input.value = formatNumber(raw, wrapDecimals);
	}

	function handleBlur(input, wrapDecimals, isFormatted) {
		if (!isFormatted) return;
		input.value = formatNumber(input.value || 0, wrapDecimals);
	}

	function restoreFromValidValue(input) {
		if (input._mentaLastValid !== undefined && input._mentaLastValid !== null) {
			input.value = input._mentaLastValid;
			try {
				input.setSelectionRange(input.value.length, input.value.length);
			} catch (e) {}
		}
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('[data-input-field]')
			: document.querySelectorAll('[data-input-field]');
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

	window.MentaInput = { initAll: initAll };
})();
