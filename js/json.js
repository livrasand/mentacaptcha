(function () {
	function isHash(bytes) {
		return (
			Array.isArray(bytes) &&
			bytes.length === 32 &&
			bytes.find(function (value) {
				return !Number.isInteger(value) || value < 0 || value > 255;
			}) === undefined
		);
	}

	function bytesToHexString(bytes) {
		return bytes.reduce(function (str, byte) {
			return str + byte.toString(16).padStart(2, '0');
		}, '');
	}

	function isPrincipal(value) {
		return typeof value === 'object' && value !== null && value._isPrincipal === true;
	}

	function stringifyJson(value) {
		return JSON.stringify(value, function (_key, val) {
			switch (typeof val) {
				case 'function':
					return 'f () { ... }';
				case 'symbol':
					return val.toString();
				case 'object':
					if (val === null) return val;
					if (isPrincipal(val)) {
						var asText = val.toString();
						return asText === '[object Object]' ? val : asText;
					}
					if (Array.isArray(val) && isHash(val)) {
						return bytesToHexString(val);
					}
					if (val instanceof Promise) {
						return 'Promise(...)';
					}
					if (val instanceof ArrayBuffer) {
						return new Uint8Array(val).toString();
					}
					break;
				case 'bigint':
					return val.toString();
			}
			return val;
		});
	}

	function getValueType(json, value) {
		if (value === null) {
			return 'null';
		}
		if (isPrincipal(value)) {
			return 'principal';
		}
		if (Array.isArray(json) && isHash(json)) {
			return 'hash';
		}
		return typeof value;
	}

	function setState(node) {
		var valueType = getValueType(node.data, node.json);
		var isExpandable = valueType === 'object';
		var value = isExpandable ? node.json : stringifyJson(node.json);
		var keyLabel = node.key + (node.key.length > 0 ? ': ' : '');
		var children = isExpandable ? Object.entries(node.json) : [];
		var hasChildren = children.length > 0;
		var isArray = Array.isArray(node.json);
		var openBracket = isArray ? '[' : '{';
		var closeBracket = isArray ? ']' : '}';
		var root = node.level === 1;

		node.valueType = valueType;
		node.isExpandable = isExpandable;
		node.value = value;
		node.keyLabel = keyLabel;
		node.children = children;
		node.hasChildren = hasChildren;
		node.isArray = isArray;
		node.openBracket = openBracket;
		node.closeBracket = closeBracket;
		node.root = root;

		node.title =
			valueType === 'hash' && Array.isArray(node.json) ? node.json.join() : undefined;
		node.collapsed =
			node.collapsed === undefined
				? node.defaultExpandedLevel < node.level
				: node.collapsed;
	}

	function setNodeCollapsed(node, collapsed) {
		node.collapsed = collapsed;
		renderNode(node);
	}

	function toggle(node) {
		setNodeCollapsed(node, !node.collapsed);
	}

	function handleKeyPress(event, node) {
		if (!['Enter', 'Space'].includes(event.code)) {
			return;
		}
		event.preventDefault();
		toggle(node);
	}

	function makeElement(tag, className, attrs, text) {
		var el = document.createElement(tag);
		if (className) el.className = className;
		if (attrs) {
			Object.keys(attrs).forEach(function (name) {
				el.setAttribute(name, attrs[name]);
			});
		}
		if (text !== undefined) {
			el.textContent = text;
		}
		return el;
	}

	function renderSpan(node) {
		if (node.isExpandable && node.hasChildren) {
			var keyClass = 'key' + (node.isExpandable && node.hasChildren ? ' arrow' : '') +
				(node.collapsed ? ' collapsed' : ' expanded') +
				(node.root ? ' root' : '');
			var attrs = {
				'aria-label': 'Toggle',
				role: 'button',
				tabindex: '0'
			};
			if (node.root) attrs['data-tid'] = 'json';

			var span = makeElement('span', keyClass, attrs);
			span.appendChild(document.createTextNode(node.keyLabel));

			if (node.collapsed) {
				var bracket = makeElement(
					'span',
					'bracket',
					null,
					node.openBracket + ' ... ' + node.closeBracket
				);
				span.appendChild(bracket);
			} else {
				var openBracketEl = makeElement('span', 'bracket open', null, node.openBracket);
				span.appendChild(openBracketEl);
			}
			span.addEventListener('click', function () {
				toggle(node);
			});
			span.addEventListener('keydown', function (event) {
				handleKeyPress(event, node);
			});
			return span;
		}

		if (node.isExpandable) {
			var noChildrenClass = 'key' + (node.root ? ' root' : '');
			var noChildrenAttrs = {};
			if (node.root) noChildrenAttrs['data-tid'] = 'json';
			var emptySpan = makeElement('span', noChildrenClass, noChildrenAttrs);
			emptySpan.appendChild(document.createTextNode(node.keyLabel));
			var emptyBracket = makeElement(
				'span',
				'bracket',
				null,
				node.openBracket + ' ' + node.closeBracket
			);
			emptySpan.appendChild(emptyBracket);
			return emptySpan;
		}

		var kv = makeElement('span', 'key-value');
		var keyCls = 'key' + (node.root ? ' root' : '');
		var keyAttrs = {};
		if (node.root) keyAttrs['data-tid'] = 'json';
		var keyEl = makeElement('span', keyCls, keyAttrs, node.keyLabel);
		var valueAttrs = {};
		if (node.title !== undefined) valueAttrs.title = node.title;
		var valueText =
			node.valueType === 'undefined' && node.value === undefined
				? 'undefined'
				: String(node.value);
		var valueEl = makeElement(
			'span',
			'value ' + node.valueType,
			valueAttrs,
			valueText
		);
		kv.appendChild(keyEl);
		kv.appendChild(valueEl);
		return kv;
	}

	function renderNode(node) {
		node.container.textContent = '';

		var span = renderSpan(node);
		node.container.appendChild(span);

		if (node.isExpandable && node.hasChildren && !node.collapsed) {
			var ul = makeElement('ul');
			for (var i = 0; i < node.children.length; i++) {
				var child = node.children[i];
				var li = makeElement('li');
				var childContainer = makeElement('span', 'node');
				var childNode = {
					container: childContainer,
					json: child[1],
					key: child[0],
					level: node.level + 1,
					defaultExpandedLevel: node.defaultExpandedLevel,
					forceCollapsed: node.forceCollapsed,
					children: [],
					collapsed: undefined
				};
				if (node.forceCollapsed) {
					childNode.collapsed = true;
				}
				renderChild(childNode);
				li.appendChild(childNode.tree);
				ul.appendChild(li);
			}
			node.container.appendChild(ul);
			var closeEl = makeElement('span', 'bracket close', null, node.closeBracket);
			node.container.appendChild(closeEl);
		}

		return node.container;
	}

	function renderChild(node) {
		setState(node);
		node.tree = renderNode(node);
	}

	function build(container) {
		if (container.getAttribute('data-json-init') === '') return;

		var script = container.querySelector('script[type="application/json"]');
		var json = null;
		if (script) {
			json = JSON.parse(script.textContent);
		} else if (container.hasAttribute('data-json-value')) {
			json = JSON.parse(container.getAttribute('data-json-value'));
		}

		var defaultExpandedLevel = Infinity;
		if (container.hasAttribute('data-default-expanded-level')) {
			defaultExpandedLevel = Number(container.getAttribute('data-default-expanded-level'));
		}

		var forceCollapsed = container.hasAttribute('data-collapsed');

		var rootNode = {
			container: container,
			json: json,
			key: '',
			level: 1,
			defaultExpandedLevel: defaultExpandedLevel,
			forceCollapsed: forceCollapsed,
			children: [],
			collapsed: forceCollapsed ? true : undefined
		};
		setState(rootNode);
		renderNode(rootNode);

		container.setAttribute('data-json-init', '');
	}

	function initAll(root) {
		var list = root
			? root.querySelectorAll('[data-json]')
			: document.querySelectorAll('[data-json]');
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

	window.MentaJson = { initAll: initAll };
})();
