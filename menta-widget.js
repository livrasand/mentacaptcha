class CapWidget extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.token = null;
        this.sessionId = null;
        this.sessionSignature = null;
        this.rendered = false;
    }

    static get observedAttributes() {
        return [
            'data-cap-theme', 'data-cap-background', 'data-cap-text-color',
            'data-cap-border-color', 'data-cap-hover-border-color', 'data-cap-border-width',
            'data-cap-border-radius', 'data-cap-box-shadow', 'data-cap-width', 'data-cap-height',
            'data-cap-padding', 'data-cap-font-family', 'data-cap-font-size', 'data-cap-font-weight',
            'data-cap-checkbox-size', 'data-cap-checkbox-border-color', 'data-cap-checkbox-border-radius',
            'data-cap-checkbox-background', 'data-cap-primary-color', 'data-cap-checkmark-color',
            'data-cap-success-background', 'data-cap-brand-color', 'data-cap-brand-bottom',
            'data-cap-links-bottom', 'data-cap-link-color', 'data-cap-link-hover-color',
            'data-cap-focus-outline-color', 'data-cap-spinner-color', 'data-cap-css',
            'data-cap-api-endpoint', 'data-cap-rtl',
            'data-cap-i18n-initial-state', 'data-cap-i18n-loading', 'data-cap-i18n-verifying',
            'data-cap-i18n-success', 'data-cap-i18n-error', 'data-cap-i18n-not-authorized',
            'data-cap-i18n-not-authorized-detail'
        ];
    }

    connectedCallback() {
        this.render();
        this.initSession();
        const theme = this.getAttribute('data-cap-theme') || 'light';
        if (theme.toLowerCase() === 'auto' && window.matchMedia) {
            this._mq = window.matchMedia('(prefers-color-scheme: dark)');
            this._mqHandler = () => this.render();
            if (this._mq.addEventListener) this._mq.addEventListener('change', this._mqHandler);
        }
    }

    disconnectedCallback() {
        if (this._mq && this._mqHandler && this._mq.removeEventListener) {
            this._mq.removeEventListener('change', this._mqHandler);
        }
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (oldValue === newValue) return;
        if (this.rendered && name.startsWith('data-cap-')) {
            this.render();
        }
    }

    i18n(key, fallback) {
        const val = this.getAttribute('data-cap-i18n-' + key);
        return val !== null && val !== '' ? val : fallback;
    }

    get isRTL() {
        if (this.hasAttribute('data-cap-rtl')) {
            const v = this.getAttribute('data-cap-rtl');
            return v !== 'false';
        }
        const host = this.getAttribute('data-cap-rtl') !== null;
        if (host) return true;
        if (this.closest('[dir]') && this.closest('[dir]').getAttribute('dir') === 'rtl') return true;
        return document.dir === 'rtl';
    }

    get headers() {
        return { 'Content-Type': 'application/json' };
    }

    get config() {
        const a = (key, fb) => {
            const v = this.getAttribute('data-cap-' + key);
            return v !== null && v !== '' ? v : fb;
        };
        const theme = a('theme', 'light').toLowerCase();
        const dark = theme === 'dark' ||
            (theme === 'auto' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
        const D = dark ? {
            text: '#e6e6e6', background: '#212121', border: '#424242', hoverBorder: '#5c5c5c',
            checkboxBorder: '#5c5c5c', checkboxBackground: '#2a2a2a',
            shadow: '0 2px 6px rgba(0,0,0,0.5)', link: '#9e9e9e', linkHover: '#ffffff',
            brand: '#9e9e9e', focus: '#e6e6e6', spinner: '#e6e6e6'
        } : {
            text: '#333333', background: '#ffffff', border: '#e0e0e0', hoverBorder: '#bdbdbd',
            checkboxBorder: '#d1d1d1', checkboxBackground: '#ffffff',
            shadow: '0 2px 4px rgba(0,0,0,0.05)', link: '#757575', linkHover: '#333333',
            brand: '#757575', focus: '#333333', spinner: '#757575'
        };
        const primary = a('primary-color', '#2ECC71');
        return {
            theme,
            fontFamily: a('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'),
            text: a('text-color', D.text),
            background: a('background', D.background),
            border: a('border-color', D.border),
            hoverBorder: a('hover-border-color', D.hoverBorder),
            borderWidth: a('border-width', '1px'),
            radius: a('border-radius', '20px'),
            shadow: a('box-shadow', D.shadow),
            width: a('width', '300px'),
            height: a('height', '70px'),
            padding: a('padding', '0 15px'),
            fontSize: a('font-size', '16px'),
            fontWeight: a('font-weight', '400'),
            checkboxSize: a('checkbox-size', '24px'),
            checkboxBorder: a('checkbox-border-color', D.checkboxBorder),
            checkboxRadius: a('checkbox-border-radius', '6px'),
            checkboxBackground: a('checkbox-background', D.checkboxBackground),
            primary,
            checkmark: a('checkmark-color', primary),
            successBackground: a('success-background', dark ? '#2a2a2a' : '#f0f0f0'),
            brand: a('brand-color', D.brand),
            brandBottom: a('brand-bottom', '24px'),
            linksBottom: a('links-bottom', '8px'),
            link: a('link-color', D.link),
            linkHover: a('link-hover-color', D.linkHover),
            focus: a('focus-outline-color', D.focus),
            spinner: a('spinner-color', D.spinner),
            css: this.getAttribute('data-cap-css') || ''
        };
    }

    async initSession() {
        const ep = this.getAttribute('data-cap-api-endpoint');
        const headers = { ...this.headers };
        delete headers['Content-Type'];
        try {
            const r = await fetch(ep + '/init', { method: 'POST', headers: headers });
            if (!r.ok) {
                const data = await r.json().catch(() => ({}));
                this._handleError(r.status, data, '/init');
                return;
            }
            const d = await r.json();
            this.sessionId = d.session_id;
            this.sessionSignature = d.session_signature;
        } catch(e) {
            // Suppress init error, will retry on click
        }
    }

    _handleError(status, data, endpoint) {
        const box = this.shadowRoot.getElementById('box');
        const label = this.shadowRoot.getElementById('label');
        const msg = this.shadowRoot.getElementById('message');
        const spin = this.shadowRoot.getElementById('spin');
        if (spin) spin.style.display = 'none';
        const origin = data.origin || this.getAttribute('data-cap-api-endpoint') || 'unknown';
        if (status === 403) {
            label.innerText = this.i18n('not-authorized', 'Protected by Menta');
            if (msg) {
                msg.innerText = this.i18n('not-authorized-detail', 'This domain is not registered or authorized by Menta.');
                msg.classList.add('protected');
                msg.style.display = 'block';
            }
            console.warn('[Menta protection] This website is not registered or authorized by Menta.', { status, endpoint, origin, support_url: data.support_url, error: data.error });
        } else {
            label.innerText = this.i18n('error', 'Error. Try again.');
            if (msg) {
                msg.innerText = data.error || this.i18n('error', 'Error. Try again.');
                msg.style.display = 'block';
            }
            console.warn('[Menta] Request failed.', { status, endpoint, error: data.error });
        }
        if (box) {
            box.setAttribute('aria-label', label.innerText);
            box.setAttribute('aria-busy', 'false');
        }
    }

    render() {
        const rtl = this.isRTL;
        const dir = rtl ? 'rtl' : 'ltr';
        const c = this.config;
        const initialLabel = this.i18n('initial-state', "Verify you're human");

        const vars = [
            ['--cap-font', c.fontFamily],
            ['--cap-text', c.text],
            ['--cap-background', c.background],
            ['--cap-border', c.border],
            ['--cap-hover-border', c.hoverBorder],
            ['--cap-border-width', c.borderWidth],
            ['--cap-radius', c.radius],
            ['--cap-shadow', c.shadow],
            ['--cap-width', c.width],
            ['--cap-height', c.height],
            ['--cap-padding', c.padding],
            ['--cap-font-size', c.fontSize],
            ['--cap-font-weight', c.fontWeight],
            ['--cap-checkbox-size', c.checkboxSize],
            ['--cap-checkbox-border', c.checkboxBorder],
            ['--cap-checkbox-radius', c.checkboxRadius],
            ['--cap-checkbox-bg', c.checkboxBackground],
            ['--cap-primary', c.primary],
            ['--cap-checkmark', c.checkmark],
            ['--cap-solved-bg', c.successBackground],
            ['--cap-brand', c.brand],
            ['--cap-brand-bottom', c.brandBottom],
            ['--cap-links-bottom', c.linksBottom],
            ['--cap-link', c.link],
            ['--cap-link-hover', c.linkHover],
            ['--cap-focus', c.focus],
            ['--cap-spinner', c.spinner]
        ].map(([k, v]) => `${k}:${v};`).join('\n');

        const extra = c.css ? `\n${c.css}` : '';

        this.shadowRoot.innerHTML = `
<style>
:host { display: inline-block; font-family: var(--cap-font); ${vars} }
.container { display:flex; align-items:center; width:var(--cap-width); height:var(--cap-height); background:var(--cap-background); border:var(--cap-border-width) solid var(--cap-border); border-radius:var(--cap-radius); padding:var(--cap-padding); position:relative; box-shadow:var(--cap-shadow); cursor:pointer; user-select:none; box-sizing:border-box; }
.container:hover { border-color:var(--cap-hover-border); }
.container:focus-visible { outline:2px solid var(--cap-focus); outline-offset:2px; }
.checkbox { width:var(--cap-checkbox-size); height:var(--cap-checkbox-size); border:2px solid var(--cap-checkbox-border); border-radius:var(--cap-checkbox-radius); margin-right:15px; display:flex; align-items:center; justify-content:center; background:var(--cap-checkbox-bg); flex-shrink:0; box-sizing:border-box; }
.container[dir="rtl"] .checkbox { margin-right:0; margin-left:15px; }
.label { font-size:var(--cap-font-size); color:var(--cap-text); flex-grow:1; font-weight:var(--cap-font-weight); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.brand { position:absolute; right:20px; bottom:var(--cap-brand-bottom); font-size:12px; color:var(--cap-brand); text-decoration:underline; text-underline-offset:3px; }
.spinner { display:none; width:18px; height:18px; border:2px solid rgba(128,128,128,0.25); border-top-color:var(--cap-spinner); border-radius:50%; animation:spin 1s linear infinite; }
@media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
@keyframes spin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }
.solved .checkbox { background:var(--cap-solved-bg); border-color:var(--cap-primary); }
.solved .checkbox::after { content:'\\u2713'; color:var(--cap-checkmark); font-weight:bold; font-size:calc(var(--cap-checkbox-size) * 0.75); line-height:1; }
.links { position:absolute; right:20px; bottom:var(--cap-links-bottom); display:flex; gap:0.4rem; font-size:8px; color:var(--cap-link); }
.links .link { color:var(--cap-link); text-decoration:underline; text-underline-offset:2px; }
.links .link:hover { color:var(--cap-link-hover); }
.links span.link { text-decoration:none; cursor:default; }
.mint-accent { fill: var(--cap-primary); color: var(--cap-primary); }
.message { display:none; margin-top:6px; font-size:11px; color:var(--cap-link); max-width:300px; line-height:1.4; }
.message.protected { color:var(--cap-primary); }
${extra}
</style>
<div class="container" id="box" role="button" tabindex="0" aria-label="${initialLabel}" aria-live="polite" aria-atomic="true" dir="${dir}">
  <div class="checkbox" id="check" aria-hidden="true"><div class="spinner" id="spin"></div></div>
  <span class="label" id="label">${initialLabel}</span>
  <span class="brand">Menta<span class="mint-accent">.</span></span>
</div>
<div class="message" id="message" style="display:none;"></div>`;

        const box = this.shadowRoot.getElementById('box');
        box.addEventListener('click', () => this.solve());
        box.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.solve();
            }
        });
        this.rendered = true;
    }

    async solve() {
        const ep = this.getAttribute('data-cap-api-endpoint');
        const box = this.shadowRoot.getElementById('box');
        const label = this.shadowRoot.getElementById('label');
        const spin = this.shadowRoot.getElementById('spin');
        if (this.token) return;

        const loadingLabel = this.i18n('loading', 'Initializing...');
        const verifyingLabel = this.i18n('verifying', 'Verifying...');
        const successLabel = this.i18n('success', "You're human");

        if (!this.sessionId) {
            label.innerText = loadingLabel;
            box.setAttribute('aria-label', loadingLabel);
            box.setAttribute('aria-busy', 'true');
            try {
                const initHeaders = { ...this.headers };
                delete initHeaders['Content-Type'];
                const r = await fetch(ep + '/init', { method: 'POST', headers: initHeaders });
                if (!r.ok) {
                    const data = await r.json().catch(() => ({}));
                    this._handleError(r.status, data, '/init');
                    return;
                }
                const d = await r.json();
                this.sessionId = d.session_id;
                this.sessionSignature = d.session_signature;
            } catch(e) {
                this._handleError(0, { error: this.i18n('error', 'Error. Try again.') }, '/init');
                return;
            }
        }

        label.innerText = verifyingLabel;
        box.setAttribute('aria-label', verifyingLabel);
        box.setAttribute('aria-busy', 'true');
        spin.style.display = "block";
        try {
            const r = await fetch(ep + '/challenge', {
                method: 'POST',
                headers: this.headers,
                body: JSON.stringify({ session_id: this.sessionId, session_signature: this.sessionSignature })
            });
            if (!r.ok) {
                const data = await r.json().catch(() => ({}));
                this._handleError(r.status, data, '/challenge');
                this.sessionId = null;
                this.sessionSignature = null;
                return;
            }
            const { token, challenge } = await r.json();
            let nonce = 0;
            while (true) {
                const h = await this.sha256(challenge.salt + nonce);
                if (h.startsWith(challenge.target)) break;
                nonce++;
            }
            const v = await fetch(ep + '/redeem', {
                method: 'POST',
                headers: this.headers,
                body: JSON.stringify({ session_id: this.sessionId, token, solutions: nonce, challenge_signature: challenge.challenge_signature })
            });
            if (!v.ok) {
                const data = await v.json().catch(() => ({}));
                this._handleError(v.status, data, '/redeem');
                this.sessionId = null;
                this.sessionSignature = null;
                return;
            }
            const result = await v.json();
            if (result.success) {
                spin.style.display = "none";
                label.innerText = successLabel;
                box.setAttribute('aria-label', successLabel);
                box.setAttribute('aria-busy', 'false');
                box.classList.add('solved');
                this.token = result.token;
                this.dispatchEvent(new CustomEvent('solve', { detail: { token: result.token }, bubbles: true, composed: true }));
            } else {
                this._handleError(0, result, '/redeem');
                this.sessionId = null;
                this.sessionSignature = null;
            }
        } catch(e) {
            this._handleError(0, { error: this.i18n('error', 'Error. Try again.') }, '/challenge');
            this.sessionId = null;
            this.sessionSignature = null;
        }
    }

    async sha256(m) {
        const b = new TextEncoder().encode(m);
        const d = await crypto.subtle.digest('SHA-256', b);
        return Array.from(new Uint8Array(d)).map(x => x.toString(16).padStart(2,'0')).join('');
    }
}
customElements.define('menta-widget', CapWidget);