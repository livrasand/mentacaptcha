class CapWidget extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.token = null;
        this.sessionId = null;
        this.sessionSignature = null;
    }

    connectedCallback() {
        this.render();
        this.initSession();
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
        const initialLabel = this.i18n('initial-state', "Verify you're human");
        const privacyLabel = this.i18n('privacy', 'Privacy');
        const termsLabel = this.i18n('terms', 'Terms');
        const privacyUrl = this.getAttribute('data-cap-privacy-url');
        const termsUrl = this.getAttribute('data-cap-terms-url');
        const ep = this.getAttribute('data-cap-api-endpoint') || '';
        const logoUrl = ep.replace(/\/*$/, '') + '/menta-logo.svg';
        const privacyLink = privacyUrl ? `<a href="${privacyUrl}" target="_blank" rel="noopener" class="link">${privacyLabel}</a>` : `<span class="link">${privacyLabel}</span>`;
        const termsLink = termsUrl ? `<a href="${termsUrl}" target="_blank" rel="noopener" class="link">${termsLabel}</a>` : `<span class="link">${termsLabel}</span>`;
        this.shadowRoot.innerHTML = `
<style>
:host { display: inline-block; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.container { display:flex; align-items:center; width:300px; height:70px; background:#fff; border:1px solid #e0e0e0; border-radius:20px; padding:0 15px; position:relative; box-shadow:0 2px 4px rgba(0,0,0,0.05); cursor:pointer; user-select:none; }
.container:hover { border-color:#bdbdbd; }
.container:focus-visible { outline: 2px solid #333; outline-offset: 2px; }
.checkbox { width:24px; height:24px; border:2px solid #d1d1d1; border-radius:6px; margin-right:15px; display:flex; align-items:center; justify-content:center; }
.label { font-size:16px; color:#333; flex-grow:1; }
.brand { position:absolute; right:20px; bottom:24px; font-size:12px; color:#757575; text-decoration:underline; text-underline-offset:3px; }
.logo { position:absolute; right:20px; bottom:42px; width:24px; height:24px; }
.spinner { display:none; width:18px; height:18px; border:2px solid #f3f3f3; border-top:2px solid #333; border-radius:50%; animation:spin 1s linear infinite; }
@media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
@keyframes spin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }
.solved .checkbox { background:#f0f0f0; border-color:#4CAF50; }
.solved .checkbox::after { content:'\u2713'; color:#4CAF50; font-weight:bold; }
.links { position:absolute; right:20px; bottom:8px; display:flex; gap:0.4rem; font-size:8px; color:#757575; }
.links .link { color:#757575; text-decoration:underline; text-underline-offset:2px; }
.links .link:hover { color:#333; }
.links span.link { text-decoration:none; cursor:default; }
.mint-accent { fill: #2ECC71; color: #2ECC71; }
.message { display:none; margin-top:6px; font-size:11px; color:#757575; max-width:300px; line-height:1.4; }
.message.protected { color:#2ECC71; }
</style>
<div class="container" id="box" role="button" tabindex="0" aria-label="${initialLabel}" aria-live="polite" aria-atomic="true" dir="${dir}">
  <div class="checkbox" id="check" aria-hidden="true"><div class="spinner" id="spin"></div></div>
  <span class="label" id="label">${initialLabel}</span>
  <span class="brand">Menta<span class="mint-accent">.</span></span>
  <div class="links" id="links">
    ${privacyLink} &middot; ${termsLink}
  </div>
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