(function () {
    'use strict';
    var script = document.currentScript || (function () { var all = document.getElementsByTagName('script'); return all[all.length - 1]; })();
    function attr(name, fallback) { var v = script ? script.getAttribute(name) : null; return v !== null && v !== '' ? v : fallback; }
    var api = attr('data-menta-api', '').replace(/\/+$/, '');
    var next = attr('data-menta-next', location.pathname);
    var checkingMsg = attr('data-menta-i18n-checking', 'Verifying you are human…');
    var blockedTitle = attr('data-menta-i18n-blocked-title', 'Access denied');
    var blockedDetail = attr('data-menta-i18n-blocked-detail', 'Your request looks automated.');

    var overlay = document.createElement('div');
    overlay.id = 'menta-challenge-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:#fff;z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif';
    overlay.innerHTML = '<div style="text-align:center;max-width:460px;padding:2rem 1.5rem;background:#fff;border:1px solid #e0e0e0;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08)"><div id="ms-spin" style="width:32px;height:32px;margin:0 auto 1.5rem;border:2px solid #e0e0e0;border-top-color:#22c45e;border-radius:50%;animation:ms-spin 0.8s linear infinite"></div><h1 id="ms-heading" style="font-size:1.75rem;font-weight:800;color:#111;margin:0 0 1rem;line-height:1.15">Verifying you are human</h1><p id="ms-status" style="font-size:1.05rem;color:#4a4a4a;margin:0 0 1.25rem;line-height:1.5">Checking your browser…</p><p id="ms-meta" style="font-size:0.875rem;color:#6b7280;margin:0 0 1rem;min-height:1.2em"></p><div id="ms-progress-wrap" style="width:100%;height:8px;background:#e5e7eb;border-radius:4px;overflow:hidden;margin:0 0 1rem"><div id="ms-progress" style="width:0%;height:100%;background:#22c45e;transition:width .2s ease"></div></div><button id="ms-retry" type="button" style="display:none;margin:0 0 1rem;padding:0.6rem 1.4rem;font-size:0.95rem;border:1px solid #e0e0e0;background:#fff;border-radius:8px;cursor:pointer">Try again</button><p style="font-size:0.875rem;color:#6b7280;margin:0">Protected by <a href="https://github.com/livrasand/mentacaptcha" target="_blank" rel="noopener" style="color:#22c45e;text-decoration:underline">Menta</a> from <a href="https://github.com/livrasand" target="_blank" rel="noopener" style="color:#22c45e;text-decoration:underline">livrasand</a>. Made with ☕ in 🇲🇽.</p></div>';
    var style = document.createElement('style');
    style.textContent = '@keyframes ms-spin{to{transform:rotate(360deg)}}@media (prefers-reduced-motion:reduce){#ms-spin{animation:none}}';
    document.head.appendChild(style);
    if (document.body) document.body.appendChild(overlay); else document.addEventListener('DOMContentLoaded', function(){ document.body.appendChild(overlay); });

    function sha256(m){ var b=new TextEncoder().encode(m); return crypto.subtle.digest('SHA-256',b).then(function(d){ return Array.from(new Uint8Array(d)).map(function(x){return x.toString(16).padStart(2,'0');}).join(''); }); }
    function setPowStat(target, hashes, elapsedMs) {
        var t = String(target || '');
        var m = t.match(/^0*/);
        var diff = Math.max(1, m ? m[0].length : 0);
        var hps = elapsedMs > 0 ? hashes / (elapsedMs / 1000) : 0;
        var txt = '—';
        if (isFinite(hps) && hps > 0) {
            if (hps >= 1e6) txt = (hps / 1e6).toFixed(3) + 'MH/s';
            else if (hps >= 1e3) txt = (hps / 1e3).toFixed(3) + 'kH/s';
            else txt = Math.max(1, Math.round(hps)) + 'H/s';
        }
        var el = document.getElementById('ms-meta');
        if (el) el.textContent = 'Difficulty: ' + diff + ', Speed: ' + txt;
        var bar = document.getElementById('ms-progress');
        if (bar && diff > 0) {
            var max = Math.pow(16, diff);
            var pct = Math.min(100, Math.max(0, Math.round((hashes / max) * 100)));
            bar.style.width = pct + '%';
        }
    }

    async function solvePoW(challenge, onProgress) {
        var nonce = 0;
        var start = performance.now();
        var lastTick = start;
        while (true) {
            var h = await sha256(challenge.salt + nonce);
            if (h.startsWith(challenge.target)) {
                if (onProgress) onProgress(nonce + 1, Math.max(1, performance.now() - start));
                return nonce;
            }
            nonce++;
            var now = performance.now();
            if (onProgress && now - lastTick > 50) {
                lastTick = now;
                onProgress(nonce, now - start);
            }
        }
    }

    function showBlocked() {
        var h = document.getElementById('ms-heading');
        var s = document.getElementById('ms-status');
        var m = document.getElementById('ms-meta');
        var spin = document.getElementById('ms-spin');
        var retry = document.getElementById('ms-retry');
        if (h) h.textContent = blockedTitle;
        if (s) { s.textContent = blockedDetail; s.style.color = '#b91c1c'; s.style.fontWeight = '700'; }
        if (m) m.textContent = '';
        if (spin) spin.style.display = 'none';
        if (retry) retry.style.display = 'inline-block';
    }

    function showSuccess() {
        var h = document.getElementById('ms-heading');
        var s = document.getElementById('ms-status');
        var m = document.getElementById('ms-meta');
        var spin = document.getElementById('ms-spin');
        if (h) h.textContent = 'Verification complete';
        if (s) { s.textContent = 'Success! Redirecting…'; s.style.color = '#16a34a'; s.style.fontWeight = '700'; }
        if (m) m.textContent = '';
        if (spin) spin.style.display = 'none';
    }

    async function run(){
        if (!api) {
            console.error('[Menta challenge] data-menta-api is required.');
            showBlocked();
            return;
        }
        var r;
        try {
            r = await fetch(api + '/shield/check', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ path: location.pathname, force: true }) });
        } catch (e) {
            showBlocked();
            return;
        }
        if (r.status === 403){ showBlocked(); return; }
        if (!r.ok) { showBlocked(); return; }
        var verdict;
        try { verdict = await r.json(); } catch (e) { showBlocked(); return; }
        if (verdict.action === 'shield' && verdict.challenge){
            var target = verdict.challenge.target || '';
            if (target.length >= 12 && /^0+$/.test(target)) { showBlocked(); return; }
            document.getElementById('ms-status').textContent = checkingMsg;
            setPowStat(target, 0, 0);
            try {
                var nonce = await solvePoW(verdict.challenge, function (hashes, ms) {
                    setPowStat(target, hashes, ms);
                });
                var v = await fetch(api + '/shield/redeem', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token: verdict.token, solutions: nonce, challenge_signature: verdict.challenge.challenge_signature }) });
                var d = await v.json().catch(function(){return {};});
                if (!v.ok || !d.success){ showBlocked(); return; }
                showSuccess();
                setTimeout(function(){ if (overlay.parentNode) overlay.parentNode.removeChild(overlay); if (next && next !== location.pathname) location.replace(next); }, 1200);
                return;
            } catch (e) { showBlocked(); return; }
        }
        if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        if (next && next !== location.pathname) location.replace(next);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
})();
