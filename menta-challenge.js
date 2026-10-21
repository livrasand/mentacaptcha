(function () {
    'use strict';
    var script = document.currentScript || (function () { var all = document.getElementsByTagName('script'); return all[all.length - 1]; })();
    function attr(name, fallback) { var v = script ? script.getAttribute(name) : null; return v !== null && v !== '' ? v : fallback; }
    var api = (attr('data-menta-api', '') || location.origin).replace(/\/+$/, '');
    var next = attr('data-menta-next', location.pathname);
    var checkingMsg = attr('data-menta-i18n-checking', 'Verifying you are human…');

    var overlay = document.createElement('div');
    overlay.id = 'menta-challenge-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:#fff;z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif';
    overlay.innerHTML = '<div style="text-align:center;padding:2rem 2.5rem;border-radius:12px;border:1px solid #e0e0e0;max-width:320px;box-shadow:0 2px 12px rgba(0,0,0,.08)"><div id="ms-spin" style="width:28px;height:28px;border:3px solid #f0f0f0;border-top-color:#22c45e;border-radius:50%;margin:0 auto 1rem;animation:ms-spin 1s linear infinite"></div><p id="ms-title" style="font-size:15px;font-weight:600;color:#333;margin:0 0 .4rem">Checking your browser</p><p id="ms-msg" style="font-size:12px;color:#757575;margin:0;line-height:1.5"></p></div>';
    var style = document.createElement('style');
    style.textContent = '@keyframes ms-spin{to{transform:rotate(360deg)}} @media (prefers-reduced-motion:reduce){#ms-spin{animation:none}}';
    document.head.appendChild(style);
    if (document.body) document.body.appendChild(overlay); else document.addEventListener('DOMContentLoaded', function(){ document.body.appendChild(overlay); });

    function sha256(m){ var b=new TextEncoder().encode(m); return crypto.subtle.digest('SHA-256',b).then(function(d){ return Array.from(new Uint8Array(d)).map(function(x){return x.toString(16).padStart(2,'0');}).join(''); }); }
    async function solvePoW(challenge){ var nonce=0; while(true){ var h=await sha256(challenge.salt+nonce); if(h.startsWith(challenge.target)) return nonce; nonce++; } }

    async function run(){
        var r = await fetch(api + '/shield/check', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ path: location.pathname, force: true }) });
        if (r.status === 403){ document.getElementById('ms-title').textContent='Access denied'; document.getElementById('ms-msg').textContent='Your request looks automated.'; return; }
        var verdict = await r.json();
        if (verdict.action === 'shield' && verdict.challenge){
            document.getElementById('ms-msg').textContent = checkingMsg;
            var nonce = await solvePoW(verdict.challenge);
            var v = await fetch(api + '/shield/redeem', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token: verdict.token, solutions: nonce, challenge_signature: verdict.challenge.challenge_signature }) });
            var d = await v.json().catch(function(){return {};});
            if (!v.ok || !d.success){ document.getElementById('ms-title').textContent='Access denied'; return; }
        }
        if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        if (next && next !== location.pathname) location.replace(next);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
})();