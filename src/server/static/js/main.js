(function(){
  var root=document.documentElement;
  // Theme is set server-side via class="theme-*" on <html> from the theme cookie (AI.md PART 16).
  // JS only writes the cookie and swaps the class when the user toggles — no page reload,
  // no matchMedia detection (auto mode is pure CSS via prefers-color-scheme).
  var toggle=document.getElementById('theme-toggle');
  var order=['dark','light','auto'];
  if(toggle){
    toggle.addEventListener('click',function(){
      var current='dark';
      for(var i=0;i<order.length;i++){
        if(root.classList.contains('theme-'+order[i])){current=order[i];break;}
      }
      var next=order[(order.indexOf(current)+1)%order.length];
      root.className=root.className.replace(/\btheme-(dark|light|auto)\b/,'theme-'+next);
      // Persist in cookie so the server reads it on next request (SameSite=Lax, 1-year TTL).
      document.cookie='theme='+next+'; path=/; max-age=31536000; SameSite=Lax';
    });
  }
})();

(function(){
  var form=document.getElementById('whois-form');
  var input=document.getElementById('q');
  var loading=document.getElementById('js-loading');
  var resultArea=document.getElementById('js-result');
  var errorArea=document.getElementById('js-error');
  if(!form||!input)return;

  // User-facing strings are injected server-side via data-* attributes so they
  // honour the request language (AI.md PART 30 — no hardcoded strings in JS).
  var msg={
    empty:form.getAttribute('data-msg-empty')||'',
    failed:form.getAttribute('data-msg-failed')||'',
    network:form.getAttribute('data-msg-network')||''
  };

  function hideAll(){
    if(loading)loading.hidden=true;
    if(resultArea)resultArea.hidden=true;
    if(errorArea)errorArea.hidden=true;
  }

  function showError(msg){
    hideAll();
    if(errorArea){errorArea.textContent=msg;errorArea.hidden=false;}
  }

  function showResult(data){
    hideAll();
    if(!resultArea)return;
    document.getElementById('r-query').textContent=data.query||'';
    document.getElementById('r-type').textContent=data.type||'';
    document.getElementById('r-server').textContent=data.server||'';
    document.getElementById('r-ts').textContent=data.timestamp||'';
    document.getElementById('r-raw').textContent=data.raw||'(no data returned)';
    resultArea.hidden=false;
  }

  function doLookup(q){
    if(!q.trim()){showError(msg.empty);return;}
    hideAll();
    if(loading)loading.hidden=false;
    var btn=form.querySelector('button[type="submit"]');
    if(btn){btn.disabled=true;}
    // Build the URL from the page origin so the app works behind a reverse proxy (AI.md PART 16).
    fetch(window.location.origin+'/api/v1/whois/'+encodeURIComponent(q.trim()))
      .then(function(res){return res.json();})
      .then(function(body){
        if(btn){btn.disabled=false;}
        if(body.ok&&body.data){showResult(body.data);}
        else{showError(body.message||msg.failed);}
      })
      .catch(function(err){
        if(btn){btn.disabled=false;}
        showError(msg.network+' '+err.message);
      });
  }

  form.addEventListener('submit',function(e){
    e.preventDefault();
    doLookup(input.value);
  });

  document.querySelectorAll('.example-chip').forEach(function(el){
    el.addEventListener('click',function(e){
      e.preventDefault();
      var q=el.getAttribute('data-query');
      if(q){input.value=q;doLookup(q);}
    });
  });
})();

// Cookie consent module (AI.md PART 16 — Cookie Consent Banner).
// Enhancement only - the banner forms POST to /server/consent and work
// without JS. This script intercepts the submits to skip the reload.
(function() {
  function readConsentCookie() {
    var match = document.cookie.match(/(?:^|;\s*)cookie_consent=([^;]+)/);
    if (!match) return null;
    try { return JSON.parse(decodeURIComponent(match[1])); }
    catch (e) { return null; }
  }

  function writeConsentCookie(consent) {
    var value = encodeURIComponent(JSON.stringify(consent));
    document.cookie = 'cookie_consent=' + value + '; path=/; max-age=31536000; SameSite=Lax';
  }

  function applyConsent(consent) {
    // Essential cookies always work (sessions, CSRF).
    if (consent.preferences) {
      document.cookie = 'preferencesEnabled=true; path=/; max-age=31536000; SameSite=Lax';
    }
    if (consent.analytics) { loadTracking(); }
  }

  function loadTracking() {
    // Tracking script is injected server-side via {{ trackingScript }};
    // nothing to do client-side once consent.analytics is true.
  }

  function saveAndApplyConsent(consent) {
    writeConsentCookie(consent);
    var banner = document.getElementById('cookie-consent');
    if (banner) { banner.remove(); }
    applyConsent(consent);
  }

  document.querySelectorAll('#cookie-consent form').forEach(function(form) {
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      var accepted = form.elements.choice.value === 'accept';
      saveAndApplyConsent({
        essential: true,
        preferences: accepted,
        analytics: accepted,
        timestamp: Date.now()
      });
    });
  });

  function showCookiePreferences() {
    var modal = document.getElementById('cookie-preferences-modal');
    if (!modal) return;
    var consent = readConsentCookie();
    var prefInput = document.getElementById('pref-preferences');
    var analyticsInput = document.getElementById('pref-analytics');
    if (consent && prefInput) { prefInput.checked = !!consent.preferences; }
    if (consent && analyticsInput) { analyticsInput.checked = !!consent.analytics; }
    if (typeof modal.showModal === 'function') { modal.showModal(); }
  }

  document.querySelectorAll('[data-action="cookie-preferences"]').forEach(function(el) {
    el.addEventListener('click', showCookiePreferences);
  });

  document.querySelectorAll('[data-action="cookie-preferences-close"]').forEach(function(el) {
    el.addEventListener('click', function() {
      var modal = document.getElementById('cookie-preferences-modal');
      if (modal) { modal.close(); }
    });
  });

  var prefsForm = document.getElementById('cookie-preferences-form');
  if (prefsForm) {
    prefsForm.addEventListener('submit', function(event) {
      event.preventDefault();
      var prefInput = document.getElementById('pref-preferences');
      var analyticsInput = document.getElementById('pref-analytics');
      saveAndApplyConsent({
        essential: true,
        preferences: !!(prefInput && prefInput.checked),
        analytics: !!(analyticsInput && analyticsInput.checked),
        timestamp: Date.now()
      });
      var modal = document.getElementById('cookie-preferences-modal');
      if (modal) { modal.close(); }
    });
  }

  function applyCCPAOptOut() {
    document.cookie = 'ccpa_opt_out=true; path=/; max-age=31536000; SameSite=Lax';
  }

  function ccpaDoNotSell() {
    applyCCPAOptOut();
    saveAndApplyConsent({
      essential: true,
      preferences: false,
      analytics: false,
      timestamp: Date.now(),
      ccpaOptOut: true
    });
  }

  document.querySelectorAll('form[action="/server/ccpa"]').forEach(function(form) {
    form.addEventListener('submit', function(event) {
      if (form.elements.choice.value === 'opt-out') {
        event.preventDefault();
        ccpaDoNotSell();
      }
    });
  });

  function initCCPA() {
    var banner = document.getElementById('cookie-consent');
    var dataSold = banner && banner.dataset.sold === 'true';
    if (!dataSold) return;
    var doNotSell = /(?:^|;\s*)ccpa_opt_out=true/.test(document.cookie);
    if (doNotSell) { applyCCPAOptOut(); }
  }

  initCCPA();
})();

// Site banner dismissal (AI.md PART 16 — Site Banner).
// Enhancement only - the dismiss form POSTs to /announcements/dismiss and
// works without JS. This script intercepts the submit to skip the reload.
(function() {
  document.querySelectorAll('.site-banner .site-banner-dismiss').forEach(function(form) {
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      var banner = form.closest('.site-banner');
      if (!banner) return;
      var match = document.cookie.match(/(?:^|;\s*)dismissed_announcements=([^;]*)/);
      var ids = match ? decodeURIComponent(match[1]).split(',').filter(Boolean) : [];
      var id = banner.getAttribute('data-announcement-id');
      if (id && ids.indexOf(id) === -1) { ids.push(id); }
      document.cookie = 'dismissed_announcements=' + encodeURIComponent(ids.join(',')) +
        '; path=/; max-age=31536000; SameSite=Lax';
      banner.remove();
    });
  });
})();

// showUpdateBanner builds the PWA "update available" banner from classed
// elements (AI.md PART 16 — no inline CSS or inline event handlers in JS).
function showUpdateBanner() {
  var form = document.getElementById('whois-form');
  var labelText = (form && form.getAttribute('data-msg-update')) || 'Update available';
  var actionText = (form && form.getAttribute('data-msg-update-action')) || 'Update';

  var banner = document.createElement('div');
  banner.className = 'sw-update-banner';

  var label = document.createElement('span');
  label.textContent = labelText;

  var btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'sw-update-btn';
  btn.textContent = actionText;
  btn.addEventListener('click', function() {
    navigator.serviceWorker.ready.then(function(r) {
      if (r.waiting) { r.waiting.postMessage({ type: 'SKIP_WAITING' }); }
    });
    banner.remove();
  });

  banner.appendChild(label);
  banner.appendChild(btn);
  document.body.appendChild(banner);
}

// PWA service worker registration (AI.md PART 16)
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .then(function(reg) {
        reg.addEventListener('updatefound', function() {
          var newWorker = reg.installing;
          newWorker.addEventListener('statechange', function() {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              showUpdateBanner();
            }
          });
        });
      })
      .catch(function(err) { console.warn('SW registration failed:', err); });
  });
}
