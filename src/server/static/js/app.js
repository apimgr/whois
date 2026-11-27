(function(){
  var root=document.documentElement;
  // Theme is set server-side from the theme cookie; this is an instant preview only.
  var toggle=document.getElementById('theme-toggle');
  var order=['dark','light','auto'];
  if(toggle){
    var form=toggle.closest('form');
    if(form)form.addEventListener('submit',function(){
      var current='dark';
      for(var i=0;i<order.length;i++){
        if(root.classList.contains('theme-'+order[i])){current=order[i];break;}
      }
      var next=order[(order.indexOf(current)+1)%order.length];
      root.className=root.className.replace(/\btheme-(dark|light|auto)\b/,'theme-'+next);
    });
  }
})();

// Toasts provide non-blocking feedback for enhanced form and API actions.
(function(){
  var container=document.getElementById('toast-container');
  if(!container)return;
  var body=document.body;
  function durationSeconds(value,fallback){
    if(value===undefined||value===null||String(value).trim()==='')return fallback;
    var parsed=Number(value);
    return Number.isFinite(parsed)?Math.max(0,parsed):fallback;
  }
  var duration=durationSeconds(body.dataset.toastDuration,3)*1000;
  var warningDuration=durationSeconds(body.dataset.toastWarningDuration,5)*1000;
  var sequence=0;
  function dismissToast(id){
    var toast=container.querySelector('[data-toast-id="'+id+'"]');
    if(toast&&!toast.classList.contains('toast-dismissed')){toast.classList.add('toast-dismissed');window.setTimeout(function(){toast.remove();showQueued();},200);}
  }
  function showQueued(){
    var visible=container.querySelectorAll('.toast').length;
    while(visible<5&&container._toastQueue&&container._toastQueue.length){
      var queued=container._toastQueue.shift();container.appendChild(queued);visible++;if(queued._startToastTimer)queued._startToastTimer();
    }
  }
  function showToast(message,type){
    type=['success','error','warning','info'].indexOf(type)>=0?type:'info';
    var toast=document.createElement('div');toast.className='toast toast-'+type;toast.setAttribute('role','alert');toast.setAttribute('aria-live','polite');
    var icon=document.createElement('span');icon.className='toast-icon';icon.textContent={success:'✓',error:'✗',warning:'⚠',info:'ℹ'}[type];
    var text=document.createElement('span');text.className='toast-message';text.textContent=String(message);
    var close=document.createElement('button');close.type='button';close.className='toast-close';close.setAttribute('aria-label','Dismiss');close.textContent='×';
    var id=String(++sequence);toast.dataset.toastId=id;toast.append(icon,text,close);
    close.addEventListener('click',function(){dismissToast(id);});toast.addEventListener('click',function(){dismissToast(id);});
    var wait=type==='error'?0:(type==='warning'?warningDuration:duration);
    if(wait>0){var progress=document.createElement('div');progress.className='toast-progress';toast.appendChild(progress);}
    if(wait>0){var timer,startedAt,remaining=wait;function start(){if(!toast.isConnected||remaining<=0)return;startedAt=Date.now();timer=window.setTimeout(function(){dismissToast(id);},remaining);}function stop(){if(!timer)return;window.clearTimeout(timer);timer=null;remaining=Math.max(0,remaining-(Date.now()-startedAt));}toast._startToastTimer=start;toast.addEventListener('mouseenter',stop);toast.addEventListener('mouseleave',start);}
    container._toastQueue=container._toastQueue||[];
    if(container.querySelectorAll('.toast').length<5){container.prepend(toast);if(toast._startToastTimer)toast._startToastTimer();}else container._toastQueue.push(toast);
    return id;
  }
  function dismissAllToasts(){container.innerHTML='';container._toastQueue=[];}
  document.addEventListener('keydown',function(event){if(event.key==='Escape'){var toast=container.querySelector('.toast');if(toast)dismissToast(toast.dataset.toastId);}});
  window.showToast=showToast;window.dismissToast=dismissToast;window.dismissAllToasts=dismissAllToasts;
})();

// Copy values from buttons or selectable multiline code blocks and announce success.
function copyToClipboard(value){
  if(navigator.clipboard&&navigator.clipboard.writeText)return navigator.clipboard.writeText(value);
  var field=document.createElement('textarea');
  field.className='sr-only';
  field.value=value;
  field.setAttribute('readonly','');
  document.body.appendChild(field);
  field.select();
  var copied=document.execCommand('copy');
  field.remove();
  return copied?Promise.resolve():Promise.reject(new Error('Clipboard unavailable'));
}

function showCopySuccess(button){
  var icon=button.querySelector('.copy-icon');
  var label=button.querySelector('.copy-text');
  var copied=button.dataset.copiedLabel||'Copied!';
  var restore=[];
  if(icon){restore.push([icon,icon.textContent]);icon.textContent='✓';}
  if(label){restore.push([label,label.textContent]);label.textContent=copied;}
  if(!icon&&!label){restore.push([button,button.textContent]);button.textContent='✓ '+copied;button.setAttribute('aria-live','polite');}
  button.classList.add('copied');
  if(button._copyFeedbackTimer)window.clearTimeout(button._copyFeedbackTimer);
  button._copyFeedbackTimer=window.setTimeout(function(){
    restore.forEach(function(item){item[0].textContent=item[1];});
    button.classList.remove('copied');
    button._copyFeedbackTimer=null;
  },2000);
}

document.addEventListener('click',function(event){
  var button=event.target.closest('.copy-btn');
  if(!button)return;
  var value=button.getAttribute('data-copy');
  if(value===null){
    var targetId=button.getAttribute('data-copy-target');
    var target=targetId?document.getElementById(targetId):button.previousElementSibling;
    value=target?target.textContent:'';
  }
  if(!value)return;
  copyToClipboard(value).then(function(){showCopySuccess(button);}).catch(function(){});
});

(function(){
  var form=document.getElementById('whois-form');
  var input=document.getElementById('q');
  var loading=document.getElementById('js-loading');
  var resultArea=document.getElementById('js-result');
  var errorArea=document.getElementById('js-error');
  if(!form||!input)return;
  var apiBase=form.getAttribute('data-api-base');
  if(!apiBase)return;

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
    fetch(window.location.origin+apiBase+'/whois/'+encodeURIComponent(q.trim()))
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
function showUpdateBanner(onUpdate) {
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
    if (onUpdate) onUpdate();
    banner.remove();
  });

  banner.appendChild(label);
  banner.appendChild(btn);
  document.body.appendChild(banner);
}

// GraphQL console enhancement; the HTML form remains usable without JavaScript.
(function(){
  var form=document.getElementById('gql-form');
  var response=document.getElementById('gql-response');
  if(!form||!response)return;

  form.addEventListener('submit',function(event){
    event.preventDefault();
    var rawVariables=document.getElementById('gql-vars').value.trim();
    var variables=null;
    if(rawVariables){
      try{variables=JSON.parse(rawVariables);}
      catch(_){response.textContent=form.dataset.invalidJson;return;}
    }

    var body={query:document.getElementById('gql-query').value.trim()};
    var operation=document.getElementById('gql-op').value.trim();
    if(variables!==null)body.variables=variables;
    if(operation)body.operationName=operation;

    response.textContent=form.dataset.loading;
    var headers={'Content-Type':'application/json','Accept':'application/json'};
    var csrf=form.querySelector('input[name="csrf_token"]');
    if(csrf)headers['X-CSRF-Token']=csrf.value;

    fetch(form.dataset.endpoint,{method:'POST',headers:headers,body:JSON.stringify(body)})
      .then(function(result){return result.json();})
      .then(function(data){response.textContent=JSON.stringify(data,null,2);})
      .catch(function(){response.textContent=form.dataset.networkError;});
  });
})();

// PWA service worker registration (AI.md PART 16)
if ('serviceWorker' in navigator) {
  var scriptPath = document.currentScript ? new URL(document.currentScript.src).pathname : '';
  var appBase = scriptPath.replace(/\/static\/js\/app\.js$/, '');
  var updateAccepted = false;
  var updateReloaded = false;

  function reloadAfterUpdate() {
    if (updateReloaded) return;
    updateReloaded = true;
    window.location.reload();
  }

  navigator.serviceWorker.addEventListener('controllerchange', function() {
    if (updateAccepted) reloadAfterUpdate();
  });

  window.addEventListener('load', function() {
    navigator.serviceWorker.register(appBase + '/sw.js', { scope: appBase + '/' })
      .then(function(reg) {
        window.setInterval(function() { reg.update().catch(function() {}); }, 60 * 60 * 1000);
        fetch(appBase + '/offline-strings.json', { cache: 'no-store' })
          .then(function(response) { if (!response.ok) throw new Error('offline strings unavailable'); return response.json(); })
          .then(function(strings) {
            return caches.open('caswhois-offline-strings').then(function(cache) {
              return cache.put(appBase + '/offline-strings.json', new Response(JSON.stringify(strings), {
                headers: { 'Content-Type': 'application/json' }
              }));
            });
          })
          .catch(function() {});

        reg.addEventListener('updatefound', function() {
          var newWorker = reg.installing;
          if (!newWorker) return;
          newWorker.addEventListener('statechange', function() {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              showUpdateBanner(function() {
                updateAccepted = true;
                if (reg.waiting) {
                  reg.waiting.postMessage({ type: 'SKIP_WAITING' });
                  window.setTimeout(reloadAfterUpdate, 5000);
                } else {
                  reloadAfterUpdate();
                }
              });
            }
          });
        });
      })
      .catch(function(err) { console.warn('SW registration failed:', err); });
  });
}

window.addEventListener('load', function() {
  var target = document.getElementById('swagger-ui');
  if (!target || typeof window.SwaggerUIBundle !== 'function') return;
  target.textContent = '';
  window.SwaggerUIBundle({
    url: target.getAttribute('data-spec-url'),
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [window.SwaggerUIBundle.presets.apis, window.SwaggerUIStandalonePreset],
    layout: 'StandaloneLayout'
  });
});
