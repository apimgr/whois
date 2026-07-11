(function(){
  var root=document.documentElement;
  // Theme is set server-side via data-theme on <html> from the theme cookie (AI.md PART 16).
  // JS only writes the cookie when the user toggles — the server applies it on every render.
  var toggle=document.getElementById('theme-toggle');
  if(toggle){
    toggle.addEventListener('click',function(){
      var current=root.getAttribute('data-theme');
      var isDark=(current==='dark')||(current===null&&window.matchMedia('(prefers-color-scheme: dark)').matches);
      var next=isDark?'light':'dark';
      root.setAttribute('data-theme',next);
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
