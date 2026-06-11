(function(){
  var root=document.documentElement;
  var stored=localStorage.getItem('theme');
  if(stored){root.setAttribute('data-theme',stored)}
  var toggle=document.getElementById('theme-toggle');
  if(toggle){
    toggle.addEventListener('click',function(){
      var current=root.getAttribute('data-theme');
      var isDark=(current==='dark')||(current===null&&window.matchMedia('(prefers-color-scheme: dark)').matches);
      var next=isDark?'light':'dark';
      root.setAttribute('data-theme',next);
      localStorage.setItem('theme',next);
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
    if(!q.trim()){showError('Enter a domain, IP address, or ASN number.');return;}
    hideAll();
    if(loading)loading.hidden=false;
    var btn=form.querySelector('button[type="submit"]');
    if(btn){btn.disabled=true;}
    fetch('/api/v1/whois/'+encodeURIComponent(q.trim()))
      .then(function(res){return res.json();})
      .then(function(body){
        if(btn){btn.disabled=false;}
        if(body.ok&&body.data){showResult(body.data);}
        else{showError(body.message||'WHOIS lookup failed — please try again.');}
      })
      .catch(function(err){
        if(btn){btn.disabled=false;}
        showError('Network error: '+err.message);
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

// PWA service worker registration (AI.md PART 16)
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .then(function(reg) {
        reg.addEventListener('updatefound', function() {
          var newWorker = reg.installing;
          newWorker.addEventListener('statechange', function() {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              var banner = document.createElement('div');
              banner.style.cssText = 'position:fixed;bottom:1rem;left:50%;transform:translateX(-50%);background:var(--color-accent,#007bff);color:#fff;padding:.75rem 1.5rem;border-radius:.5rem;display:flex;gap:1rem;align-items:center;z-index:9999;';
              banner.innerHTML = '<span>Update available</span><button onclick="navigator.serviceWorker.ready.then(function(r){if(r.waiting)r.waiting.postMessage({type:\'SKIP_WAITING\'})});this.closest(\'[style]\').remove()" style="background:rgba(0,0,0,.2);border:none;color:#fff;padding:.25rem .75rem;border-radius:.25rem;cursor:pointer;">Update</button>';
              document.body.appendChild(banner);
            }
          });
        });
      })
      .catch(function(err) { console.warn('SW registration failed:', err); });
  });
}
