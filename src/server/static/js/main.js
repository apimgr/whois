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
