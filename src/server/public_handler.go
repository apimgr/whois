package server

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/whois"
)

// sharedCSS contains the full CSS token system and layout styles shared across all pages.
// Kept here as a constant so it is embedded into the binary at compile time.
const sharedCSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

/* ── Dark theme (default) ───────────────────────────────────────── */
:root{
  --bg:#0d1117;--bg-subtle:#161b22;--bg-elevated:#21262d;
  --bg-overlay:#30363d;--bg-inset:#010409;
  --fg:#e6edf3;--fg-muted:#8b949e;--fg-subtle:#6e7681;
  --fg-disabled:#484f58;--fg-on-accent:#0d1117;--fg-link:#58a6ff;
  --border-subtle:#21262d;--border:#30363d;--border-strong:#8b949e;
  --accent:#58a6ff;--accent-hover:#79b8ff;--accent-pressed:#388bfd;
  --accent-subtle:#1f3d63;--accent-fg:#58a6ff;
  --color-success-fg:#3fb950;--color-success-bg:#0f2d1b;--color-success-border:#238636;
  --color-warning-fg:#e3b341;--color-warning-bg:#2d2000;--color-warning-border:#9e6a03;
  --color-error-fg:#f85149;--color-error-bg:#2d1212;--color-error-border:#da3633;
  --color-info-fg:#58a6ff;--color-info-bg:#1f3d63;--color-info-border:#1f6feb;
}

/* ── Light theme ─────────────────────────────────────────────────── */
[data-theme="light"]{
  --bg:#ffffff;--bg-subtle:#f6f8fa;--bg-elevated:#ffffff;
  --bg-overlay:#ffffff;--bg-inset:#eaeef2;
  --fg:#1f2328;--fg-muted:#636c76;--fg-subtle:#818b98;
  --fg-disabled:#adb5c0;--fg-on-accent:#ffffff;--fg-link:#0969da;
  --border-subtle:#eaeef2;--border:#d0d7de;--border-strong:#636c76;
  --accent:#0969da;--accent-hover:#0860ca;--accent-pressed:#0550ae;
  --accent-subtle:#ddf4ff;--accent-fg:#0969da;
  --color-success-fg:#1a7f37;--color-success-bg:#dafbe1;--color-success-border:#82cfb0;
  --color-warning-fg:#9a6700;--color-warning-bg:#fff8c5;--color-warning-border:#d4a72c;
  --color-error-fg:#d1242f;--color-error-bg:#ffebe9;--color-error-border:#cf222e;
  --color-info-fg:#0969da;--color-info-bg:#ddf4ff;--color-info-border:#54aeff;
}

/* ── Auto mode (no data-theme set) ──────────────────────────────── */
@media(prefers-color-scheme:light){
  :root{
    --bg:#ffffff;--bg-subtle:#f6f8fa;--bg-elevated:#ffffff;
    --bg-overlay:#ffffff;--bg-inset:#eaeef2;
    --fg:#1f2328;--fg-muted:#636c76;--fg-subtle:#818b98;
    --fg-disabled:#adb5c0;--fg-on-accent:#ffffff;--fg-link:#0969da;
    --border-subtle:#eaeef2;--border:#d0d7de;--border-strong:#636c76;
    --accent:#0969da;--accent-hover:#0860ca;--accent-pressed:#0550ae;
    --accent-subtle:#ddf4ff;--accent-fg:#0969da;
    --color-success-fg:#1a7f37;--color-success-bg:#dafbe1;--color-success-border:#82cfb0;
    --color-warning-fg:#9a6700;--color-warning-bg:#fff8c5;--color-warning-border:#d4a72c;
    --color-error-fg:#d1242f;--color-error-bg:#ffebe9;--color-error-border:#cf222e;
    --color-info-fg:#0969da;--color-info-bg:#ddf4ff;--color-info-border:#54aeff;
  }
}

/* ── Base layout ─────────────────────────────────────────────────── */
html{font-size:16px}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
  background:var(--bg);color:var(--fg);line-height:1.6;
  display:flex;flex-direction:column;min-height:100vh;
}
main{flex:1}
a{color:var(--fg-link)}
a:hover{color:var(--accent-hover)}

/* ── Navigation ──────────────────────────────────────────────────── */
.site-nav{
  background:var(--bg-subtle);border-bottom:1px solid var(--border);
  padding:0 1rem;
}
.nav-inner{
  max-width:72rem;margin:0 auto;
  display:flex;align-items:center;justify-content:space-between;
  height:3.5rem;
}
.nav-brand{
  font-size:1.25rem;font-weight:700;color:var(--fg);text-decoration:none;
  letter-spacing:-0.02em;
}
.nav-brand:hover{color:var(--accent)}
.nav-links{display:flex;gap:0;list-style:none;align-items:center}
.nav-links a{
  display:flex;align-items:center;height:3.5rem;padding:0 0.875rem;
  color:var(--fg-muted);text-decoration:none;font-size:0.9375rem;
  border-bottom:2px solid transparent;transition:color 150ms,border-color 150ms;
  white-space:nowrap;
}
.nav-links a:hover,.nav-links a[aria-current="page"]{
  color:var(--fg);border-bottom-color:var(--accent);
}
.nav-actions{display:flex;align-items:center;gap:0.5rem}
.btn-theme{
  background:none;border:1px solid var(--border);border-radius:6px;
  color:var(--fg-muted);cursor:pointer;font-size:1rem;line-height:1;
  padding:0.375rem 0.5rem;min-width:44px;min-height:44px;
  display:flex;align-items:center;justify-content:center;
  transition:border-color 150ms,color 150ms;
}
.btn-theme:hover{border-color:var(--border-strong);color:var(--fg)}
.btn-theme:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

/* ── Skip to main content (a11y) ─────────────────────────────────── */
.skip-link{
  position:absolute;top:-3rem;left:1rem;z-index:9999;
  background:var(--accent);color:var(--fg-on-accent);
  padding:0.5rem 1rem;border-radius:0 0 6px 6px;
  font-weight:600;text-decoration:none;transition:top 150ms;
}
.skip-link:focus{top:0}

/* ── Footer ──────────────────────────────────────────────────────── */
.site-footer{
  background:var(--bg-subtle);border-top:1px solid var(--border);
  text-align:center;padding:1.25rem 1rem;font-size:0.875rem;color:var(--fg-muted);
}
.site-footer a{color:var(--fg-link);text-decoration:none}
.site-footer a:hover{text-decoration:underline}

/* ── Long string utility (WCAG + WHOIS raw data) ─────────────────── */
.long-string,.ip-address,.onion-address,.api-token,.hash,.uuid{
  word-break:break-all;overflow-wrap:break-word;font-family:monospace;
}

/* ── Container ───────────────────────────────────────────────────── */
.container{max-width:72rem;margin:0 auto;padding:0 1rem}

/* ── Cards ───────────────────────────────────────────────────────── */
.card{
  background:var(--bg-elevated);border:1px solid var(--border);
  border-radius:8px;padding:1.5rem;
}

/* ── Page header ─────────────────────────────────────────────────── */
.page-header{padding:2.5rem 0 1.5rem;text-align:center}
.page-header h1{font-size:2rem;font-weight:700;margin-bottom:0.5rem;line-height:1.2}
.page-header p{color:var(--fg-muted);font-size:1.0625rem}

/* ── Search form (homepage) ──────────────────────────────────────── */
.search-section{padding:2.5rem 0}
.search-card{max-width:48rem;margin:0 auto}
.search-hero{text-align:center;margin-bottom:2rem}
.search-hero h1{font-size:2.25rem;font-weight:700;line-height:1.2;margin-bottom:0.5rem}
.search-hero p{color:var(--fg-muted);font-size:1.0625rem}

.search-form-wrap{display:flex;flex-direction:column;gap:0.75rem}
.search-row{display:flex;flex-direction:column;gap:0.75rem}
.search-input{
  flex:1;width:100%;padding:0.75rem 1rem;
  font-size:1rem;font-family:inherit;
  background:var(--bg-inset);color:var(--fg);
  border:1px solid var(--border);border-radius:6px;
  outline:none;transition:border-color 150ms,box-shadow 150ms;
  min-height:44px;
}
.search-input::placeholder{color:var(--fg-subtle)}
.search-input:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(88,166,255,.15);
}
.btn-primary{
  padding:0.75rem 1.5rem;font-size:1rem;font-weight:600;
  font-family:inherit;cursor:pointer;min-height:44px;
  background:var(--accent);color:var(--fg-on-accent);
  border:none;border-radius:6px;transition:background 150ms;
  white-space:nowrap;
}
.btn-primary:hover{background:var(--accent-hover)}
.btn-primary:active{background:var(--accent-pressed)}
.btn-primary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn-primary:disabled{background:var(--fg-disabled);cursor:not-allowed}

/* ── Examples bar ────────────────────────────────────────────────── */
.examples{
  margin-top:1rem;padding:0.875rem 1rem;
  background:var(--bg-subtle);border:1px solid var(--border);border-radius:6px;
}
.examples-label{
  font-size:0.75rem;font-weight:600;text-transform:uppercase;
  letter-spacing:.06em;color:var(--fg-muted);margin-bottom:0.5rem;
}
.example-chips{display:flex;flex-wrap:wrap;gap:0.5rem}
.example-chip{
  padding:0.25rem 0.625rem;font-size:0.8125rem;min-height:28px;
  background:var(--bg-elevated);border:1px solid var(--border);
  border-radius:4px;color:var(--accent-fg);text-decoration:none;
  font-family:'SF Mono','Fira Code',monospace;
  transition:background 150ms,border-color 150ms,color 150ms;
  cursor:pointer;display:inline-flex;align-items:center;
}
.example-chip:hover{
  background:var(--accent-subtle);border-color:var(--accent);color:var(--fg);
}
.example-chip:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

/* ── Result area ─────────────────────────────────────────────────── */
.result-area{margin-top:1.5rem}
.result-meta{
  display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;
  margin-bottom:1rem;
}
.meta-item{
  background:var(--bg-subtle);border:1px solid var(--border);
  border-radius:6px;padding:0.75rem;
}
.meta-label{
  font-size:0.75rem;font-weight:600;text-transform:uppercase;
  letter-spacing:.06em;color:var(--fg-muted);margin-bottom:0.25rem;
}
.meta-value{font-size:0.9375rem;color:var(--fg);word-break:break-all}
.type-badge{
  display:inline-block;padding:0.125rem 0.5rem;
  background:var(--accent-subtle);color:var(--accent-fg);
  border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:uppercase;
}
.whois-raw{
  font-family:'SF Mono','Fira Code','Fira Mono','Cascadia Code',monospace;
  font-size:0.8125rem;line-height:1.65;
  word-break:break-all;overflow-wrap:break-word;white-space:pre-wrap;
  background:var(--bg-inset);color:var(--fg);
  border:1px solid var(--border);border-radius:6px;
  padding:1rem;max-height:32rem;overflow-y:auto;
}

/* ── Status states ───────────────────────────────────────────────── */
.state-box{
  padding:1rem 1.25rem;border-radius:6px;border:1px solid;
  font-size:0.9375rem;line-height:1.5;
}
.state-error{
  background:var(--color-error-bg);color:var(--color-error-fg);
  border-color:var(--color-error-border);
}
.state-success{
  background:var(--color-success-bg);color:var(--color-success-fg);
  border-color:var(--color-success-border);
}
.state-loading{
  display:flex;align-items:center;gap:0.75rem;
  color:var(--fg-muted);padding:1rem 0;
}
.spinner{
  width:1.25rem;height:1.25rem;border-radius:50%;flex-shrink:0;
  border:2px solid var(--border);border-top-color:var(--accent);
  animation:spin .7s linear infinite;
}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── Server-rendered result (no-JS path) ─────────────────────────── */
.server-result{margin-top:1.5rem}
.server-result h2{font-size:1.25rem;font-weight:600;margin-bottom:1rem}

/* ── Responsive: tablet+ ─────────────────────────────────────────── */
@media(min-width:768px){
  .page-header h1{font-size:2.5rem}
  .search-hero h1{font-size:2.75rem}
  .search-row{flex-direction:row}
  .result-meta{grid-template-columns:repeat(4,1fr)}
  .card{padding:2rem}
}
@media(min-width:1024px){
  .container{padding:0 2rem}
  .search-section{padding:4rem 0}
}

/* ── Theme toggle icon helpers ───────────────────────────────────── */
[data-theme="light"] .icon-moon{display:inline}
[data-theme="light"] .icon-sun{display:none}
.icon-moon{display:none}
.icon-sun{display:inline}
@media(prefers-color-scheme:light){
  :root:not([data-theme]) .icon-moon{display:inline}
  :root:not([data-theme]) .icon-sun{display:none}
}
`

// themeToggleJS is the minimal script that reads/writes the data-theme attribute.
const themeToggleJS = `
(function(){
  var root=document.documentElement;
  var stored=localStorage.getItem('theme');
  if(stored){root.setAttribute('data-theme',stored)}
  document.getElementById('theme-toggle').addEventListener('click',function(){
    var current=root.getAttribute('data-theme');
    var isDark=(current==='dark')||(current===null&&window.matchMedia('(prefers-color-scheme: dark)').matches);
    var next=isDark?'light':'dark';
    root.setAttribute('data-theme',next);
    localStorage.setItem('theme',next);
  });
})();
`

// whoisLookupJS is the progressive-enhancement script for the homepage.
// When JS is available, searches happen in-page without a full redirect.
// When JS is absent, the form submits normally to GET /whois?q=...
const whoisLookupJS = `
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
`

// homepageTmpl is the template for the WHOIS homepage (/).
var homepageTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Look up domain names, IP addresses, and ASN information — fast, free, and accurate.">
<title>caswhois — WHOIS Lookup</title>
<style>` + sharedCSS + `</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>

<nav class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="caswhois home">caswhois</a>
    <ul class="nav-links" role="list">
      <li><a href="/about">About</a></li>
      <li><a href="/docs">API Docs</a></li>
    </ul>
    <div class="nav-actions">
      <button id="theme-toggle" class="btn-theme" aria-label="Toggle colour scheme">
        <span class="icon-sun" aria-hidden="true">&#9788;</span>
        <span class="icon-moon" aria-hidden="true">&#9790;</span>
      </button>
    </div>
  </div>
</nav>

<main id="main-content">
  <section class="search-section" aria-labelledby="search-heading">
    <div class="container">
      <div class="card search-card">
        <div class="search-hero">
          <h1 id="search-heading">WHOIS Lookup</h1>
          <p>Query domain names, IP addresses, and autonomous system numbers.</p>
        </div>

        <form id="whois-form" class="search-form-wrap" action="/whois" method="GET" novalidate>
          <div class="search-row">
            <label for="q" class="sr-only">Query — domain, IP address, or ASN</label>
            <input
              id="q" name="q" type="text"
              class="search-input"
              placeholder="example.com, 8.8.8.8, AS15169 …"
              autocomplete="off" autocorrect="off" autocapitalize="none"
              spellcheck="false"
              value="{{.Query}}"
              aria-label="Domain, IP address, or ASN"
              required
            >
            <button type="submit" class="btn-primary" aria-label="Run WHOIS lookup">
              Look up
            </button>
          </div>
        </form>

        <div class="examples" aria-label="Example queries">
          <div class="examples-label">Try an example</div>
          <div class="example-chips">
            <a href="/whois?q=example.com"   class="example-chip" data-query="example.com">example.com</a>
            <a href="/whois?q=8.8.8.8"       class="example-chip" data-query="8.8.8.8">8.8.8.8</a>
            <a href="/whois?q=1.1.1.1"       class="example-chip" data-query="1.1.1.1">1.1.1.1</a>
            <a href="/whois?q=2001%3A4860%3A4860%3A%3A8888" class="example-chip" data-query="2001:4860:4860::8888">2001:4860:4860::8888</a>
            <a href="/whois?q=AS15169"        class="example-chip" data-query="AS15169">AS15169</a>
            <a href="/whois?q=AS13335"        class="example-chip" data-query="AS13335">AS13335</a>
          </div>
        </div>

        {{/* Loading indicator — hidden until JS shows it */}}
        <div id="js-loading" class="state-loading result-area" hidden aria-live="polite" aria-busy="true">
          <span class="spinner" role="status" aria-label="Loading"></span>
          <span>Looking up WHOIS information…</span>
        </div>

        {{/* JS-rendered result */}}
        <div id="js-result" class="result-area" hidden aria-live="polite">
          <div class="result-meta">
            <div class="meta-item">
              <div class="meta-label">Query</div>
              <div id="r-query" class="meta-value long-string"></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Type</div>
              <div id="r-type" class="meta-value"><span class="type-badge"></span></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Server</div>
              <div id="r-server" class="meta-value long-string"></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Looked up</div>
              <div id="r-ts" class="meta-value"></div>
            </div>
          </div>
          <pre id="r-raw" class="whois-raw" aria-label="Raw WHOIS data"></pre>
        </div>

        {{/* JS error */}}
        <div id="js-error" class="state-box state-error result-area" role="alert" hidden></div>

        {{/* Server-side result (no-JS path) */}}
        {{if .Result}}
        <div class="server-result" aria-label="WHOIS result">
          <div class="result-meta">
            <div class="meta-item">
              <div class="meta-label">Query</div>
              <div class="meta-value long-string">{{.Result.Query}}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Type</div>
              <div class="meta-value"><span class="type-badge">{{.Result.Type}}</span></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Server</div>
              <div class="meta-value long-string">{{.Result.Server}}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Looked up</div>
              <div class="meta-value"><time datetime="{{.Result.Timestamp}}">{{.Result.Timestamp}}</time></div>
            </div>
          </div>
          <pre class="whois-raw" aria-label="Raw WHOIS data">{{.Result.Raw}}</pre>
        </div>
        {{end}}

        {{/* Server-side error (no-JS path) */}}
        {{if .Err}}
        <div class="state-box state-error" role="alert">
          {{.Err}}
        </div>
        {{end}}
      </div>
    </div>
  </section>
</main>

<footer class="site-footer">
  <p>
    <a href="/">caswhois</a> &mdash;
    <a href="/about">About</a> &middot;
    <a href="/docs">API Docs</a> &middot;
    <a href="/server/healthz">Health</a>
  </p>
</footer>

<style>.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0}</style>
<script>` + themeToggleJS + `</script>
<script>` + whoisLookupJS + `</script>
</body>
</html>`))

// whoisPageTmpl is the template for GET /whois?q=... (no-JS server-rendered result page).
// Browsers with JS active will never navigate here; they see results inline on /.
var whoisPageTmpl = template.Must(template.New("whois-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="WHOIS result for {{.Query}}">
<title>{{.Query}} — caswhois</title>
<style>` + sharedCSS + `</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>

<nav class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="caswhois home">caswhois</a>
    <ul class="nav-links" role="list">
      <li><a href="/about">About</a></li>
      <li><a href="/docs">API Docs</a></li>
    </ul>
    <div class="nav-actions">
      <button id="theme-toggle" class="btn-theme" aria-label="Toggle colour scheme">
        <span class="icon-sun" aria-hidden="true">&#9788;</span>
        <span class="icon-moon" aria-hidden="true">&#9790;</span>
      </button>
    </div>
  </div>
</nav>

<main id="main-content">
  <div class="container" style="padding-top:2rem;padding-bottom:2rem">

    <form id="whois-form" class="search-form-wrap" action="/whois" method="GET" style="margin-bottom:1.5rem" novalidate>
      <div class="search-row">
        <label for="q" class="sr-only">Query — domain, IP address, or ASN</label>
        <input
          id="q" name="q" type="text"
          class="search-input"
          placeholder="example.com, 8.8.8.8, AS15169 …"
          autocomplete="off" autocorrect="off" autocapitalize="none"
          spellcheck="false"
          value="{{.Query}}"
          aria-label="Domain, IP address, or ASN"
        >
        <button type="submit" class="btn-primary">Look up</button>
      </div>
    </form>

    {{if .Err}}
    <div class="state-box state-error" role="alert">{{.Err}}</div>
    {{else if .Result}}
    <div class="card">
      <div class="result-meta" style="margin-bottom:1rem">
        <div class="meta-item">
          <div class="meta-label">Query</div>
          <div class="meta-value long-string">{{.Result.Query}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Type</div>
          <div class="meta-value"><span class="type-badge">{{.Result.Type}}</span></div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Server</div>
          <div class="meta-value long-string">{{.Result.Server}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Looked up</div>
          <div class="meta-value">
            <time datetime="{{.Result.Timestamp}}">{{.Result.Timestamp}}</time>
          </div>
        </div>
      </div>
      <pre class="whois-raw" aria-label="Raw WHOIS data">{{.Result.Raw}}</pre>
    </div>
    {{else if .Query}}
    <div class="state-box state-error" role="alert">No result returned for "{{.Query}}".</div>
    {{end}}

    <p style="margin-top:1rem"><a href="/">&larr; New lookup</a></p>
  </div>
</main>

<footer class="site-footer">
  <p>
    <a href="/">caswhois</a> &mdash;
    <a href="/about">About</a> &middot;
    <a href="/docs">API Docs</a> &middot;
    <a href="/server/healthz">Health</a>
  </p>
</footer>

<style>.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0}</style>
<script>` + themeToggleJS + `</script>
</body>
</html>`))

// homePageData holds template data for the homepage.
type homePageData struct {
	Query  string
	Result *whoisResultView
	Err    string
}

// whoisResultView is a presentation-layer view of a WHOISResult.
type whoisResultView struct {
	Query     string
	Type      string
	Server    string
	Timestamp string
	Raw       string
}

// whoisPageData holds template data for the /whois result page.
type whoisPageData struct {
	Query  string
	Result *whoisResultView
	Err    string
}

// handlePublicWHOISPage serves the public WHOIS lookup homepage at /.
// GET /
func (s *Server) handlePublicWHOISPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// JSON API clients get the API info response.
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		s.handleRootAPI(w, r)
		return
	}

	data := homePageData{}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homepageTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleWHOISPage handles the form-submission fallback at GET /whois?q=...
// Browsers with JS never reach this — the fetch intercepts first.
// Browsers without JS (and curl with Accept: text/html) do reach it.
func (s *Server) handleWHOISPage(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	clientType := DetectClientType(r)

	// Plain-text clients (curl, wget, etc.) get raw WHOIS output.
	if clientType == ClientTypeText || strings.Contains(r.Header.Get("Accept"), "text/plain") {
		if q == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Usage: GET /whois?q=<domain|ip|asn>\n"))
			return
		}
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("WHOIS lookup failed: " + err.Error() + "\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(result.Raw))
		return
	}

	// JSON clients get the structured response.
	if clientType == ClientTypeJSON || strings.Contains(r.Header.Get("Accept"), "application/json") {
		if q == "" {
			SendError(w, ErrBadRequest, "Query parameter q is required")
			return
		}
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			SendError(w, ErrServerError, "WHOIS lookup failed: "+err.Error())
			return
		}
		SendSuccess(w, map[string]interface{}{
			"query":     result.Query,
			"type":      result.Type.String(),
			"server":    result.Server,
			"timestamp": result.Timestamp.Format(time.RFC3339),
			"raw":       result.Raw,
		})
		return
	}

	// HTML clients — render the server-side result page.
	data := whoisPageData{Query: q}

	if q != "" {
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			data.Err = "WHOIS lookup failed: " + err.Error()
		} else {
			data.Result = &whoisResultView{
				Query:     result.Query,
				Type:      result.Type.String(),
				Server:    result.Server,
				Timestamp: result.Timestamp.Format(time.RFC3339),
				Raw:       result.Raw,
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := whoisPageTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleRootAPI returns API information for root endpoint when Accept: application/json.
func (s *Server) handleRootAPI(w http.ResponseWriter, r *http.Request) {
	SendSuccess(w, map[string]interface{}{
		"service":     "caswhois",
		"description": "WHOIS lookup service — query domains, IPs, and ASNs",
		"version":     "0.1.0",
		"endpoints": []string{
			"GET /api/v1/whois/{query}         — generic lookup",
			"GET /api/v1/whois/domain/{domain} — domain lookup",
			"GET /api/v1/whois/ip/{ip}         — IP lookup",
			"GET /api/v1/whois/asn/{asn}       — ASN lookup",
			"GET /api/v1/whois/validate/{q}    — validate without lookup",
			"POST /api/v1/whois/bulk           — bulk lookup (auth required)",
			"GET /api/v1/whois-servers         — list WHOIS servers",
			"GET /api/v1/server/stats          — service statistics",
			"GET /server/healthz               — health check",
		},
	})
}
