//go:build e2e

package e2e

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apimgr/whois/src/config"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/chromedp"
)

//go:embed vendor/axe.min.js
var axeCore string

type debugRoute struct {
	Method string `json:"method"`
	Route  string `json:"route"`
}

func publicPageRoutes(t *testing.T, base, token string) []string {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/debug/routes", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close debug routes response: %v", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("debug routes status = %d", response.StatusCode)
	}
	var result struct {
		Routes []debugRoute `json:"routes"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{"/": true, "/whois": true, "/debug/components": true}
	for _, route := range result.Routes {
		if route.Method == http.MethodGet && strings.HasPrefix(route.Route, "/server/") && route.Route != "/server/healthz" && !strings.ContainsAny(route.Route, "{}*") {
			pageRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+route.Route, nil)
			if err != nil {
				t.Fatalf("create page probe for %s: %v", route.Route, err)
			}
			pageRequest.Header.Set("Accept", "text/html")
			pageRequest.Header.Set("Authorization", "Bearer "+token)
			pageResponse, err := http.DefaultClient.Do(pageRequest)
			if err != nil {
				t.Fatalf("probe page %s: %v", route.Route, err)
			}
			if strings.HasPrefix(pageResponse.Header.Get("Content-Type"), "text/html") {
				seen[route.Route] = true
			}
			if err := pageResponse.Body.Close(); err != nil {
				t.Errorf("close page probe for %s: %v", route.Route, err)
			}
		}
	}
	pages := make([]string, 0, len(seen)+1)
	for page := range seen {
		pages = append(pages, page)
	}
	pages = append(pages, "/debug/error500", "/__layout_contract_not_found__")
	sort.Strings(pages)
	return pages
}

func translationNamespaces(t *testing.T) []string {
	t.Helper()
	locale, err := os.ReadFile("../../src/common/i18n/locales/en.json")
	if err != nil {
		t.Fatal(err)
	}
	var translations map[string]json.RawMessage
	if err := json.Unmarshal(locale, &translations); err != nil {
		t.Fatal(err)
	}
	namespaces := make([]string, 0, len(translations))
	for namespace := range translations {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	return namespaces
}

func TestTier3LayoutContractRegisteredPages(t *testing.T) {
	base := baseURL(t)
	browserBase := browserBaseURL(t)
	configDir := os.Getenv("E2E_CONFIG_DIR")
	token, err := config.ReadOperatorToken(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("E2E operator token is empty")
	}
	pages := publicPageRoutes(t, base, token)
	if pageFilter := os.Getenv("E2E_PAGE"); pageFilter != "" {
		filtered := pages[:0]
		for _, page := range pages {
			if page == pageFilter {
				filtered = append(filtered, page)
			}
		}
		if len(filtered) == 0 {
			t.Fatalf("E2E_PAGE %q is not a registered browser page", pageFilter)
		}
		pages = filtered
	}
	namespaces, err := json.Marshal(translationNamespaces(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := browserContext(t)
	defer cancel()
	ctx, stop := chromedp.NewContext(ctx)
	defer stop()
	var eventMu sync.Mutex
	var browserFaults []string
	chromedp.ListenTarget(ctx, func(event any) {
		eventMu.Lock()
		defer eventMu.Unlock()
		switch value := event.(type) {
		case *runtime.EventExceptionThrown:
			browserFaults = append(browserFaults, "JavaScript exception")
		case *runtime.EventConsoleAPICalled:
			if value.Type == "error" || value.Type == "warning" {
				browserFaults = append(browserFaults, "console "+fmt.Sprint(value.Type))
			}
		case *network.EventLoadingFailed:
			browserFaults = append(browserFaults, "failed network request")
		}
	})
	if err := chromedp.Run(ctx, security.SetIgnoreCertificateErrors(true), network.Enable(), network.SetExtraHTTPHeaders(network.Headers{"Authorization": "Bearer " + token})); err != nil {
		t.Fatal(err)
	}
	viewports := []struct{ width, height int }{
		{375, 812}, {1280, 800},
	}
	componentViewports := []struct{ width, height int }{
		{320, 640}, {375, 812}, {390, 844}, {639, 900}, {640, 900}, {767, 900},
		{768, 1024}, {820, 1180}, {1023, 900}, {1024, 768}, {1279, 900},
		{1280, 800}, {1440, 900}, {1920, 1080},
	}
	for _, page := range pages {
		page := page
		t.Run(page, func(t *testing.T) {
			pageCtx, pageCancel := chromedp.NewContext(ctx)
			defer pageCancel()
			pageViewports := viewports
			target := browserBase + page
			if err := chromedp.Run(pageCtx, security.SetIgnoreCertificateErrors(true), network.Enable(), network.SetExtraHTTPHeaders(network.Headers{"Authorization": "Bearer " + token})); err != nil {
				t.Fatalf("authorize page target: %v", err)
			}
			if page == "/debug/components" {
				query := url.Values{"theme": {"dark"}, "dir": {"ltr"}}
				target += "?" + query.Encode()
				pageViewports = componentViewports
			}
			if err := chromedp.Run(pageCtx, chromedp.Navigate(target)); err != nil {
				t.Fatalf("navigate %s: %v", page, err)
			}
			if err := chromedp.Run(pageCtx, runtime.Enable()); err != nil {
				t.Fatalf("enable runtime events: %v", err)
			}
			if err := chromedp.Run(pageCtx, chromedp.Evaluate(axeCore, nil)); err != nil {
				t.Fatalf("inject axe-core: %v", err)
			}
			for _, theme := range []string{"dark", "light", "auto"} {
				for _, direction := range []string{"ltr", "rtl"} {
					for _, viewport := range pageViewports {
						viewport := viewport
						t.Run(fmt.Sprintf("%s/%s/%dx%d", theme, direction, viewport.width, viewport.height), func(t *testing.T) {
							var failures []string
							var scrollWidth int
							var cls float64
							err := chromedp.Run(pageCtx,
								chromedp.EmulateViewport(int64(viewport.width), int64(viewport.height)),
								chromedp.Evaluate(`(() => {
								  document.documentElement.style.overflowX = 'visible';
								  document.body.style.overflowX = 'visible';
								  document.documentElement.classList.remove('theme-dark','theme-light','theme-auto');
								  document.documentElement.classList.add('theme-' + `+fmt.Sprintf("%q", theme)+`);
								  document.documentElement.dir = `+fmt.Sprintf("%q", direction)+`;
								})()`, nil),
								chromedp.Evaluate(`new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))`, nil, func(params *runtime.EvaluateParams) *runtime.EvaluateParams { params.AwaitPromise = true; return params }),
								chromedp.Evaluate(`document.documentElement.scrollWidth`, &scrollWidth),
								chromedp.Evaluate(`performance.getEntriesByType('layout-shift').filter(entry => !entry.hadRecentInput).reduce((total, entry) => total + entry.value, 0)`, &cls),
								chromedp.Evaluate(`(() => {
								  const failures = [];
								  const visible = el => { const s = getComputedStyle(el), r = el.getBoundingClientRect(); return s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0' && r.width > 0 && r.height > 0 && (!el.matches('.skip-link') || el.matches(':focus')); };
								  const appOwned = el => !el.closest('.swagger-ui');
								  const namespaces = new Set(`+string(namespaces)+`);
								  const rawKey = text => { const parts = text.split('.'); return parts.length > 1 && namespaces.has(parts[0]) && parts.slice(1).every(part => /^[a-z0-9_]+$/.test(part)); };
								  for (const node of document.querySelectorAll('body *')) {
								    if (!appOwned(node) || !visible(node) || node.closest('code,pre,kbd,samp')) continue;
								    const text = node.children.length === 0 ? node.textContent.trim() : '';
								    if (text && (rawKey(text) || /undefined|null|NaN|\[object Object\]|\{\{|\}\}|\bTODO\b/.test(text))) failures.push('raw-key-or-placeholder:' + text.slice(0,80));
								  }
								  for (const el of document.querySelectorAll('body *')) {
								    const style = getComputedStyle(el), rect = el.getBoundingClientRect();
								    if (!appOwned(el) || !visible(el) || el.closest('[popover]:not(:popover-open)')) continue;
					if (!el.matches('.table-wrapper,.code-block') && el.closest('.table-wrapper,.code-block')) continue;
								    if (rect.left < -1 || rect.right > innerWidth + 1) failures.push('out-of-viewport:' + el.tagName + '.' + (typeof el.className === 'string' ? el.className : ''));
								    if (el.matches('input,select,textarea') && !el.labels?.length && !el.getAttribute('aria-label')) failures.push('unlabeled-control:' + el.outerHTML.slice(0,120));
								    if (el.matches('select') && !el.options.length) failures.push('empty-select');
								    if (el.matches('button') && !el.innerText.trim() && !el.getAttribute('aria-label')) failures.push('unlabeled-button');
								    if (el.matches('a,button,input,select,textarea,[role="switch"],[role="radio"],[role="tab"],label.toggle,label.check')) {
								      if (el.matches('#nav-toggle') || (el.matches('input[type="checkbox"]') && el.closest('.toggle,.check'))) continue;
								      if (el.matches('a') && getComputedStyle(el).display === 'inline') continue;
									  const label = el.matches('input[type="checkbox"],input[type="radio"]') ? el.labels?.[0] : null;
									  const hitArea = label ? label.getBoundingClientRect() : rect;
								      const minimum = innerWidth < 768 ? 44 : (el.classList.contains('btn-sm') || el.classList.contains('input-sm') ? 24 : 0);
									  if (minimum && (hitArea.width < minimum || hitArea.height < minimum)) failures.push('small-target:' + el.tagName + '.' + el.className);
								    }
								    if (el.matches('.toggle-track,.tile,.segmented-option') && (rect.width === 0 || rect.height === 0)) failures.push('collapsed-custom-control:' + el.className);
								  }
								  const candidates = Array.from(document.querySelectorAll('body *')).filter(el => appOwned(el) && visible(el) && (el.matches('a,button,input,select,textarea,[role="switch"],[role="radio"],[role="tab"],label.toggle,label.check') || (el.children.length === 0 && el.textContent.trim())));
								  for (let i = 0; i < candidates.length; i++) for (let j = i + 1; j < candidates.length; j++) {
								    const a = candidates[i], b = candidates[j];
								    if (a.parentElement !== b.parentElement || a.closest('.toast,.modal,.drawer,.popover') || b.closest('.toast,.modal,.drawer,.popover')) continue;
								    const x = a.getBoundingClientRect(), y = b.getBoundingClientRect();
									  if (x.left < y.right - 1 && x.right > y.left + 1 && x.top < y.bottom - 1 && x.bottom > y.top + 1) failures.push('overlap:' + a.tagName + '.' + a.className + '/' + b.tagName + '.' + b.className + '@' + a.parentElement.tagName + '.' + a.parentElement.className);
								  }
								  for (const selector of ['.section-card', '.form-group']) {
								    const items = Array.from(document.querySelectorAll(selector)).filter(visible);
								    for (let i = 0; i < items.length; i++) for (let j = i + 1; j < items.length; j++) {
								      if (items[i].parentElement !== items[j].parentElement) continue;
								      const a = items[i].getBoundingClientRect(), b = items[j].getBoundingClientRect();
								      const dx = Math.max(b.left - a.right, a.left - b.right), dy = Math.max(b.top - a.bottom, a.top - b.bottom);
								      if (dx <= 0 && dy <= 0) failures.push('zero-gap:' + selector);
								    }
								  }
								  for (const row of document.querySelectorAll('.cluster:has(button),.button-row')) {
								    if (!visible(row)) continue;
								    let next = row.nextElementSibling;
								    if (!next) next = row.parentElement?.nextElementSibling;
								    if (!next || !visible(next)) continue;
								    const a = row.getBoundingClientRect(), b = next.getBoundingClientRect();
								    const dx = Math.max(b.left - a.right, a.left - b.right), dy = Math.max(b.top - a.bottom, a.top - b.bottom);
								    if (dx <= 0 && dy <= 0) failures.push('zero-gap-after-button-row');
								  }
								  return failures;
								})()`, &failures),
							)
							if err != nil {
								t.Fatal(err)
							}
							if scrollWidth > viewport.width || len(failures) != 0 {
								t.Errorf("layout failures at %dx%d: scrollWidth=%d issues=%s", viewport.width, viewport.height, scrollWidth, strings.Join(failures, "; "))
							}
							if cls >= 0.1 {
								t.Errorf("layout shift score = %.3f, want < 0.1", cls)
							}
							if page == "/debug/components" {
								var sizeFailures []string
								if err := chromedp.Run(pageCtx, chromedp.Evaluate(`(() => {
								  const small = innerWidth < 768 ? 44 : 32;
								  const checks = [
					['button-sm', document.querySelector('section[aria-labelledby="gallery-buttons"] .btn-sm')?.getBoundingClientRect().height, small],
					['button-md', document.querySelector('section[aria-labelledby="gallery-buttons"] .btn:not(.btn-sm):not(.btn-lg):not(.btn-xl)')?.getBoundingClientRect().height, 44],
					['button-lg', document.querySelector('section[aria-labelledby="gallery-buttons"] .btn-lg')?.getBoundingClientRect().height, 52],
					['button-xl', document.querySelector('section[aria-labelledby="gallery-buttons"] .btn-xl')?.getBoundingClientRect().height, 60],
					['input-sm', document.querySelector('section[aria-labelledby="gallery-inputs"] .input-sm')?.getBoundingClientRect().height, small],
					['input-md', document.querySelector('#gallery-input')?.getBoundingClientRect().height, 44],
					['input-lg', document.querySelector('section[aria-labelledby="gallery-inputs"] .input-lg')?.getBoundingClientRect().height, 52],
					['toggle-sm', document.querySelector('section[aria-labelledby="gallery-toggles"] .toggle-sm .toggle-track')?.getBoundingClientRect().width, innerWidth < 768 ? 44 : 32],
					['toggle-lg', document.querySelector('section[aria-labelledby="gallery-toggles"] .toggle-lg .toggle-track')?.getBoundingClientRect().width, 52],
					['tile-sm', parseFloat(getComputedStyle(document.querySelector('section[aria-labelledby="gallery-toggles"] .tile-sm')).minWidth), innerWidth < 768 ? 44 : 32],
					['tile-md', parseFloat(getComputedStyle(document.querySelector('section[aria-labelledby="gallery-toggles"] .tile:not(.tile-sm):not(.tile-lg):not(.tile-xl)')).minWidth), 44],
					['tile-lg', parseFloat(getComputedStyle(document.querySelector('section[aria-labelledby="gallery-toggles"] .tile-lg')).minWidth), 52],
					['tile-xl', parseFloat(getComputedStyle(document.querySelector('section[aria-labelledby="gallery-toggles"] .tile-xl')).minWidth), 60],
					['badge-sm', parseFloat(getComputedStyle(document.querySelector('section[aria-labelledby="gallery-status"] .badge-sm')).minHeight), innerWidth < 768 ? 44 : 32],
					['badge-md', parseFloat(getComputedStyle(document.querySelector('section[aria-labelledby="gallery-status"] .badge:not(.badge-sm):not(.badge-lg)')).minHeight), 44],
					['badge-lg', parseFloat(getComputedStyle(document.querySelector('section[aria-labelledby="gallery-status"] .badge-lg')).minHeight), 52],
					['icon-sm', document.querySelector('section[aria-labelledby="gallery-icons"] .icon-sm')?.getBoundingClientRect().width, 16],
					['icon-md', document.querySelector('section[aria-labelledby="gallery-icons"] .icon-md')?.getBoundingClientRect().width, 20],
					['icon-lg', document.querySelector('section[aria-labelledby="gallery-icons"] .icon-lg')?.getBoundingClientRect().width, 24],
					['icon-xl', document.querySelector('section[aria-labelledby="gallery-icons"] .icon-xl')?.getBoundingClientRect().width, 32]
								  ];
								  return checks.filter(([name, actual, expected]) => actual == null || Math.abs(actual - expected) > 1).map(([name, actual, expected]) => name + '=' + actual + ' expected ' + expected);
								})()`, &sizeFailures)); err != nil {
									t.Errorf("check component gallery size: %v", err)
								} else if len(sizeFailures) > 0 {
									t.Errorf("component gallery sizes: %s", strings.Join(sizeFailures, "; "))
								}
							}
							if direction == "ltr" && (theme == "dark" || theme == "light") && viewport.width == 320 {
								var violations []string
								if err := chromedp.Run(pageCtx, chromedp.Evaluate(`axe.run({exclude: [['.swagger-ui']]}).then(result => result.violations.map(v => v.id + ': ' + v.help + ' (' + v.nodes.map(n => n.target.join(' ') + ': ' + n.failureSummary).join('; ') + ')'))`, &violations, func(params *runtime.EvaluateParams) *runtime.EvaluateParams { params.AwaitPromise = true; return params })); err != nil {
									t.Errorf("run axe-core: %v", err)
								} else if len(violations) > 0 {
									t.Errorf("axe-core violations: %s", strings.Join(violations, "; "))
								}
							}
						})
					}
				}
			}
			var drawerDiagnostic string
			if err := chromedp.Run(pageCtx,
				chromedp.EmulateViewport(375, 812),
				chromedp.Click(`label.nav-toggle`, chromedp.ByQuery),
				chromedp.Sleep(350 * time.Millisecond),
				chromedp.Evaluate(`(() => {
				  const panel = document.querySelector('.nav-panel');
				  const rect = panel?.getBoundingClientRect();
				  const desktopLinks = document.querySelectorAll('.nav-links .nav-link').length;
				  const drawerLinks = panel?.querySelectorAll('.nav-link').length || 0;
				  const checked = Boolean(document.querySelector('#nav-toggle')?.checked);
				  return checked && rect && rect.height >= innerHeight - 1 && drawerLinks === desktopLinks ? '' : JSON.stringify({checked, panelDisplay: panel ? getComputedStyle(panel).display : 'missing', panelHeight: rect?.height || 0, viewportHeight: innerHeight, drawerLinks, desktopLinks});
				})()`, &drawerDiagnostic),
			); err != nil {
				t.Errorf("open mobile navigation drawer: %v", err)
		} else if drawerDiagnostic != "" {
			t.Errorf("mobile navigation drawer state: %s", drawerDiagnostic)
			}
			eventMu.Lock()
			defer eventMu.Unlock()
			if len(browserFaults) > 0 {
				t.Errorf("browser reported errors, warnings, or failed requests (%d)", len(browserFaults))
			}
		})
	}
}
