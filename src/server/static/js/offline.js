// Retry handler for the PWA offline fallback page (AI.md PART 16 — no inline
// onclick attributes; handlers are wired via addEventListener).
(function () {
  var btn = document.getElementById('offline-retry');
  if (btn) {
    btn.addEventListener('click', function () {
      window.location.reload();
    });
  }
})();
