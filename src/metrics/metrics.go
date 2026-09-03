// Package metrics provides Prometheus-compatible metrics
// See AI.md PART 20: METRICS
package metrics

import (
	"regexp"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collector holds all Prometheus metrics
type Collector struct {
	// Application info (REQUIRED)
	AppInfo      *prometheus.GaugeVec
	AppUptime    prometheus.Gauge
	AppStartTime prometheus.Gauge

	// HTTP metrics (REQUIRED)
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPRequestSize     *prometheus.HistogramVec
	HTTPResponseSize    *prometheus.HistogramVec
	HTTPActiveRequests  prometheus.Gauge

	// Database metrics (REQUIRED)
	DBQueriesTotal     *prometheus.CounterVec
	DBQueryDuration    *prometheus.HistogramVec
	DBConnectionsOpen  prometheus.Gauge
	DBConnectionsInUse prometheus.Gauge
	DBErrorsTotal      *prometheus.CounterVec

	// Cache metrics
	CacheHitsTotal      *prometheus.CounterVec
	CacheMissesTotal    *prometheus.CounterVec
	CacheEvictionsTotal *prometheus.CounterVec
	CacheSize           *prometheus.GaugeVec

	// Scheduler metrics
	SchedulerTasksTotal       *prometheus.CounterVec
	SchedulerTaskDuration     *prometheus.HistogramVec
	SchedulerTasksRunning     *prometheus.GaugeVec
	SchedulerLastRunTimestamp *prometheus.GaugeVec
	SchedulerTaskFailures     *prometheus.CounterVec

	// Authentication metrics
	AuthAttemptsTotal  *prometheus.CounterVec
	AuthSessionsActive prometheus.Gauge

	// System metrics (optional)
	SystemCPU        prometheus.Gauge
	SystemMemory     prometheus.Gauge
	SystemGoroutines prometheus.Gauge

	startTime time.Time
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled         bool
	Endpoint        string
	IncludeSystem   bool
	IncludeRuntime  bool
	Token           string
	DurationBuckets []float64
	SizeBuckets     []float64
}

// New creates a new metrics collector
// All metrics follow AI.md PART 20 naming conventions
func New(namespace string, cfg MetricsConfig) *Collector {
	if !cfg.Enabled {
		return nil
	}

	// Set default buckets if not provided
	if len(cfg.DurationBuckets) == 0 {
		cfg.DurationBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	}
	if len(cfg.SizeBuckets) == 0 {
		cfg.SizeBuckets = []float64{100, 1000, 10000, 100000, 1000000, 10000000}
	}

	c := &Collector{
		startTime: time.Now(),
	}

	// Application info (REQUIRED) - Always 1, labels carry info
	c.AppInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "app_info",
			Help:      "Application information (version, commit, build_date, go_version)",
		},
		[]string{"version", "commit", "build_date", "go_version"},
	)

	// Application uptime (REQUIRED)
	c.AppUptime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "app_uptime_seconds",
			Help:      "Seconds since application start",
		},
	)

	// Application start timestamp (REQUIRED)
	c.AppStartTime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "app_start_timestamp",
			Help:      "Unix timestamp when application started",
		},
	)

	// HTTP requests total (REQUIRED)
	c.HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total HTTP requests processed",
		},
		[]string{"method", "path", "status"},
	)

	// HTTP request duration (REQUIRED)
	c.HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency distribution",
			Buckets:   cfg.DurationBuckets,
		},
		[]string{"method", "path"},
	)

	// HTTP request size (REQUIRED)
	c.HTTPRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_size_bytes",
			Help:      "HTTP request body size distribution",
			Buckets:   cfg.SizeBuckets,
		},
		[]string{"method", "path"},
	)

	// HTTP response size (REQUIRED)
	c.HTTPResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_response_size_bytes",
			Help:      "HTTP response body size distribution",
			Buckets:   cfg.SizeBuckets,
		},
		[]string{"method", "path"},
	)

	// HTTP active requests (REQUIRED)
	c.HTTPActiveRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "http_active_requests",
			Help:      "Number of requests currently being processed",
		},
	)

	// Database queries total (REQUIRED)
	c.DBQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "db_queries_total",
			Help:      "Total database queries",
		},
		[]string{"operation", "table"},
	)

	// Database query duration (REQUIRED)
	c.DBQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "db_query_duration_seconds",
			Help:      "Database query latency distribution",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		},
		[]string{"operation", "table"},
	)

	// Database connections (REQUIRED)
	c.DBConnectionsOpen = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "db_connections_open",
			Help:      "Number of open database connections in pool",
		},
	)

	c.DBConnectionsInUse = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "db_connections_in_use",
			Help:      "Number of database connections actively in use",
		},
	)

	// Database errors (REQUIRED)
	c.DBErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "db_errors_total",
			Help:      "Total database errors",
		},
		[]string{"operation", "error_type"},
	)

	// Cache metrics
	c.CacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_hits_total",
			Help:      "Total cache hits",
		},
		[]string{"cache"},
	)

	c.CacheMissesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_misses_total",
			Help:      "Total cache misses",
		},
		[]string{"cache"},
	)

	c.CacheEvictionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_evictions_total",
			Help:      "Total cache evictions",
		},
		[]string{"cache"},
	)

	c.CacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cache_size",
			Help:      "Current number of items in cache",
		},
		[]string{"cache"},
	)

	// Scheduler metrics
	c.SchedulerTasksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "scheduler_tasks_total",
			Help:      "Total scheduler tasks executed",
		},
		[]string{"task", "status"},
	)

	c.SchedulerTaskDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "scheduler_task_duration_seconds",
			Help:      "Scheduler task execution duration",
			Buckets:   []float64{0.1, 0.5, 1, 5, 10, 30, 60, 300, 600},
		},
		[]string{"task"},
	)

	c.SchedulerTasksRunning = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "scheduler_tasks_running",
			Help:      "Currently running task instances",
		},
		[]string{"task"},
	)

	c.SchedulerLastRunTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "scheduler_last_run_timestamp",
			Help:      "Unix timestamp of last task execution",
		},
		[]string{"task"},
	)

	c.SchedulerTaskFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "scheduler_task_failures_total",
			Help:      "Total scheduler task failures",
		},
		[]string{"task", "error_type"},
	)

	// Authentication metrics
	c.AuthAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_attempts_total",
			Help:      "Total authentication attempts",
		},
		[]string{"method", "status"},
	)

	c.AuthSessionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "auth_sessions_active",
			Help:      "Number of active authentication sessions",
		},
	)

	// System metrics (optional)
	if cfg.IncludeSystem {
		c.SystemCPU = promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "system_cpu_percent",
				Help:      "CPU usage percentage",
			},
		)

		c.SystemMemory = promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "system_memory_bytes",
				Help:      "Memory usage in bytes",
			},
		)

		c.SystemGoroutines = promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "system_goroutines",
				Help:      "Number of goroutines",
			},
		)
	}

	// Set initial values
	c.AppStartTime.Set(float64(c.startTime.Unix()))

	return c
}

// SetAppInfo sets the application info metric
func (c *Collector) SetAppInfo(version, commit, buildDate, goVersion string) {
	if c == nil || c.AppInfo == nil {
		return
	}
	c.AppInfo.WithLabelValues(version, commit, buildDate, goVersion).Set(1)
}

// UpdateSystemMetrics updates system-level metrics
func (c *Collector) UpdateSystemMetrics() {
	if c == nil {
		return
	}

	// Update uptime
	if c.AppUptime != nil {
		c.AppUptime.Set(time.Since(c.startTime).Seconds())
	}

	// Update goroutines count
	if c.SystemGoroutines != nil {
		c.SystemGoroutines.Set(float64(runtime.NumGoroutine()))
	}

	// Update memory stats
	if c.SystemMemory != nil {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		c.SystemMemory.Set(float64(m.Alloc))
	}
}

// Compiled regexps for NormalizePath — package-level to avoid repeated compilation.
var (
	reUUID          = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reWhoisIP       = regexp.MustCompile(`^(/api/v1/whois/ip/)([^/]+)(.*)$`)
	reWhoisDomain   = regexp.MustCompile(`^(/api/v1/whois/domain/)([^/]+)(.*)$`)
	reWhoisASN      = regexp.MustCompile(`^(/api/v1/whois/asn/)([^/]+)(.*)$`)
	reWhoisValidate = regexp.MustCompile(`^(/api/v1/whois/validate/)([^/]+)(.*)$`)
	reWhoisGeneric  = regexp.MustCompile(`^(/api/v1/whois/)([^/]+)(.*)$`)
)

// NormalizePath normalizes URL path for metrics by replacing high-cardinality
// segments (UUIDs, IP addresses, domain names, ASNs, query values) with named
// placeholders. This prevents metrics label explosion (AI.md PART 20).
func NormalizePath(path string) string {
	// Replace WHOIS sub-resource paths before the generic whois rule to preserve ordering.
	if reWhoisIP.MatchString(path) {
		path = reWhoisIP.ReplaceAllString(path, "${1}:ip${3}")
	} else if reWhoisDomain.MatchString(path) {
		path = reWhoisDomain.ReplaceAllString(path, "${1}:domain${3}")
	} else if reWhoisASN.MatchString(path) {
		path = reWhoisASN.ReplaceAllString(path, "${1}:asn${3}")
	} else if reWhoisValidate.MatchString(path) {
		path = reWhoisValidate.ReplaceAllString(path, "${1}:query${3}")
	} else if reWhoisGeneric.MatchString(path) {
		// Preserve static terminal segments like "bulk".
		m := reWhoisGeneric.FindStringSubmatch(path)
		if m != nil && m[2] != "bulk" {
			path = reWhoisGeneric.ReplaceAllString(path, "${1}:query${3}")
		}
	}

	// Replace any remaining UUIDs with :id.
	path = reUUID.ReplaceAllString(path, ":id")

	return path
}
