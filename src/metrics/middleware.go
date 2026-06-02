package metrics

import (
	"net/http"
	"strconv"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture status code and size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// HTTPMiddleware instruments HTTP handlers with Prometheus metrics
func (c *Collector) HTTPMiddleware(next http.Handler) http.Handler {
	if c == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Increment active requests
		c.HTTPActiveRequests.Inc()
		defer c.HTTPActiveRequests.Dec()

		// Wrap response writer to capture status and size.
		// statusCode defaults to 200 because net/http treats a missing
		// WriteHeader call as an implicit 200 OK.
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		// Call next handler
		next.ServeHTTP(rw, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		method := r.Method
		path := NormalizePath(r.URL.Path)
		status := strconv.Itoa(rw.statusCode)

		// Increment request counter
		c.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()

		// Record request duration
		c.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)

		// Record request size
		if r.ContentLength > 0 {
			c.HTTPRequestSize.WithLabelValues(method, path).Observe(float64(r.ContentLength))
		}

		// Record response size
		if rw.size > 0 {
			c.HTTPResponseSize.WithLabelValues(method, path).Observe(float64(rw.size))
		}
	})
}
