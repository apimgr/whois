package server

import (
	"sync/atomic"
	"time"
)

// serverStats holds runtime counters for the server, all updated atomically.
type serverStats struct {
	requestsTotal atomic.Int64
	requests24h   atomic.Int64
	// dayStart stores the Unix timestamp (seconds) of the start of the current UTC day.
	// When today's day start differs from stored, requests24h is reset.
	dayStart      atomic.Int64
	activeConns   atomic.Int32
	domainQueries atomic.Int64
	ipQueries     atomic.Int64
	asnQueries    atomic.Int64
}

// recordRequest increments the total request counter and the 24-hour sliding counter.
// The 24h counter resets when the UTC calendar day changes.
func (st *serverStats) recordRequest() {
	st.requestsTotal.Add(1)

	today := time.Now().UTC().Truncate(24 * time.Hour).Unix()
	old := st.dayStart.Load()
	if old != today {
		// First request of a new day — try to claim the reset.
		// If CAS fails another goroutine already reset it; just increment.
		if st.dayStart.CompareAndSwap(old, today) {
			st.requests24h.Store(1)
		} else {
			st.requests24h.Add(1)
		}
	} else {
		st.requests24h.Add(1)
	}
}

// connOpen increments the active-connections gauge.
func (st *serverStats) connOpen() { st.activeConns.Add(1) }

// connClose decrements the active-connections gauge.
func (st *serverStats) connClose() { st.activeConns.Add(-1) }
