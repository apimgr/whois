package server

import (
	"context"
	"database/sql"
	"log"
	"sort"
	"sync"
	"time"
)

const hotCounterBatchSize = 250

type hotCounterBuffer struct {
	mu     sync.Mutex
	tokens map[string]int64
	owners map[string]int64
	events []rateLimitEvent
}

type rateLimitEvent struct {
	key        string
	occurredAt int64
}

func (s *Server) queueTokenUse(tokenID, ownerID string, now int64) int64 {
	s.hotCounters.mu.Lock()
	defer s.hotCounters.mu.Unlock()
	if s.hotCounters.tokens == nil {
		s.hotCounters.tokens = make(map[string]int64)
		s.hotCounters.owners = make(map[string]int64)
	}
	if queued, ok := s.hotCounters.tokens[tokenID]; ok && queued > now-60 {
		return queued
	}
	s.hotCounters.tokens[tokenID] = now
	s.hotCounters.owners[ownerID] = now
	return now
}

func (s *Server) queueRateLimitEvent(key string, occurredAt int64) {
	s.hotCounters.mu.Lock()
	s.hotCounters.events = append(s.hotCounters.events, rateLimitEvent{key: key, occurredAt: occurredAt})
	s.hotCounters.mu.Unlock()
}

func (s *Server) runHotCounterFlush(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.flushHotCounters(ctx); err != nil {
				log.Printf("WARN: hot counter flush failed: %v", err)
			}
		case <-ctx.Done():
			if err := s.flushHotCounters(context.Background()); err != nil {
				log.Printf("WARN: final hot counter flush failed: %v", err)
			}
			return
		}
	}
}

func (s *Server) flushHotCounters(ctx context.Context) error {
	s.hotCounters.mu.Lock()
	tokens := s.hotCounters.tokens
	owners := s.hotCounters.owners
	events := s.hotCounters.events
	s.hotCounters.tokens = nil
	s.hotCounters.owners = nil
	s.hotCounters.events = nil
	s.hotCounters.mu.Unlock()
	if s.database == nil {
		return nil
	}
	if len(tokens) == 0 && len(owners) == 0 && len(events) == 0 {
		return s.cleanupRateLimitEvents(ctx)
	}

	tokenIDs := make([]string, 0, len(tokens))
	for id := range tokens {
		tokenIDs = append(tokenIDs, id)
	}
	ownerIDs := make([]string, 0, len(owners))
	for id := range owners {
		ownerIDs = append(ownerIDs, id)
	}
	sort.Strings(tokenIDs)
	sort.Strings(ownerIDs)
	for tokenStart, ownerStart, eventStart := 0, 0, 0; tokenStart < len(tokenIDs) || ownerStart < len(ownerIDs) || eventStart < len(events); {
		remaining := hotCounterBatchSize
		tokenEnd := min(tokenStart+remaining, len(tokenIDs))
		remaining -= tokenEnd - tokenStart
		ownerEnd := min(ownerStart+remaining, len(ownerIDs))
		remaining -= ownerEnd - ownerStart
		eventEnd := min(eventStart+remaining, len(events))
		tokenBatch := tokenIDs[tokenStart:tokenEnd]
		ownerBatch := ownerIDs[ownerStart:ownerEnd]
		eventBatch := events[eventStart:eventEnd]
		err := s.database.Write(ctx, func(tx *sql.Tx) error {
			for _, id := range tokenBatch {
				usedAt := tokens[id]
				if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at <= ?)`, usedAt, id, usedAt-60); err != nil {
					return err
				}
			}
			for _, id := range ownerBatch {
				seenAt := owners[id]
				if _, err := tx.ExecContext(ctx, `UPDATE owners SET last_seen_at = ? WHERE id = ? AND last_seen_at <= ?`, seenAt, id, seenAt-60); err != nil {
					return err
				}
			}
			for _, event := range eventBatch {
				if _, err := tx.ExecContext(ctx, `INSERT INTO rate_limit_events(event_key, occurred_at) VALUES(?, ?)`, event.key, event.occurredAt); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			s.requeueHotCounters(tokenBatch, ownerBatch, eventBatch, tokens, owners)
			return err
		}
		tokenStart = tokenEnd
		ownerStart = ownerEnd
		eventStart = eventEnd
		if tokenStart < len(tokenIDs) || ownerStart < len(ownerIDs) || eventStart < len(events) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return s.cleanupRateLimitEvents(ctx)
}

func (s *Server) cleanupRateLimitEvents(ctx context.Context) error {
	cutoff := (time.Now().Unix() - int64(s.maxRateLimitWindow())) * 1000
	for {
		var deleted int64
		err := s.database.Write(ctx, func(tx *sql.Tx) error {
			result, err := tx.ExecContext(ctx, `DELETE FROM rate_limit_events WHERE id IN (SELECT id FROM rate_limit_events WHERE occurred_at <= ? ORDER BY id LIMIT 500)`, cutoff)
			if err != nil {
				return err
			}
			deleted, err = result.RowsAffected()
			return err
		})
		if err != nil || deleted < 500 {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *Server) requeueHotCounters(tokenIDs, ownerIDs []string, events []rateLimitEvent, tokens, owners map[string]int64) {
	s.hotCounters.mu.Lock()
	defer s.hotCounters.mu.Unlock()
	if s.hotCounters.tokens == nil {
		s.hotCounters.tokens = make(map[string]int64)
		s.hotCounters.owners = make(map[string]int64)
	}
	for _, id := range tokenIDs {
		if current, ok := s.hotCounters.tokens[id]; !ok || current < tokens[id] {
			s.hotCounters.tokens[id] = tokens[id]
		}
	}
	for _, id := range ownerIDs {
		if current, ok := s.hotCounters.owners[id]; !ok || current < owners[id] {
			s.hotCounters.owners[id] = owners[id]
		}
	}
	s.hotCounters.events = append(events, s.hotCounters.events...)
}
