package server

import (
	"fmt"
)

func notificationsCSSContent(s *Server) string {
	duration := s.config.Notifications.WebUI.Duration
	if duration < 0 {
		duration = 0
	}
	warningDuration := s.config.Notifications.WebUI.WarningDuration
	if warningDuration < 0 {
		warningDuration = 0
	}
	return fmt.Sprintf("@layer components{.toast{--toast-duration:%ds;--toast-duration-warning:%ds}}\n", duration, warningDuration)
}
