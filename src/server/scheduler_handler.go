package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SchedulerTask represents a scheduled task
type SchedulerTask struct {
	Name        string `json:"name"`
	Schedule    string `json:"schedule"`     // Cron schedule
	Enabled     bool   `json:"enabled"`      // Can be disabled (if skippable)
	Skippable   bool   `json:"skippable"`    // Can this task be disabled?
	LastRun     string `json:"last_run"`     // ISO timestamp
	NextRun     string `json:"next_run"`     // ISO timestamp
	Status      string `json:"status"`       // success, failed, running, never_run
	Description string `json:"description"`  // Human-readable description
}

// SchedulerStatusResponse represents scheduler status
type SchedulerStatusResponse struct {
	Running       bool            `json:"running"`
	Timezone      string          `json:"timezone"`
	CatchUpWindow string          `json:"catch_up_window"` // e.g., "1h"
	Tasks         []SchedulerTask `json:"tasks"`
}

// SchedulerTaskUpdateRequest represents task configuration update
type SchedulerTaskUpdateRequest struct {
	Name     string `json:"name"`
	Schedule string `json:"schedule,omitempty"` // Optional: update schedule
	Enabled  bool   `json:"enabled"`            // Enable or disable task
}

// handleServerSchedulerSettings serves the scheduler management page HTML
// GET /{admin_path}/server/scheduler
func (s *Server) handleServerSchedulerSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	html := renderServerSchedulerSettingsHTML(adminCtx, s.config.AdminPath)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleServerSchedulerStatusAPI returns scheduler status and all tasks
// GET /api/v1/{admin_path}/server/scheduler
func (s *Server) handleServerSchedulerStatusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get all tasks from scheduler
	tasks := s.scheduler.GetTasks()
	
	// Convert to response format
	apiTasks := make([]SchedulerTask, 0, len(tasks))
	for _, task := range tasks {
		// Determine if task can be skipped (disabled)
		skippable := !task.Global
		
		// Format timestamps
		lastRun := "never"
		if !task.LastRun.IsZero() {
			lastRun = task.LastRun.Format(time.RFC3339)
		}
		
		nextRun := "calculating..."
		if !task.NextRun.IsZero() {
			nextRun = task.NextRun.Format(time.RFC3339)
		}
		
		// Determine status
		status := task.LastStatus
		if status == "" {
			status = "never_run"
		}
		
		// Build description from name
		description := getTaskDescription(task.Name)
		
		apiTasks = append(apiTasks, SchedulerTask{
			Name:        task.Name,
			Schedule:    task.Schedule,
			Enabled:     task.Enabled,
			Skippable:   skippable,
			LastRun:     lastRun,
			NextRun:     nextRun,
			Status:      status,
			Description: description,
		})
	}
	
	status := SchedulerStatusResponse{
		Running:       s.scheduler.IsRunning(),
		Timezone:      s.scheduler.GetTimezone(),
		CatchUpWindow: s.scheduler.GetCatchUpWindow().String(),
		Tasks:         apiTasks,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleServerSchedulerTaskUpdate updates a scheduler task configuration
// POST /api/v1/{admin_path}/server/scheduler/task
func (s *Server) handleServerSchedulerTaskUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	var req SchedulerTaskUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	// Validate task update request
	if err := validateSchedulerTaskUpdate(&req); err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}

	// Update task enabled status
	var err error
	if req.Enabled {
		err = s.scheduler.EnableTask(req.Name)
	} else {
		err = s.scheduler.DisableTask(req.Name)
	}

	if err != nil {
		SendError(w, ErrServerError, "Failed to update task: "+err.Error())
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Task '%s' %s successfully", req.Name, map[bool]string{true: "enabled", false: "disabled"}[req.Enabled]),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleServerSchedulerTaskRun triggers immediate task execution
// POST /api/v1/{admin_path}/server/scheduler/task/run
func (s *Server) handleServerSchedulerTaskRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	if req.Name == "" {
		SendError(w, ErrValidationFailed, "task name is required")
		return
	}

	// Trigger immediate task execution
	if err := s.scheduler.RunTaskNow(req.Name); err != nil {
		SendError(w, ErrServerError, "Failed to run task: "+err.Error())
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Task '%s' triggered successfully", req.Name),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// validateSchedulerTaskUpdate validates task update request
func validateSchedulerTaskUpdate(req *SchedulerTaskUpdateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("task name is required")
	}

	// TODO: Validate cron schedule format if provided
	// For now, just basic validation
	if req.Schedule != "" && len(req.Schedule) < 5 {
		return fmt.Errorf("invalid schedule format")
	}

	return nil
}

// getTaskDescription returns a human-readable description for a task
func getTaskDescription(name string) string {
	descriptions := map[string]string{
		"session.cleanup":       "Remove expired admin sessions",
		"token.cleanup":         "Remove expired reset/verification tokens",
		"cache.cleanup":         "Remove expired cache entries",
		"log.rotation":          "Rotate and compress old log files",
		"backup.daily":          "Daily full database backup",
		"ssl.renewal":           "Renew SSL certificates 7 days before expiry",
		"healthcheck.self":      "Self-health check (database, disk, upstream)",
		"whois.servers.update":  "Update WHOIS server list from IANA",
		"geoip.update":          "Update MaxMind GeoLite2 databases",
	}
	
	if desc, ok := descriptions[name]; ok {
		return desc
	}
	return "Scheduled task"
}

// renderServerSchedulerSettingsHTML generates the scheduler management page HTML
func renderServerSchedulerSettingsHTML(adminCtx *AdminContext, adminPath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scheduler Tasks - Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            line-height: 1.6;
        }
        .header {
            background: #2a2a2a;
            border-bottom: 1px solid #3a3a3a;
            padding: 1rem 2rem;
        }
        .header h1 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
        }
        .section {
            background: #2a2a2a;
            border: 1px solid #3a3a3a;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .section-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #3a3a3a;
        }
        .status-box {
            padding: 1.5rem;
            background: #1a1a1a;
            border: 1px solid #3a3a3a;
            border-radius: 4px;
            margin-bottom: 1.5rem;
        }
        .status-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
        }
        .status-label {
            color: #999;
        }
        .status-value {
            font-weight: 500;
        }
        .status-running {
            color: #4caf50;
        }
        .table-container {
            overflow-x: auto;
        }
        table {
            width: 100%%;
            border-collapse: collapse;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #3a3a3a;
        }
        th {
            background: #1a1a1a;
            font-weight: 600;
        }
        .task-name {
            font-family: monospace;
            color: #64b5f6;
        }
        .task-schedule {
            font-family: monospace;
            font-size: 0.875rem;
            color: #999;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge-success {
            background: #2e7d32;
            color: white;
        }
        .badge-warning {
            background: #f57c00;
            color: white;
        }
        .badge-error {
            background: #c62828;
            color: white;
        }
        .badge-disabled {
            background: #424242;
            color: #999;
        }
        .badge-critical {
            background: #6a1b9a;
            color: white;
        }
        .button {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            font-size: 0.875rem;
            cursor: pointer;
            margin-right: 0.5rem;
        }
        .button-primary {
            background: #007bff;
            color: white;
        }
        .button-success {
            background: #4caf50;
            color: white;
        }
        .button-secondary {
            background: #3a3a3a;
            color: #e0e0e0;
        }
        .button-small {
            padding: 0.25rem 0.75rem;
            font-size: 0.75rem;
        }
        .alert {
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
        .alert.success { background: #2e7d32; color: white; }
        .alert.error { background: #c62828; color: white; }
        .info-box {
            background: #1a3a5a;
            border: 1px solid #2a4a6a;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 1rem;
        }
        .info-box p {
            margin: 0.5rem 0;
        }
        @media (max-width: 768px) {
            .container {
                padding: 0 1rem;
            }
            .section {
                padding: 1.5rem;
            }
            table {
                font-size: 0.875rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Scheduler Tasks</h1>
    </div>
    <div class="container">
        <div id="alert" class="alert"></div>
        
        <div class="section">
            <div class="section-title">Scheduler Status</div>
            <div class="status-box">
                <div class="status-row">
                    <span class="status-label">Status:</span>
                    <span class="status-value status-running" id="schedulerStatus">✅ Running</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Timezone:</span>
                    <span class="status-value" id="timezone">America/New_York</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Catch-up Window:</span>
                    <span class="status-value" id="catchUpWindow">1h</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Scheduled Tasks</div>
            
            <div class="table-container">
                <table id="tasksTable">
                    <thead>
                        <tr>
                            <th>Task</th>
                            <th>Schedule</th>
                            <th>Status</th>
                            <th>Last Run</th>
                            <th>Next Run</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="tasksBody">
                        <tr>
                            <td colspan="6" style="text-align: center; color: #999;">Loading tasks...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="info-box">
                <p><strong>ℹ️ Scheduler Information</strong></p>
                <p>• Built-in scheduler runs automatically (no external cron needed)</p>
                <p>• Critical tasks (SSL renewal, session cleanup) cannot be disabled</p>
                <p>• Optional tasks (backup, GeoIP update) can be enabled/disabled</p>
                <p>• Catch-up logic runs missed tasks if within catch-up window</p>
                <p>• All task execution is logged with success/failure status</p>
            </div>
        </div>
    </div>
    
    <script>
        function showAlert(msg, type) {
            const alert = document.getElementById('alert');
            alert.className = 'alert ' + type;
            alert.textContent = msg;
            alert.style.display = 'block';
            setTimeout(() => alert.style.display = 'none', 5000);
        }
        
        async function loadSchedulerStatus() {
            try {
                const res = await fetch('/api/v1/%s/server/scheduler');
                const data = await res.json();
                
                document.getElementById('schedulerStatus').textContent = data.running ? '✅ Running' : '⚠️ Stopped';
                document.getElementById('timezone').textContent = data.timezone || 'America/New_York';
                document.getElementById('catchUpWindow').textContent = data.catch_up_window || '1h';
                
                renderTasks(data.tasks);
            } catch (e) {
                console.error('Failed to load scheduler status:', e);
                showAlert('Failed to load scheduler status', 'error');
            }
        }
        
        function renderTasks(tasks) {
            const tbody = document.getElementById('tasksBody');
            tbody.innerHTML = '';
            
            if (!tasks || tasks.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #999;">No tasks configured</td></tr>';
                return;
            }
            
            tasks.forEach(task => {
                const row = document.createElement('tr');
                
                const statusBadge = getStatusBadge(task.status);
                const criticalBadge = task.skippable ? '' : '<span class="badge badge-critical">Critical</span> ';
                const enabledBadge = task.enabled ? '<span class="badge badge-success">Enabled</span>' : '<span class="badge badge-disabled">Disabled</span>';
                
                row.innerHTML = '<td>' +
                    '<div class="task-name">' + task.name + '</div>' +
                    '<small style="color: #999;">' + (task.description || '') + '</small>' +
                    '</td>' +
                    '<td><span class="task-schedule">' + task.schedule + '</span></td>' +
                    '<td>' + criticalBadge + enabledBadge + ' ' + statusBadge + '</td>' +
                    '<td>' + (task.last_run || 'Never') + '</td>' +
                    '<td>' + (task.next_run || 'N/A') + '</td>' +
                    '<td>' +
                    '<button class="button button-success button-small" onclick="runTask(\'' + task.name + '\')">Run Now</button>' +
                    (task.skippable ? '<button class="button button-secondary button-small" onclick="toggleTask(\'' + task.name + '\', ' + !task.enabled + ')">' + (task.enabled ? 'Disable' : 'Enable') + '</button>' : '') +
                    '</td>';
                
                tbody.appendChild(row);
            });
        }
        
        function getStatusBadge(status) {
            switch (status) {
                case 'success':
                    return '<span class="badge badge-success">Success</span>';
                case 'failed':
                    return '<span class="badge badge-error">Failed</span>';
                case 'running':
                    return '<span class="badge badge-warning">Running</span>';
                case 'never_run':
                default:
                    return '<span class="badge badge-disabled">Not Run</span>';
            }
        }
        
        async function runTask(name) {
            if (!confirm('Run task "' + name + '" now? This will execute immediately.')) return;
            
            try {
                const res = await fetch('/api/v1/%s/server/scheduler/task/run', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: name })
                });
                const data = await res.json();
                
                if (data.success) {
                    showAlert('Task started successfully', 'success');
                    setTimeout(loadSchedulerStatus, 2000);
                } else {
                    showAlert(data.message || 'Failed to start task', 'error');
                }
            } catch (e) {
                showAlert('Network error: ' + e.message, 'error');
            }
        }
        
        async function toggleTask(name, enable) {
            const action = enable ? 'enable' : 'disable';
            if (!confirm(action.charAt(0).toUpperCase() + action.slice(1) + ' task "' + name + '"?')) return;
            
            try {
                const res = await fetch('/api/v1/%s/server/scheduler/task', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: name, enabled: enable })
                });
                const data = await res.json();
                
                if (data.success) {
                    showAlert(data.message, 'success');
                    loadSchedulerStatus();
                } else {
                    showAlert(data.message || 'Failed to ' + action + ' task', 'error');
                }
            } catch (e) {
                showAlert('Network error: ' + e.message, 'error');
            }
        }
        
        loadSchedulerStatus();
        
        // Auto-refresh every 30 seconds
        setInterval(loadSchedulerStatus, 30000);
    </script>
</body>
</html>`, adminPath, adminPath, adminPath)
}
