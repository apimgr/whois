package server

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// handleAdminDashboard serves the admin dashboard (requires authentication)
// GET /{admin_path} or /{admin_path}/dashboard
func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		// Should not happen if middleware is working
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	// Serve dashboard HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := s.renderAdminDashboardHTML(adminCtx)
	fmt.Fprint(w, html)
}

// renderAdminDashboardHTML returns the admin dashboard HTML
func (s *Server) renderAdminDashboardHTML(adminCtx *AdminContext) string {
	// Calculate uptime
	uptime := time.Since(s.startTime)
	days := int(uptime.Hours() / 24)
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memUsedMB := m.Alloc / 1024 / 1024
	memTotalMB := m.Sys / 1024 / 1024

	adminPath := s.config.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" class="theme-dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - CASWHOIS</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }
        .header {
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            color: #58a6ff;
            font-size: 1.5rem;
        }
        .header .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .header .user-name {
            color: #8b949e;
        }
        .header a {
            color: #58a6ff;
            text-decoration: none;
        }
        .header a:hover {
            text-decoration: underline;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
        }
        .stat-card h3 {
            color: #8b949e;
            font-size: 0.9rem;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
            font-weight: normal;
        }
        .stat-card .value {
            color: #58a6ff;
            font-size: 2rem;
            font-weight: 600;
        }
        .stat-card .label {
            color: #8b949e;
            font-size: 0.85rem;
            margin-top: 0.25rem;
        }
        .section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .section h2 {
            color: #c9d1d9;
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid #30363d;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 0.75rem 0;
            border-bottom: 1px solid #21262d;
        }
        .info-row:last-child {
            border-bottom: none;
        }
        .info-row .label {
            color: #8b949e;
        }
        .info-row .value {
            color: #c9d1d9;
            font-weight: 500;
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%%;
            background: #2ea043;
            margin-right: 0.5rem;
        }
        .btn {
            display: inline-block;
            padding: 0.5rem 1rem;
            background: #238636;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 0.9rem;
            margin-right: 0.5rem;
            margin-top: 0.5rem;
        }
        .btn:hover {
            background: #2ea043;
        }
        .btn-secondary {
            background: #21262d;
        }
        .btn-secondary:hover {
            background: #30363d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔧 CASWHOIS Admin</h1>
        <div class="user-info">
            <span class="user-name">%s</span>
            <a href="/auth/logout">Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Status</h3>
                <div class="value">
                    <span class="status-indicator"></span>Online
                </div>
                <div class="label">Service is running</div>
            </div>

            <div class="stat-card">
                <h3>Uptime</h3>
                <div class="value">%dd %dh %dm</div>
                <div class="label">Since last restart</div>
            </div>

            <div class="stat-card">
                <h3>Memory</h3>
                <div class="value">%d MB</div>
                <div class="label">%d MB total allocated</div>
            </div>

            <div class="stat-card">
                <h3>Cache Hit Rate</h3>
                <div class="value">--</div>
                <div class="label">Not yet implemented</div>
            </div>
        </div>

        <div class="section">
            <h2>Server Information</h2>
            <div class="info-row">
                <span class="label">Address</span>
                <span class="value">%s:%d</span>
            </div>
            <div class="info-row">
                <span class="label">Version</span>
                <span class="value">%s</span>
            </div>
            <div class="info-row">
                <span class="label">Go Version</span>
                <span class="value">%s</span>
            </div>
            <div class="info-row">
                <span class="label">Database</span>
                <span class="value">%s</span>
            </div>
            <div class="info-row">
                <span class="label">Admin Path</span>
                <span class="value">/%s</span>
            </div>
        </div>

        <div class="section">
            <h2>Quick Actions</h2>
            <a href="/%s/server/setup" class="btn btn-secondary">Setup Wizard</a>
            <a href="/healthz" class="btn btn-secondary">Health Check</a>
            <a href="/api/v1/stats" class="btn btn-secondary">API Stats</a>
            <a href="/api/v1/whois-servers" class="btn btn-secondary">WHOIS Servers</a>
        </div>

        <div class="section">
            <h2>Admin Account</h2>
            <div class="info-row">
                <span class="label">Email</span>
                <span class="value">%s</span>
            </div>
            <div class="info-row">
                <span class="label">Name</span>
                <span class="value">%s</span>
            </div>
            <div class="info-row">
                <span class="label">Account Type</span>
                <span class="value">%s</span>
            </div>
            <div class="info-row">
                <span class="label">Last Login</span>
                <span class="value">%s</span>
            </div>
        </div>

        <div class="section">
            <h2>Admin Features</h2>
            <p style="color: #8b949e; margin-bottom: 1rem;">
                Manage your WHOIS server from the admin panel:
            </p>
            <ul style="color: #8b949e; margin-left: 1.5rem; line-height: 2;">
                <li><a href="/%s/server/settings" style="color: #58a6ff;">Configure server settings</a> - Adjust server configuration</li>
                <li><a href="/%s/profile" style="color: #58a6ff;">Manage your account</a> - Update profile and credentials</li>
                <li><a href="/%s/server/email" style="color: #58a6ff;">Email configuration</a> - Configure SMTP settings</li>
                <li><a href="/%s/server/scheduler" style="color: #58a6ff;">Scheduled tasks</a> - Manage automated tasks</li>
                <li><a href="/%s/server/backup" style="color: #58a6ff;">Backup & restore</a> - Database backup management</li>
                <li><a href="/%s/server/ssl" style="color: #58a6ff;">SSL/TLS certificates</a> - Configure HTTPS certificates</li>
            </ul>
        </div>
    </div>
</body>
</html>`,
		adminCtx.Admin.Name,
		days, hours, minutes,
		memUsedMB,
		memTotalMB,
		s.config.Address, s.config.Port,
		Version,
		runtime.Version(),
		s.database.Driver,
		adminPath,
		adminPath,
		adminCtx.Admin.Email,
		adminCtx.Admin.Name,
		func() string {
			if adminCtx.Admin.IsSuper {
				return "Super Admin"
			}
			return "Admin"
		}(),
		func() string {
			if adminCtx.Admin.LastLogin != nil {
				return adminCtx.Admin.LastLogin.Format("2006-01-02 15:04:05")
			}
			return "Never"
		}(),
		adminPath,  // for settings link
		adminPath,  // for profile link
		adminPath,  // for email link
		adminPath,  // for scheduler link
		adminPath,  // for backup link
		adminPath,  // for ssl link
	)
}
