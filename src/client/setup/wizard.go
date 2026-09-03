package setup

import (
	"fmt"
	"strings"

	"github.com/apimgr/whois/src/client/config"
	"github.com/apimgr/whois/src/client/lookup"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// step tracks wizard progress
type step int

const (
	stepURL step = iota
	stepTest
	stepToken
	stepDone
)

// testDoneMsg carries the result of the connection test
type testDoneMsg struct {
	err error
}

var (
	styleTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	styleOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	styleErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleHint  = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
)

// WizardModel is the bubbletea wizard model
type WizardModel struct {
	step    step
	urlIn   textinput.Model
	tokenIn textinput.Model
	testErr error
	cfg     *config.CLIConfig
}

// New creates a new wizard model with the provided initial config
func New(cfg *config.CLIConfig) WizardModel {
	urlIn := textinput.New()
	urlIn.Placeholder = "http://localhost:64580"
	urlIn.Focus()
	urlIn.CharLimit = 512
	urlIn.Width = 50

	tokenIn := textinput.New()
	tokenIn.Placeholder = "tok_… (leave blank to skip)"
	tokenIn.CharLimit = 80
	tokenIn.Width = 50

	if cfg.Server != "" {
		urlIn.SetValue(cfg.Server)
	}

	return WizardModel{
		step:    stepURL,
		urlIn:   urlIn,
		tokenIn: tokenIn,
		cfg:     cfg,
	}
}

// Init starts the blink cursor
func (m WizardModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages
func (m WizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit

		case tea.KeyEnter:
			return m.handleEnter()
		}

	case testDoneMsg:
		if msg.err != nil {
			m.testErr = msg.err
			m.step = stepURL
			m.urlIn.Focus()
			return m, nil
		}
		m.step = stepToken
		m.tokenIn.Focus()
		return m, nil
	}

	var cmd tea.Cmd
	switch m.step {
	case stepURL:
		m.urlIn, cmd = m.urlIn.Update(msg)
	case stepToken:
		m.tokenIn, cmd = m.tokenIn.Update(msg)
	}
	return m, cmd
}

// handleEnter advances the wizard on Enter key press
func (m WizardModel) handleEnter() (tea.Model, tea.Cmd) {
	switch m.step {
	case stepURL:
		serverURL := strings.TrimSpace(m.urlIn.Value())
		if serverURL == "" {
			return m, nil
		}
		m.cfg.Server = serverURL
		m.testErr = nil
		m.step = stepTest
		return m, m.testConnection(serverURL)

	case stepToken:
		token := strings.TrimSpace(m.tokenIn.Value())
		m.cfg.Token = token
		m.step = stepDone
		return m, tea.Quit
	}
	return m, nil
}

// testConnection pings /server/healthz in a goroutine
func (m WizardModel) testConnection(serverURL string) tea.Cmd {
	return func() tea.Msg {
		client := lookup.New(serverURL, "", "")
		err := client.HealthCheck()
		return testDoneMsg{err: err}
	}
}

// View renders the wizard
func (m WizardModel) View() string {
	var sb strings.Builder
	sb.WriteString(styleTitle.Render("caswhois-cli setup") + "\n\n")

	switch m.step {
	case stepURL:
		sb.WriteString("Step 1/2: Enter the caswhois server URL\n\n")
		sb.WriteString(m.urlIn.View())
		sb.WriteString("\n\n")
		if m.testErr != nil {
			sb.WriteString(styleErr.Render("Connection failed: "+m.testErr.Error()) + "\n")
			sb.WriteString("Please correct the URL and try again.\n")
		}
		sb.WriteString(styleHint.Render("[enter] continue  [ctrl+c] quit"))

	case stepTest:
		sb.WriteString(fmt.Sprintf("Testing connection to %s…\n", m.cfg.Server))

	case stepToken:
		sb.WriteString(styleOK.Render("Connected successfully!") + "\n\n")
		sb.WriteString("Step 2/2: Enter an API token (optional)\n\n")
		sb.WriteString(m.tokenIn.View())
		sb.WriteString("\n\n")
		sb.WriteString(styleHint.Render("[enter] save  [ctrl+c] quit"))

	case stepDone:
		sb.WriteString(styleOK.Render("Configuration saved.") + "\n")
	}

	return sb.String()
}

// Run launches the setup wizard and saves the resulting config to the default path.
func Run(cfg *config.CLIConfig) (*config.CLIConfig, error) {
	return RunTo(cfg, config.ConfigPath())
}

// RunTo launches the setup wizard and saves the resulting config to path.
// Use config.ResolveConfigPath to turn a --config flag value into path.
func RunTo(cfg *config.CLIConfig, path string) (*config.CLIConfig, error) {
	m := New(cfg)
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		return nil, err
	}

	finalWizardModel, ok := final.(WizardModel)
	if !ok {
		return nil, fmt.Errorf("unexpected model type from wizard")
	}

	if finalWizardModel.step != stepDone {
		return nil, fmt.Errorf("setup cancelled")
	}

	if err := config.SaveTo(path, finalWizardModel.cfg); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	return finalWizardModel.cfg, nil
}
