package tui

import (
	"fmt"
	"strings"

	"github.com/apimgr/whois/src/client/lookup"
	"github.com/apimgr/whois/src/common/theme"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// palette is resolved once at startup from the system/config theme mode.
var palette = theme.GetThemePalette("auto")

var (
	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(palette.Border)).
			Padding(0, 1)

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(palette.Primary))

	styleLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color(palette.Muted))

	styleResult = lipgloss.NewStyle().
			Foreground(lipgloss.Color(palette.Foreground))

	styleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color(palette.Error))

	styleHelp = lipgloss.NewStyle().
			Foreground(lipgloss.Color(palette.Muted)).
			Italic(true)

	styleLoading = lipgloss.NewStyle().
			Foreground(lipgloss.Color(palette.Warning))
)

// lookupDoneMsg is sent when a lookup completes
type lookupDoneMsg struct {
	result *lookup.Result
	err    error
}

// TUIModel is the bubbletea model for the TUI
type TUIModel struct {
	client  *lookup.Client
	input   textinput.Model
	result  string
	loading bool
	err     error
	width   int
	height  int
}

// New creates a new TUI model bound to the given lookup client
func New(client *lookup.Client) TUIModel {
	ti := textinput.New()
	ti.Placeholder = "example.com, 8.8.8.8, AS15169…"
	ti.Focus()
	ti.CharLimit = 253
	ti.Width = 40

	return TUIModel{
		client: client,
		input:  ti,
	}
}

// Init focuses the input on startup
func (m TUIModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages and keypresses
func (m TUIModel) Update(msg tea.Msg) (TUIModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			if m.input.Value() == "" {
				return m, tea.Quit
			}
			m.input.SetValue("")
			m.result = ""
			m.err = nil
			return m, nil

		case tea.KeyEnter:
			query := strings.TrimSpace(m.input.Value())
			if query == "" || m.loading {
				return m, nil
			}
			m.loading = true
			m.result = ""
			m.err = nil
			return m, m.doLookup(query)
		}

		switch msg.String() {
		case "q":
			if !m.input.Focused() {
				return m, tea.Quit
			}
		}

	case lookupDoneMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.result = formatResult(msg.result)
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// View renders the full-screen TUI
func (m TUIModel) View() string {
	title := styleTitle.Render("caswhois")

	queryLabel := styleLabel.Render("Query: ")
	inputField := m.input.View()
	queryRow := queryLabel + inputField

	var body string
	switch {
	case m.loading:
		body = styleLoading.Render("Looking up… please wait")
	case m.err != nil:
		body = styleError.Render("Error: " + m.err.Error())
	case m.result != "":
		body = styleResult.Render(m.result)
	default:
		body = styleLabel.Render("Enter a domain, IP address, or ASN above and press Enter.")
	}

	helpLine := styleHelp.Render("[ctrl+c / esc] quit or clear  [enter] lookup")

	content := fmt.Sprintf(
		"%s\n\n%s\n\n%s\n\n%s",
		title,
		queryRow,
		body,
		helpLine,
	)

	if m.width > 0 {
		return styleBorder.Width(m.width - 4).Render(content)
	}
	return styleBorder.Render(content)
}

// doLookup performs the WHOIS lookup in a goroutine and returns the result as a Cmd
func (m TUIModel) doLookup(query string) tea.Cmd {
	return func() tea.Msg {
		result, err := m.client.Lookup(query)
		return lookupDoneMsg{result: result, err: err}
	}
}

// formatResult formats a lookup.Result for display in the TUI
func formatResult(r *lookup.Result) string {
	if r == nil {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Query:     %s\n", r.Query)
	fmt.Fprintf(&sb, "Type:      %s\n", r.Type)
	fmt.Fprintf(&sb, "Server:    %s\n", r.Server)
	fmt.Fprintf(&sb, "Timestamp: %s\n", r.Timestamp)
	if r.Raw != "" {
		sb.WriteString("\n")
		sb.WriteString(r.Raw)
	}
	return sb.String()
}

// Run starts the TUI program
func Run(client *lookup.Client) error {
	p := tea.NewProgram(New(client), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
