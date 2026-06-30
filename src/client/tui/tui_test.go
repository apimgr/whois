package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/client/lookup"
	tea "github.com/charmbracelet/bubbletea"
)

func newTestClient() *lookup.Client {
	return lookup.New("http://localhost:0", "", "test")
}

func TestNew_InitialState(t *testing.T) {
	client := newTestClient()
	m := New(client)
	if m.client == nil {
		t.Fatal("client should not be nil")
	}
	if m.loading {
		t.Error("loading should be false initially")
	}
	if m.result != "" {
		t.Error("result should be empty initially")
	}
	if m.err != nil {
		t.Error("err should be nil initially")
	}
}

func TestInit_ReturnsBlink(t *testing.T) {
	m := New(newTestClient())
	cmd := m.Init()
	if cmd == nil {
		t.Error("Init should return a non-nil Cmd")
	}
}

func TestView_EmptyState(t *testing.T) {
	m := New(newTestClient())
	v := m.View()
	if !strings.Contains(v, "caswhois") {
		t.Error("View should contain 'caswhois' title")
	}
	if !strings.Contains(v, "Enter a domain") {
		t.Error("View should contain placeholder text")
	}
}

func TestView_WithError(t *testing.T) {
	m := New(newTestClient())
	m.err = errors.New("lookup failed")
	v := m.View()
	if !strings.Contains(v, "lookup failed") {
		t.Error("View should display error message")
	}
}

func TestView_WithResult(t *testing.T) {
	m := New(newTestClient())
	m.result = "example.com WHOIS data"
	v := m.View()
	if !strings.Contains(v, "example.com WHOIS data") {
		t.Error("View should display result")
	}
}

func TestView_Loading(t *testing.T) {
	m := New(newTestClient())
	m.loading = true
	v := m.View()
	if !strings.Contains(v, "Looking up") {
		t.Error("View should show loading message")
	}
}

func TestView_WithWidth(t *testing.T) {
	m := New(newTestClient())
	m.width = 80
	v := m.View()
	if v == "" {
		t.Error("View should return non-empty string with width set")
	}
}

func TestUpdate_WindowSize(t *testing.T) {
	m := New(newTestClient())
	msg := tea.WindowSizeMsg{Width: 100, Height: 40}
	result, _ := m.Update(msg)
	updated := result.(TUIModel)
	if updated.width != 100 {
		t.Errorf("width = %d, want 100", updated.width)
	}
	if updated.height != 40 {
		t.Errorf("height = %d, want 40", updated.height)
	}
}

func TestUpdate_CtrlC_EmptyInput(t *testing.T) {
	m := New(newTestClient())
	msg := tea.KeyMsg{Type: tea.KeyCtrlC}
	_, cmd := m.Update(msg)
	if cmd == nil {
		t.Error("CtrlC with empty input should return quit cmd")
	}
}

func TestUpdate_Esc_EmptyInput(t *testing.T) {
	m := New(newTestClient())
	msg := tea.KeyMsg{Type: tea.KeyEsc}
	_, cmd := m.Update(msg)
	if cmd == nil {
		t.Error("Esc with empty input should return quit cmd")
	}
}

func TestUpdate_Esc_WithInput_ClearsInput(t *testing.T) {
	m := New(newTestClient())
	m.input.SetValue("example.com")
	m.result = "some result"
	m.err = errors.New("some error")

	msg := tea.KeyMsg{Type: tea.KeyEsc}
	result, cmd := m.Update(msg)
	if cmd != nil {
		t.Error("Esc with input should not quit")
	}
	updated := result.(TUIModel)
	if updated.result != "" {
		t.Error("result should be cleared")
	}
	if updated.err != nil {
		t.Error("err should be cleared")
	}
}

func TestUpdate_Enter_EmptyQuery(t *testing.T) {
	m := New(newTestClient())
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	result, cmd := m.Update(msg)
	updated := result.(TUIModel)
	if updated.loading {
		t.Error("should not be loading on empty query")
	}
	if cmd != nil {
		t.Error("no cmd should be issued for empty query")
	}
}

func TestUpdate_Enter_WhileLoading(t *testing.T) {
	m := New(newTestClient())
	m.loading = true
	m.input.SetValue("example.com")
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	_, cmd := m.Update(msg)
	if cmd != nil {
		t.Error("no cmd should be issued while already loading")
	}
}

func TestUpdate_Enter_WithQuery(t *testing.T) {
	m := New(newTestClient())
	m.input.SetValue("example.com")
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	result, cmd := m.Update(msg)
	updated := result.(TUIModel)
	if !updated.loading {
		t.Error("should be loading after enter with query")
	}
	if cmd == nil {
		t.Error("should return a lookup cmd")
	}
}

func TestUpdate_LookupDoneMsg_WithResult(t *testing.T) {
	m := New(newTestClient())
	m.loading = true
	r := &lookup.Result{Query: "example.com", Type: "domain"}
	msg := lookupDoneMsg{result: r, err: nil}
	result, _ := m.Update(msg)
	updated := result.(TUIModel)
	if updated.loading {
		t.Error("should not be loading after result")
	}
	if !strings.Contains(updated.result, "example.com") {
		t.Error("result should contain query")
	}
}

func TestUpdate_LookupDoneMsg_WithError(t *testing.T) {
	m := New(newTestClient())
	m.loading = true
	msg := lookupDoneMsg{result: nil, err: errors.New("not found")}
	result, _ := m.Update(msg)
	updated := result.(TUIModel)
	if updated.loading {
		t.Error("should not be loading after error")
	}
	if updated.err == nil {
		t.Error("err should be set")
	}
}

func TestUpdate_QKey_NotFocused(t *testing.T) {
	m := New(newTestClient())
	m.input.Blur()
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	_, cmd := m.Update(msg)
	if cmd == nil {
		t.Error("'q' when input is not focused should return quit cmd")
	}
}

func TestFormatResult_Nil(t *testing.T) {
	got := formatResult(nil)
	if got != "" {
		t.Errorf("formatResult(nil) = %q, want empty string", got)
	}
}

func TestFormatResult_WithData(t *testing.T) {
	r := &lookup.Result{
		Query:     "8.8.8.8",
		Type:      "ip",
		Server:    "whois.iana.org",
		Timestamp: "2025-01-01T00:00:00Z",
		Raw:       "raw whois data",
	}
	got := formatResult(r)
	checks := []string{"8.8.8.8", "ip", "whois.iana.org", "raw whois data"}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("formatResult missing %q in output", want)
		}
	}
}

func TestFormatResult_EmptyRaw(t *testing.T) {
	r := &lookup.Result{
		Query: "example.com",
		Type:  "domain",
		Raw:   "",
	}
	got := formatResult(r)
	if !strings.Contains(got, "example.com") {
		t.Error("should contain query even with empty Raw")
	}
}
