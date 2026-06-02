package setup

import (
	"strings"
	"testing"

	"github.com/casapps/caswhois/src/client/config"
	tea "github.com/charmbracelet/bubbletea"
)

func newTestCfg() *config.CLIConfig {
	return &config.CLIConfig{Format: "text"}
}

func TestNew_InitialState(t *testing.T) {
	cfg := newTestCfg()
	m := New(cfg)
	if m.step != stepURL {
		t.Errorf("initial step = %d, want stepURL (%d)", m.step, stepURL)
	}
	if m.cfg != cfg {
		t.Error("cfg should be the same pointer")
	}
	if m.testErr != nil {
		t.Error("testErr should be nil initially")
	}
}

func TestNew_WithExistingServer(t *testing.T) {
	cfg := &config.CLIConfig{Server: "http://example.com:64000"}
	m := New(cfg)
	if m.urlIn.Value() != "http://example.com:64000" {
		t.Errorf("urlIn.Value() = %q, want %q", m.urlIn.Value(), "http://example.com:64000")
	}
}

func TestInit_ReturnsBlink(t *testing.T) {
	m := New(newTestCfg())
	cmd := m.Init()
	if cmd == nil {
		t.Error("Init should return a non-nil Cmd")
	}
}

func TestView_StepURL(t *testing.T) {
	m := New(newTestCfg())
	v := m.View()
	if !strings.Contains(v, "caswhois-cli setup") {
		t.Error("View should contain title")
	}
	if !strings.Contains(v, "Step 1/2") {
		t.Error("View should show Step 1/2")
	}
}

func TestView_StepURL_WithError(t *testing.T) {
	m := New(newTestCfg())
	m.testErr = &testError{"connection refused"}
	v := m.View()
	if !strings.Contains(v, "connection refused") {
		t.Error("View should display connection error")
	}
}

func TestView_StepTest(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepTest
	m.cfg.Server = "http://localhost:64580"
	v := m.View()
	if !strings.Contains(v, "localhost") {
		t.Error("View should show server URL while testing")
	}
}

func TestView_StepToken(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepToken
	v := m.View()
	if !strings.Contains(v, "Step 2/2") {
		t.Error("View should show Step 2/2")
	}
	if !strings.Contains(v, "Connected successfully") {
		t.Error("View should show success message")
	}
}

func TestView_StepDone(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepDone
	v := m.View()
	if !strings.Contains(v, "Configuration saved") {
		t.Error("View should show saved message")
	}
}

func TestUpdate_CtrlC_Quits(t *testing.T) {
	m := New(newTestCfg())
	msg := tea.KeyMsg{Type: tea.KeyCtrlC}
	_, cmd := m.Update(msg)
	if cmd == nil {
		t.Error("CtrlC should return a cmd")
	}
}

func TestUpdate_Enter_EmptyURL_NoOp(t *testing.T) {
	m := New(newTestCfg())
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	result, cmd := m.Update(msg)
	updated := result.(Model)
	if updated.step != stepURL {
		t.Error("empty URL enter should stay on stepURL")
	}
	if cmd != nil {
		t.Error("empty URL enter should return nil cmd")
	}
}

func TestUpdate_Enter_WithURL_AdvancesToTest(t *testing.T) {
	m := New(newTestCfg())
	m.urlIn.SetValue("http://localhost:64580")
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	result, cmd := m.Update(msg)
	updated := result.(Model)
	if updated.step != stepTest {
		t.Errorf("step = %d, want stepTest (%d)", updated.step, stepTest)
	}
	if cmd == nil {
		t.Error("should return a connection test cmd")
	}
}

func TestUpdate_Enter_TokenStep_AdvancesToDone(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepToken
	m.tokenIn.SetValue("tok_abc123")
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	result, cmd := m.Update(msg)
	updated := result.(Model)
	if updated.step != stepDone {
		t.Errorf("step = %d, want stepDone (%d)", updated.step, stepDone)
	}
	if updated.cfg.Token != "tok_abc123" {
		t.Errorf("Token = %q, want %q", updated.cfg.Token, "tok_abc123")
	}
	if cmd == nil {
		t.Error("done step should return quit cmd")
	}
}

func TestUpdate_TestDoneMsg_Success(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepTest
	msg := testDoneMsg{err: nil}
	result, _ := m.Update(msg)
	updated := result.(Model)
	if updated.step != stepToken {
		t.Errorf("step = %d, want stepToken (%d)", updated.step, stepToken)
	}
}

func TestUpdate_TestDoneMsg_Failure(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepTest
	msg := testDoneMsg{err: &testError{"connection refused"}}
	result, _ := m.Update(msg)
	updated := result.(Model)
	if updated.step != stepURL {
		t.Errorf("step = %d, want stepURL (%d) on failure", updated.step, stepURL)
	}
	if updated.testErr == nil {
		t.Error("testErr should be set on failure")
	}
}

func TestStepConstants(t *testing.T) {
	if stepURL != 0 {
		t.Errorf("stepURL = %d, want 0", stepURL)
	}
	if stepTest != 1 {
		t.Errorf("stepTest = %d, want 1", stepTest)
	}
	if stepToken != 2 {
		t.Errorf("stepToken = %d, want 2", stepToken)
	}
	if stepDone != 3 {
		t.Errorf("stepDone = %d, want 3", stepDone)
	}
}

// testError is a simple error implementation for tests.
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
