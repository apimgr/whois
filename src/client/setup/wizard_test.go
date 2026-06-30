package setup

import (
	"strings"
	"testing"

	"github.com/apimgr/whois/src/client/config"
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
	updated := result.(WizardModel)
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
	updated := result.(WizardModel)
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
	updated := result.(WizardModel)
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
	updated := result.(WizardModel)
	if updated.step != stepToken {
		t.Errorf("step = %d, want stepToken (%d)", updated.step, stepToken)
	}
}

func TestUpdate_TestDoneMsg_Failure(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepTest
	msg := testDoneMsg{err: &testError{"connection refused"}}
	result, _ := m.Update(msg)
	updated := result.(WizardModel)
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

// TestUpdate_NonKeyNonDone_StepURL exercises the textinput update path on stepURL.
func TestUpdate_NonKeyNonDone_StepURL(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepURL
	type customMsg struct{}
	result, _ := m.Update(customMsg{})
	updated := result.(WizardModel)
	if updated.step != stepURL {
		t.Errorf("unhandled msg on stepURL should stay stepURL, got %d", updated.step)
	}
}

// TestUpdate_NonKeyNonDone_StepToken exercises the textinput update path on stepToken.
func TestUpdate_NonKeyNonDone_StepToken(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepToken
	type customMsg struct{}
	result, _ := m.Update(customMsg{})
	updated := result.(WizardModel)
	if updated.step != stepToken {
		t.Errorf("unhandled msg on stepToken should stay stepToken, got %d", updated.step)
	}
}

// TestUpdate_NonKeyNonDone_StepTest exercises no-op update on stepTest.
func TestUpdate_NonKeyNonDone_StepTest(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepTest
	m.cfg.Server = "http://localhost:64580"
	type customMsg struct{}
	result, _ := m.Update(customMsg{})
	updated := result.(WizardModel)
	if updated.step != stepTest {
		t.Errorf("unhandled msg on stepTest should stay stepTest, got %d", updated.step)
	}
}

// TestTestConnection_ReturnsCmd verifies testConnection returns a non-nil Cmd.
func TestTestConnection_ReturnsCmd(t *testing.T) {
	m := New(newTestCfg())
	cmd := m.testConnection("http://127.0.0.1:1")
	if cmd == nil {
		t.Error("testConnection should return a non-nil cmd")
	}
}

// TestTestConnection_CmdReturnsTestDoneMsg verifies the cmd returned by testConnection
// produces a testDoneMsg when executed (error path with unreachable server).
func TestTestConnection_CmdReturnsTestDoneMsg(t *testing.T) {
	m := New(newTestCfg())
	cmd := m.testConnection("http://127.0.0.1:1")
	msg := cmd()
	done, ok := msg.(testDoneMsg)
	if !ok {
		t.Fatalf("testConnection cmd returned %T, want testDoneMsg", msg)
	}
	if done.err == nil {
		t.Error("connecting to 127.0.0.1:1 should produce an error")
	}
}

// TestHandleEnter_StepDone_IsNoOp verifies handleEnter on stepDone is a no-op.
func TestHandleEnter_StepDone_IsNoOp(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepDone
	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated := result.(WizardModel)
	if updated.step != stepDone {
		t.Errorf("handleEnter on stepDone should stay stepDone, got %d", updated.step)
	}
	if cmd != nil {
		t.Error("handleEnter on stepDone should return nil cmd")
	}
}

// TestUpdate_Enter_TokenStep_BlankToken verifies a blank token is accepted (optional).
func TestUpdate_Enter_TokenStep_BlankToken(t *testing.T) {
	m := New(newTestCfg())
	m.step = stepToken
	m.tokenIn.SetValue("")
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	result, _ := m.Update(msg)
	updated := result.(WizardModel)
	if updated.step != stepDone {
		t.Errorf("blank token should still advance to stepDone, got %d", updated.step)
	}
	if updated.cfg.Token != "" {
		t.Errorf("blank token should store empty string, got %q", updated.cfg.Token)
	}
}

// testError is a simple error implementation for tests.
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
