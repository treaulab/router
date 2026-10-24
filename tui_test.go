package main

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func testTUIApp(backend, country string, servers ...protonServer) *app {
	return &app{
		opts:          options{backend: backend, country: country, listenPort: defaultListenPort},
		country:       country,
		protonServers: servers,
	}
}

func testKey(key tea.KeyType) tea.KeyMsg {
	return tea.KeyMsg{Type: key}
}

func testRuneKey(value string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)}
}

func updateTUI(t *testing.T, model *tuiModel, msg tea.Msg) tea.Cmd {
	t.Helper()
	updated, cmd := model.Update(msg)
	if updated != model {
		t.Fatal("Update returned a different model")
	}
	return cmd
}

func TestTUIOptionsWarp(t *testing.T) {
	options := testTUIApp(backendWarp, "us").tuiOptions()
	want := []string{"any", "us", "random", "quit"}
	if len(options) != len(want) {
		t.Fatalf("options = %+v, want %d entries", options, len(want))
	}
	for i, code := range want {
		if options[i].code != code {
			t.Fatalf("options[%d].code = %q, want %q", i, options[i].code, code)
		}
	}
	if options[0].label != "Automatic (Cloudflare edge)" {
		t.Fatalf("any label = %q", options[0].label)
	}
}

func TestTUIOptionsTor(t *testing.T) {
	options := testTUIApp(backendTor, "jp").tuiOptions()
	if len(options) != len(commonCountries)+3 {
		t.Fatalf("options = %d, want %d", len(options), len(commonCountries)+3)
	}
	if options[0].code != "any" {
		t.Fatalf("first option = %q, want any", options[0].code)
	}
	if options[len(options)-2].code != "random" || options[len(options)-1].code != "quit" {
		t.Fatalf("trailing options = %+v", options[len(options)-2:])
	}
	for i, code := range countryCodes(backendTor) {
		if options[i+1].code != code {
			t.Fatalf("options[%d].code = %q, want %q", i+1, options[i+1].code, code)
		}
	}
}

func TestTUIOptionsProton(t *testing.T) {
	app := testTUIApp(backendProton, "us/san-jose", testProtonServers(t)...)
	options := app.tuiOptions()
	if options[0].code != "any" || options[0].label != "Any free server (random)" {
		t.Fatalf("first option = %+v", options[0])
	}
	want := []string{
		"any",
		"ca", "ca/montreal",
		"sg", "sg/singapore",
		"us", "us/miami", "us/san-jose",
		"random", "quit",
	}
	if len(options) != len(want) {
		t.Fatalf("options = %+v, want %v", options, want)
	}
	for i, code := range want {
		if options[i].code != code {
			t.Fatalf("options[%d].code = %q, want %q", i, options[i].code, code)
		}
	}
	if options[len(options)-2].label != "Random city" {
		t.Fatalf("random label = %q", options[len(options)-2].label)
	}
}

func TestNewTUICursorMatchesCountry(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "us"))
	if model.cursor != 1 {
		t.Fatalf("cursor = %d, want 1 for US", model.cursor)
	}

	model = newTUIModel(testTUIApp(backendWarp, "any"))
	if model.cursor != 0 {
		t.Fatalf("cursor = %d, want 0 for any", model.cursor)
	}

	model = newTUIModel(testTUIApp(backendTor, "jp"))
	want := 0
	for i, code := range countryCodes(backendTor) {
		if code == "jp" {
			want = i + 1
		}
	}
	if model.cursor != want {
		t.Fatalf("cursor = %d, want %d for jp", model.cursor, want)
	}

	model = newTUIModel(testTUIApp(backendProton, "us/san-jose", testProtonServers(t)...))
	want = 0
	for i, option := range model.options {
		if option.code == "us/san-jose" {
			want = i
		}
	}
	if model.cursor != want {
		t.Fatalf("cursor = %d, want %d for Proton us/san-jose", model.cursor, want)
	}
}

func TestTUIKeyboardNavigation(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "us"))
	if model.cursor != 1 {
		t.Fatalf("initial cursor = %d, want 1", model.cursor)
	}

	updateTUI(t, model, testKey(tea.KeyDown))
	if model.cursor != 2 {
		t.Fatalf("cursor after down = %d, want 2", model.cursor)
	}
	updateTUI(t, model, testRuneKey("j"))
	if model.cursor != 3 {
		t.Fatalf("cursor after j = %d, want 3", model.cursor)
	}
	updateTUI(t, model, testKey(tea.KeyDown))
	if model.cursor != 0 {
		t.Fatalf("cursor after wrapping down = %d, want 0", model.cursor)
	}
	updateTUI(t, model, testKey(tea.KeyUp))
	if model.cursor != len(model.options)-1 {
		t.Fatalf("cursor after wrapping up = %d, want %d", model.cursor, len(model.options)-1)
	}
	updateTUI(t, model, testRuneKey("k"))
	if model.cursor != len(model.options)-2 {
		t.Fatalf("cursor after k = %d, want %d", model.cursor, len(model.options)-2)
	}
}

func TestTUIActivateCurrentCountry(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "us"))
	cmd := updateTUI(t, model, testKey(tea.KeyEnter))
	if cmd != nil {
		t.Fatal("activating the current country returned a command")
	}
	if model.switching {
		t.Fatal("activating the current country started a switch")
	}
	if !strings.Contains(model.message, "Already using") {
		t.Fatalf("message = %q", model.message)
	}
}

func TestTUIActivateStartsSwitch(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "any"))
	updateTUI(t, model, testKey(tea.KeyDown))
	cmd := updateTUI(t, model, testKey(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("activating a new country returned no command")
	}
	if !model.switching {
		t.Fatal("activating a new country did not mark the model as switching")
	}
	if !strings.Contains(model.message, "Switching to United States") {
		t.Fatalf("message = %q", model.message)
	}
}

func TestTUISwitchResult(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "us"))
	model.switching = true
	updateTUI(t, model, switchResultMsg{err: errors.New("switch failed")})
	if model.switching {
		t.Fatal("switch error left model switching")
	}
	if model.err != "switch failed" {
		t.Fatalf("err = %q", model.err)
	}
	if model.message != "" {
		t.Fatalf("message = %q, want empty after error", model.message)
	}

	model = newTUIModel(testTUIApp(backendWarp, "any"))
	model.switching = true
	model.app.country = "us"
	updateTUI(t, model, switchResultMsg{})
	if model.switching || model.err != "" {
		t.Fatalf("unexpected state after success: %+v", model)
	}
	if !strings.Contains(model.message, "Switched to United States") {
		t.Fatalf("message = %q", model.message)
	}
	if model.cursor != 1 {
		t.Fatalf("cursor = %d, want 1 after switching to US", model.cursor)
	}
}

func TestTUIQuit(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "us"))
	cmd := updateTUI(t, model, testRuneKey("q"))
	if cmd == nil {
		t.Fatal("q returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("q returned %T, want tea.QuitMsg", cmd())
	}

	cmd = updateTUI(t, model, testKey(tea.KeyCtrlC))
	if cmd == nil {
		t.Fatal("ctrl+c returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("ctrl+c returned %T, want tea.QuitMsg", cmd())
	}
}

func TestTUIQuitDuringSwitch(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "any"))
	updateTUI(t, model, testKey(tea.KeyDown))
	updateTUI(t, model, testKey(tea.KeyEnter))
	if !model.switching {
		t.Fatal("expected a switch in progress")
	}

	cmd := updateTUI(t, model, testRuneKey("q"))
	if cmd != nil {
		t.Fatal("q during a switch should wait for the switch to finish")
	}
	if !model.quitPending {
		t.Fatal("q during a switch did not set quitPending")
	}
	if !strings.Contains(model.message, "Quitting after the current switch") {
		t.Fatalf("message = %q", model.message)
	}

	cmd = updateTUI(t, model, switchResultMsg{})
	if cmd == nil {
		t.Fatal("switch completion did not quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("switch completion returned %T, want tea.QuitMsg", cmd())
	}
}

func TestTUISignalQuitDuringSwitch(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "us"))
	model.switching = true
	cmd := updateTUI(t, model, quitRequestMsg{})
	if cmd != nil {
		t.Fatal("signal during a switch should wait for the switch to finish")
	}
	if !model.quitPending {
		t.Fatal("signal during a switch did not set quitPending")
	}
}

func TestTUIEnsureCursorVisible(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "any"))
	model.height = 12
	model.cursor = len(model.options) - 1
	model.ensureCursorVisible()
	start, end := model.visibleRange()
	if model.cursor < start || model.cursor >= end {
		t.Fatalf("cursor %d outside visible range %d-%d", model.cursor, start, end)
	}
	if model.offset == 0 {
		t.Fatal("offset = 0, want the list scrolled to the cursor")
	}
}

func TestTUIView(t *testing.T) {
	model := newTUIModel(testTUIApp(backendWarp, "us"))
	view := model.View()
	for _, want := range []string{
		"WARP Router",
		"United States (us)",
		"(current)",
		"up/down or j/k move",
		"de/fi/nl unavailable on WARP",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("view does not contain %q:\n%s", want, view)
		}
	}

	torView := newTUIModel(testTUIApp(backendTor, "jp")).View()
	if strings.Contains(torView, "de/fi/nl unavailable") {
		t.Error("Tor view contains the WARP-only warning")
	}

	protonView := newTUIModel(testTUIApp(backendProton, "us/san-jose", testProtonServers(t)...)).View()
	for _, want := range []string{
		"Proton VPN Router",
		"Select exit country or city",
		"us/san-jose",
		"free Proton WireGuard servers only",
	} {
		if !strings.Contains(protonView, want) {
			t.Errorf("Proton view does not contain %q:\n%s", want, protonView)
		}
	}

	protonWarpView := newTUIModel(testTUIApp(backendProtonWarp, "us/san-jose", testProtonServers(t)...)).View()
	for _, want := range []string{
		"Proton -> WARP Router",
		"Select exit country or city",
		"us/san-jose",
		"free Proton WireGuard servers only",
		"Proton outer -> Cloudflare WARP inner",
	} {
		if !strings.Contains(protonWarpView, want) {
			t.Errorf("Proton-WARP view does not contain %q:\n%s", want, protonWarpView)
		}
	}
}
