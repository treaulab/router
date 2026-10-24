package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

type tuiOption struct {
	code  string
	label string
}

type switchResultMsg struct {
	err error
}

// quitRequestMsg asks the interface to quit. Signals are routed through the
// model so an in-flight country switch can finish before sing-box is stopped.
type quitRequestMsg struct{}

type tuiModel struct {
	app     *app
	options []tuiOption
	// status and current are snapshots of app state. Switch commands run in a
	// Bubble Tea goroutine, so View must not read app fields directly.
	status      []string
	current     string
	cursor      int
	offset      int
	width       int
	height      int
	switching   bool
	quitPending bool
	message     string
	err         string
	switchWG    sync.WaitGroup
}

func newTUIModel(a *app) *tuiModel {
	model := &tuiModel{
		app:     a,
		options: a.tuiOptions(),
		status:  a.statusLines(),
		current: a.country,
		width:   80,
		height:  24,
	}
	model.cursor = model.cursorFor(model.current)
	model.ensureCursorVisible()
	return model
}

func (a *app) tuiOptions() []tuiOption {
	if a.opts.backend == backendProton {
		choices := protonTUIChoices(a.protonServers)
		options := make([]tuiOption, 0, len(choices))
		for _, choice := range choices {
			options = append(options, tuiOption{code: choice.Code, label: choice.Label})
		}
		return options
	}

	options := []tuiOption{{code: "any", label: countryLabel(a.opts.backend, "any", nil)}}
	for _, code := range countryCodes(a.opts.backend) {
		options = append(options, tuiOption{code: code, label: countryName(code)})
	}
	options = append(options, tuiOption{code: "random", label: "Random country"})
	options = append(options, tuiOption{code: "quit", label: "Quit"})
	return options
}

func (m *tuiModel) Init() tea.Cmd {
	return nil
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch message := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		m.ensureCursorVisible()
		return m, nil
	case switchResultMsg:
		m.switching = false
		m.current = m.app.country
		m.status = m.app.statusLines()
		if message.err != nil {
			m.err = message.err.Error()
			m.message = ""
		} else {
			m.err = ""
			m.message = "Switched to " + m.app.choiceLabel(m.current)
			m.cursor = m.cursorFor(m.current)
			m.ensureCursorVisible()
		}
		if m.quitPending {
			return m, tea.Quit
		}
		return m, nil
	case quitRequestMsg:
		return m.requestQuit()
	case tea.KeyMsg:
		switch message.String() {
		case "q", "ctrl+c":
			return m.requestQuit()
		}
		if m.switching {
			return m, nil
		}
		switch message.String() {
		case "up", "k":
			m.cursor = (m.cursor - 1 + len(m.options)) % len(m.options)
			m.ensureCursorVisible()
			return m, nil
		case "down", "j":
			m.cursor = (m.cursor + 1) % len(m.options)
			m.ensureCursorVisible()
			return m, nil
		case "home", "g":
			m.cursor = 0
			m.offset = 0
			return m, nil
		case "end", "G":
			m.cursor = len(m.options) - 1
			m.ensureCursorVisible()
			return m, nil
		case "r":
			return m, m.activate()
		case "enter":
			return m, m.activate()
		}
	}
	return m, nil
}

func (m *tuiModel) requestQuit() (tea.Model, tea.Cmd) {
	if m.switching {
		m.quitPending = true
		m.message = "Quitting after the current switch completes..."
		return m, nil
	}
	return m, tea.Quit
}

func (a *app) choiceLabel(code string) string {
	if code == "random" {
		if a.opts.backend == backendProton {
			return "a random city"
		}
		return "a random country"
	}
	return a.countryLabel(code)
}

func (m *tuiModel) activate() tea.Cmd {
	option := m.options[m.cursor]
	switch option.code {
	case "quit":
		return tea.Quit
	case "random":
		return m.switchTo("random")
	}
	if option.code == m.current {
		m.message = "Already using " + m.app.choiceLabel(m.current)
		return nil
	}
	return m.switchTo(option.code)
}

func (m *tuiModel) switchTo(code string) tea.Cmd {
	m.switching = true
	m.err = ""
	m.message = "Switching to " + m.app.choiceLabel(code) + "..."
	app := m.app
	m.switchWG.Add(1)
	return func() tea.Msg {
		defer m.switchWG.Done()
		return switchResultMsg{err: app.switchCountry(code)}
	}
}

func (m *tuiModel) cursorFor(code string) int {
	for i, option := range m.options {
		if option.code == code {
			return i
		}
	}
	return 0
}

func (m *tuiModel) maxVisible() int {
	max := m.height - len(m.status) - 9
	if max < 3 {
		max = 3
	}
	return max
}

func (m *tuiModel) ensureCursorVisible() {
	maxVisible := m.maxVisible()
	if maxVisible > len(m.options) {
		maxVisible = len(m.options)
	}
	maxOffset := len(m.options) - maxVisible
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+m.maxVisible() {
		m.offset = m.cursor - m.maxVisible() + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
	if m.offset > maxOffset {
		m.offset = maxOffset
	}
}

func (m *tuiModel) visibleRange() (int, int) {
	start := m.offset
	end := start + m.maxVisible()
	if end > len(m.options) {
		end = len(m.options)
	}
	if start < 0 {
		start = 0
	}
	if end > len(m.options) {
		end = len(m.options)
	}
	return start, end
}

func (a *app) title() string {
	switch a.opts.backend {
	case backendWarp:
		return "WARP Router"
	case backendProton:
		return "Proton VPN Router"
	default:
		return "Tor Router"
	}
}

func (m *tuiModel) View() string {
	var b strings.Builder
	b.WriteString("  " + m.app.title() + "\n\n")
	for _, line := range m.status {
		b.WriteString("  " + line + "\n")
	}
	heading := "Select exit country"
	if m.app.opts.backend == backendProton {
		heading = "Select exit country or city"
	}
	b.WriteString("\n  " + heading + "\n")
	start, end := m.visibleRange()
	for i := start; i < end; i++ {
		option := m.options[i]
		line := "  " + option.code + "  " + option.label
		if i == m.cursor {
			line = "> " + option.code + "  " + option.label
		}
		if option.code == m.current {
			line += "  (current)"
		}
		b.WriteString(line + "\n")
	}
	if end < len(m.options) || start > 0 {
		b.WriteString(fmt.Sprintf("  ... %d-%d of %d\n", start, end-1, len(m.options)))
	}
	b.WriteString("\n")
	if m.switching {
		b.WriteString("  " + m.message + "\n")
	} else if m.err != "" {
		b.WriteString("  " + m.err + "\n")
	} else if m.message != "" {
		b.WriteString("  " + m.message + "\n")
	}
	b.WriteString("\n  up/down or j/k move | enter select | r random | q quit\n")
	if m.app.opts.backend == backendWarp {
		b.WriteString("  de/fi/nl unavailable on WARP; use -b tor\n")
	}
	if m.app.opts.backend == backendProton {
		b.WriteString("  free Proton WireGuard servers only\n")
	}
	return b.String()
}

// Run starts the Bubble Tea program and blocks until the user quits.
func (a *app) interactive(sigCh <-chan os.Signal) error {
	oldStdout, oldStderr := stdout, stderr
	stdout, stderr = io.Discard, io.Discard
	defer func() {
		stdout, stderr = oldStdout, oldStderr
	}()

	model := newTUIModel(a)
	// The app owns signal handling so a switch already in progress can finish
	// before the interface exits.
	program := tea.NewProgram(model, tea.WithAltScreen(), tea.WithoutSignalHandler())
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigCh:
			program.Send(quitRequestMsg{})
		case <-done:
		}
	}()
	_, err := program.Run()
	// If the terminal closed during a switch, let the switch finish before the
	// caller restores output and stops the engine.
	model.switchWG.Wait()
	return err
}
