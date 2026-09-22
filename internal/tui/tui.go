package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/benchmark"
	"github.com/abdorrahmani/cryptolens/internal/cli"
	"github.com/abdorrahmani/cryptolens/internal/config"
	"github.com/abdorrahmani/cryptolens/internal/crypto"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const version = "1.4.0"

// cryptoLensBanner is the ASCII logo shown on the main menu.
const cryptoLensBanner = `
  ..____                  _        _
 / ___|_ __ _   _ _ __ | |_ ___ | |    ___ _ __  ___
| |   | '__| | | | '_ \| __/ _ \| |   / _ | '_ \/ __|
| |___| |  | |_| | |_) | || (_) | |__|  __| | | \__ \
 \____|_|   \__, | .__/ \__\___/|_____\___|_| |_|___/
            |___/|_|
`

// attackMenuID is the sentinel main-menu id that opens the attack submenu.
const attackMenuID = 100

type screen int

const (
	screenMenu screen = iota
	screenAttackMenu
	screenOperation
	screenHashSelect
	screenPBKDFSelect
	screenJWTSelect
	screenJWTSecret
	screenBenchText
	screenBenchIter
	screenTextInput
	screenConfirmRun
	screenRunning
	screenResult
)

// menuItem is one selectable row. id meaning depends on the menu it belongs to.
type menuItem struct {
	title  string
	desc   string
	id     int
	danger bool
}

// menu is a minimal single-select list with keyboard navigation.
type menu struct {
	title  string
	items  []menuItem
	cursor int
}

func (mn *menu) up() {
	if mn.cursor > 0 {
		mn.cursor--
	}
}

func (mn *menu) down() {
	if mn.cursor < len(mn.items)-1 {
		mn.cursor++
	}
}

func (mn *menu) selected() menuItem { return mn.items[mn.cursor] }

func (mn *menu) view() string {
	var b strings.Builder
	if mn.title != "" {
		b.WriteString(titleStyle.Render(mn.title))
		b.WriteString("\n\n")
	}
	for i, it := range mn.items {
		line := fmt.Sprintf("%d. %s", it.id, it.title)
		if it.id >= attackMenuID {
			line = it.title
		}
		switch {
		case i == mn.cursor:
			b.WriteString(selectedItemStyle.Render("▸ " + line))
		case it.danger:
			b.WriteString(dangerItemStyle.Render(line))
		default:
			b.WriteString(itemStyle.Render(line))
		}
		if it.desc != "" {
			b.WriteString("  " + itemDescStyle.Render(it.desc))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// resultMsg carries the outcome of a processor or benchmark run.
type resultMsg struct {
	title  string
	result string
	steps  []string
	err    error
}

type model struct {
	factory *cli.CryptoProcessorFactory

	screen screen
	menu   menu

	input    textinput.Model
	viewport viewport.Model
	spinner  spinner.Model

	width  int
	height int

	// selections accumulated across the flow
	algoChoice int
	isAttack   bool
	operation  string
	hashAlgo   string
	pbkdfAlgo  string
	jwtAlgo    string
	jwtSecret  string
	benchKind  string
	benchText  string
	text       string

	resultTitle string
	err         error
}

func newModel(factory *cli.CryptoProcessorFactory) model {
	ti := textinput.New()
	ti.CharLimit = 4096

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(colTitle)

	m := model{
		factory:  factory,
		screen:   screenMenu,
		input:    ti,
		viewport: viewport.New(80, 20),
		spinner:  sp,
	}
	m.menu = mainMenu()
	return m
}

func (m model) Init() tea.Cmd { return textinput.Blink }

// --- menu builders ---------------------------------------------------------

func mainMenu() menu {
	return menu{
		title: "Select an operation",
		items: []menuItem{
			{id: 1, title: "Base64 Encoding/Decoding"},
			{id: 2, title: "Caesar Cipher"},
			{id: 3, title: "AES Encryption/Decryption"},
			{id: 4, title: "SHA-256 Hashing"},
			{id: 5, title: "RSA Encryption/Decryption"},
			{id: 6, title: "HMAC (Hash-based Message Authentication)"},
			{id: 7, title: "PBKDF (Password-Based Key Derivation)"},
			{id: 8, title: "Diffie-Hellman Key Exchange"},
			{id: 9, title: "X25519 Key Exchange"},
			{id: 10, title: "JWT (JSON Web Token)"},
			{id: 11, title: "ChaCha20-Poly1305 Encryption"},
			{id: 12, title: "ML-KEM (Post-Quantum Key Encapsulation)"},
			{id: 13, title: "ML-DSA (Post-Quantum Signatures)"},
			{id: attackMenuID, title: "Attack Simulations", danger: true},
		},
	}
}

func attackMenu() menu {
	return menu{
		title: "🎯 Attack Simulations",
		items: []menuItem{
			{id: 1, title: "ECB Mode Vulnerability"},
			{id: 2, title: "Nonce Reuse in AEAD (ChaCha20-Poly1305)"},
			{id: 3, title: "Timing Attack (HMAC verification)"},
			{id: 4, title: "Brute Force on Weak Keys or Passwords"},
			{id: 5, title: "JWT None Algorithm Attack"},
		},
	}
}

func operationMenu() menu {
	return menu{
		title: "Choose operation",
		items: []menuItem{
			{id: 1, title: "Encrypt"},
			{id: 2, title: "Decrypt"},
		},
	}
}

func hashMenu() menu {
	return menu{
		title: "Select hash algorithm",
		items: []menuItem{
			{id: 1, title: "SHA-1", desc: "legacy"},
			{id: 2, title: "SHA-256"},
			{id: 3, title: "SHA-512"},
			{id: 4, title: "BLAKE2b-256"},
			{id: 5, title: "BLAKE2b-512"},
			{id: 6, title: "BLAKE3"},
			{id: 7, title: "Run Benchmark", danger: true},
		},
	}
}

func pbkdfMenu() menu {
	return menu{
		title: "Select PBKDF algorithm",
		items: []menuItem{
			{id: 1, title: "PBKDF2"},
			{id: 2, title: "Argon2id", desc: "memory-hard"},
			{id: 3, title: "Scrypt", desc: "memory-hard"},
			{id: 4, title: "Run Benchmark on All", danger: true},
		},
	}
}

func jwtMenu() menu {
	return menu{
		title: "Select JWT algorithm",
		items: []menuItem{
			{id: 1, title: "HS256", desc: "HMAC with SHA-256"},
			{id: 2, title: "RS256", desc: "RSA with SHA-256"},
			{id: 3, title: "EdDSA", desc: "Ed25519"},
		},
	}
}

// --- update ----------------------------------------------------------------

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeViewport()
		return m, nil

	case resultMsg:
		m.err = msg.err
		m.resultTitle = msg.title
		if msg.err == nil {
			m.setResultContent(msg.result, msg.steps)
		}
		m.screen = screenResult
		return m, nil

	case spinner.TickMsg:
		if m.screen == screenRunning {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
		return m.handleKey(msg)
	}

	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenMenu:
		return m.handleMenuKey(msg)
	case screenAttackMenu, screenOperation, screenHashSelect, screenPBKDFSelect, screenJWTSelect:
		return m.handleSelectKey(msg)
	case screenTextInput, screenJWTSecret, screenBenchText, screenBenchIter:
		return m.handleInputKey(msg)
	case screenConfirmRun:
		return m.handleConfirmKey(msg)
	case screenResult:
		return m.handleResultKey(msg)
	}
	return m, nil
}

func (m model) handleMenuKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		m.menu.up()
	case "down", "j":
		m.menu.down()
	case "enter":
		sel := m.menu.selected()
		if sel.id == attackMenuID {
			m.screen = screenAttackMenu
			m.menu = attackMenu()
			return m, nil
		}
		return m.selectAlgorithm(sel.id)
	}
	return m, nil
}

func (m model) handleSelectKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m.backToMenu(), nil
	case "up", "k":
		m.menu.up()
	case "down", "j":
		m.menu.down()
	case "enter":
		return m.applySelection(m.menu.selected())
	}
	return m, nil
}

func (m model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m.backToMenu(), nil
	case "enter":
		return m.submitInput()
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m.backToMenu(), nil
	case "enter":
		m.text = ""
		m.operation = crypto.OperationEncrypt
		return m.startRun()
	}
	return m, nil
}

func (m model) handleResultKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "enter":
		return m.backToMenu(), nil
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

// --- flow helpers ----------------------------------------------------------

func (m *model) resetSelections() {
	m.algoChoice = 0
	m.isAttack = false
	m.operation = crypto.OperationEncrypt
	m.hashAlgo = ""
	m.pbkdfAlgo = ""
	m.jwtAlgo = ""
	m.jwtSecret = ""
	m.benchKind = ""
	m.benchText = ""
	m.text = ""
	m.err = nil
}

func (m model) backToMenu() model {
	m.resetSelections()
	m.screen = screenMenu
	m.menu = mainMenu()
	return m
}

// needsOperation reports whether an algorithm asks for encrypt/decrypt, matching
// the original CLI (SHA-256, HMAC, PBKDF, DH and X25519 are one-way/demo flows).
func needsOperation(choice int) bool {
	switch choice {
	case 1, 2, 3, 5, 10, 11:
		return true
	default:
		return false
	}
}

func (m model) selectAlgorithm(choice int) (tea.Model, tea.Cmd) {
	m.resetSelections()
	m.algoChoice = choice
	m.resultTitle = algoTitle(choice)
	if needsOperation(choice) {
		m.screen = screenOperation
		m.menu = operationMenu()
		return m, nil
	}
	return m.postOperation()
}

// postOperation routes to the next screen once the operation (if any) is chosen.
func (m model) postOperation() (tea.Model, tea.Cmd) {
	switch m.algoChoice {
	case 6: // HMAC
		m.screen = screenHashSelect
		m.menu = hashMenu()
	case 7: // PBKDF
		m.screen = screenPBKDFSelect
		m.menu = pbkdfMenu()
	case 10: // JWT
		m.screen = screenJWTSelect
		m.menu = jwtMenu()
	case 8, 9, 12: // DH / X25519 / ML-KEM key-agreement demonstrations
		m.screen = screenConfirmRun
	case 13: // ML-DSA signs a message
		m.focusInput("Enter a message to sign", "", "")
		m.screen = screenTextInput
	default: // Base64, Caesar, AES, SHA-256, RSA, ChaCha20
		m.focusInput("Enter text to process", "", "")
		m.screen = screenTextInput
	}
	return m, nil
}

// applySelection handles a menu choice on the operation / hash / pbkdf / jwt /
// attack submenus.
func (m model) applySelection(sel menuItem) (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenAttackMenu:
		m.isAttack = true
		m.algoChoice = sel.id
		m.resultTitle = "Attack: " + sel.title
		m.focusInput("Enter text to demonstrate the attack", "", "")
		m.screen = screenTextInput
		return m, nil

	case screenOperation:
		if sel.id == 2 {
			m.operation = crypto.OperationDecrypt
		} else {
			m.operation = crypto.OperationEncrypt
		}
		return m.postOperation()

	case screenHashSelect:
		if sel.id == 7 { // benchmark
			m.benchKind = "hmac"
			m.resultTitle = "HMAC Benchmark"
			m.focusInput("Sample text", "Hello, World!", "")
			m.screen = screenBenchText
			return m, nil
		}
		m.hashAlgo = []string{"", "sha1", "sha256", "sha512", "blake2b-256", "blake2b-512", "blake3"}[sel.id]
		m.focusInput("Enter text to process", "", "")
		m.screen = screenTextInput
		return m, nil

	case screenPBKDFSelect:
		if sel.id == 4 { // benchmark
			m.benchKind = "pbkdf"
			m.resultTitle = "PBKDF Benchmark"
			m.focusInput("Sample text", "Hello", "")
			m.screen = screenBenchText
			return m, nil
		}
		m.pbkdfAlgo = []string{"", "pbkdf2", "argon2id", "scrypt"}[sel.id]
		m.focusInput("Enter text to process", "", "")
		m.screen = screenTextInput
		return m, nil

	case screenJWTSelect:
		m.jwtAlgo = []string{"", "HS256", "RS256", "EdDSA"}[sel.id]
		if m.jwtAlgo == "HS256" {
			m.focusInput("Secret key", "my-secret-key", "")
			m.screen = screenJWTSecret
			return m, nil
		}
		m.focusInput("Enter text to process", "", "")
		m.screen = screenTextInput
		return m, nil
	}
	return m, nil
}

func (m model) submitInput() (tea.Model, tea.Cmd) {
	value := strings.TrimSpace(m.input.Value())

	switch m.screen {
	case screenJWTSecret:
		if value == "" {
			value = "my-secret-key"
		}
		m.jwtSecret = value
		m.focusInput("Enter text to process", "", "")
		m.screen = screenTextInput
		return m, nil

	case screenBenchText:
		m.benchText = value // empty => benchmark applies its default
		m.focusInput("Number of iterations", benchIterHint(m.benchKind), "")
		m.screen = screenBenchIter
		return m, nil

	case screenBenchIter:
		iters := 0
		if value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				m.input.SetValue("")
				m.err = fmt.Errorf("please enter a positive whole number")
				return m, nil
			}
			iters = n
		}
		m.err = nil
		return m.startBenchmark(iters)

	case screenTextInput:
		if value == "" {
			m.err = fmt.Errorf("text cannot be empty")
			return m, nil
		}
		m.err = nil
		m.text = value
		return m.startRun()
	}
	return m, nil
}

func (m model) startRun() (tea.Model, tea.Cmd) {
	m.screen = screenRunning
	return m, tea.Batch(m.spinner.Tick, m.runProcessorCmd())
}

func (m model) startBenchmark(iters int) (tea.Model, tea.Cmd) {
	kind := m.benchKind
	text := m.benchText
	title := m.resultTitle
	m.screen = screenRunning
	return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
		var r string
		var s []string
		var err error
		switch kind {
		case "hmac":
			r, s, err = benchmark.RunHMACBenchmark(text, iters)
		case "pbkdf":
			r, s, err = benchmark.RunPBKDFBenchmark(text, iters)
		}
		return resultMsg{title: title, result: r, steps: s, err: err}
	})
}

func (m model) runProcessorCmd() tea.Cmd {
	factory := m.factory
	choice := m.algoChoice
	isAttack := m.isAttack
	op := m.operation
	text := m.text
	hashAlgo := m.hashAlgo
	pbkdfAlgo := m.pbkdfAlgo
	jwtAlgo := m.jwtAlgo
	jwtSecret := m.jwtSecret
	title := m.resultTitle

	return func() tea.Msg {
		var proc crypto.Processor
		var err error
		if isAttack {
			proc, err = factory.CreateAttackProcessor(choice)
		} else {
			proc, err = factory.CreateProcessor(choice)
		}
		if err != nil {
			return resultMsg{title: title, err: err}
		}

		if cfg, ok := proc.(crypto.ConfigurableProcessor); ok && !isAttack {
			switch choice {
			case 6:
				if hashAlgo != "" {
					err = cfg.Configure(map[string]interface{}{"hashAlgorithm": hashAlgo})
				}
			case 7:
				if pbkdfAlgo != "" {
					err = cfg.Configure(map[string]interface{}{"algorithm": pbkdfAlgo})
				}
			case 10:
				if jwtAlgo != "" {
					err = cfg.Configure(map[string]interface{}{"algorithm": jwtAlgo})
					if err == nil && jwtAlgo == "HS256" && jwtSecret != "" {
						err = cfg.Configure(map[string]interface{}{"secretKey": jwtSecret})
					}
				}
			}
			if err != nil {
				return resultMsg{title: title, err: err}
			}
		}

		result, steps, err := proc.Process(text, op)
		return resultMsg{title: title, result: result, steps: steps, err: err}
	}
}

// --- view ------------------------------------------------------------------

func (m model) View() string {
	var body string
	switch m.screen {
	case screenMenu:
		body = m.bannerView() + m.menu.view() + "\n" + m.menuHelp()
	case screenAttackMenu, screenOperation, screenHashSelect, screenPBKDFSelect, screenJWTSelect:
		body = m.menu.view() + "\n" + m.menuHelp()
	case screenTextInput, screenJWTSecret, screenBenchText, screenBenchIter:
		body = m.inputView()
	case screenConfirmRun:
		body = m.confirmView()
	case screenRunning:
		body = fmt.Sprintf("%s %s", m.spinner.View(), promptStyle.Render("Working…"))
	case screenResult:
		body = m.resultView()
	}
	return "\n" + body + "\n"
}

// bannerView renders the ASCII logo and tagline, centered to the terminal
// width when known, followed by a blank line. It falls back to left alignment
// on terminals too narrow to hold the art without wrapping.
func (m model) bannerView() string {
	lines := strings.Split(strings.Trim(cryptoLensBanner, "\n"), "\n")

	maxLen := 0
	for _, ln := range lines {
		if w := lipgloss.Width(ln); w > maxLen {
			maxLen = w
		}
	}

	pad := 0
	if m.width > maxLen {
		pad = (m.width - maxLen) / 2
	}
	indent := strings.Repeat(" ", pad)

	var b strings.Builder
	for _, ln := range lines {
		b.WriteString(indent + bannerStyle.Render(ln) + "\n")
	}

	tagline := fmt.Sprintf("Interactive Cryptography Learning Tool · v%s", version)
	tagPad := 0
	if m.width > lipgloss.Width(tagline) {
		tagPad = (m.width - lipgloss.Width(tagline)) / 2
	}
	b.WriteString(strings.Repeat(" ", tagPad) + subtitleStyle.Render(tagline) + "\n\n")
	return b.String()
}

func (m model) menuHelp() string {
	if m.screen == screenMenu {
		return helpStyle.Render("↑/↓ move · enter select · q quit")
	}
	return helpStyle.Render("↑/↓ move · enter select · esc back")
}

func (m model) inputView() string {
	title := map[screen]string{
		screenTextInput: m.resultTitle,
		screenJWTSecret: "JWT — secret key",
		screenBenchText: m.resultTitle + " — sample text",
		screenBenchIter: m.resultTitle + " — iterations",
	}[m.screen]

	var b strings.Builder
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")
	b.WriteString(m.input.View())
	b.WriteString("\n")
	if m.err != nil {
		b.WriteString("\n" + errStyle.Render("⚠️  "+m.err.Error()) + "\n")
	}
	b.WriteString(helpStyle.Render("enter submit · esc back"))
	return b.String()
}

func (m model) confirmView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.resultTitle))
	b.WriteString("\n\n")
	b.WriteString(promptStyle.Render("Press enter to start the demonstration."))
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("enter run · esc back"))
	return b.String()
}

func (m model) resultView() string {
	var b strings.Builder
	b.WriteString(resultTitleStyle.Render("Result — " + m.resultTitle))
	b.WriteString("\n")
	if m.err != nil {
		b.WriteString("\n" + errStyle.Render("Error: "+m.err.Error()) + "\n\n")
		b.WriteString(helpStyle.Render("esc/enter back to menu"))
		return b.String()
	}
	b.WriteString(m.viewport.View())
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓ scroll · esc/enter back to menu"))
	return b.String()
}

// --- helpers ---------------------------------------------------------------

func (m *model) focusInput(prompt, placeholder, value string) {
	m.input.Prompt = promptStyle.Render(prompt+": ") + ""
	m.input.Placeholder = placeholder
	m.input.SetValue(value)
	m.input.CursorEnd()
	m.input.Focus()
	m.err = nil
}

func (m *model) resizeViewport() {
	w := m.width - 2
	if w < 20 {
		w = 20
	}
	h := m.height - 6
	if h < 3 {
		h = 3
	}
	m.viewport.Width = w
	m.viewport.Height = h
}

func (m *model) setResultContent(result string, steps []string) {
	var b strings.Builder
	if result != "" {
		b.WriteString(resultTitleStyle.Render(result))
		b.WriteString("\n\n")
	}
	b.WriteString(renderSteps(steps))
	m.resizeViewport()
	m.viewport.SetContent(b.String())
	m.viewport.GotoTop()
}

func algoTitle(choice int) string {
	titles := map[int]string{
		1: "Base64", 2: "Caesar Cipher", 3: "AES", 4: "SHA-256",
		5: "RSA", 6: "HMAC", 7: "PBKDF", 8: "Diffie-Hellman",
		9: "X25519", 10: "JWT", 11: "ChaCha20-Poly1305",
		12: "ML-KEM", 13: "ML-DSA",
	}
	if t, ok := titles[choice]; ok {
		return t
	}
	return "CryptoLens"
}

func benchIterHint(kind string) string {
	if kind == "pbkdf" {
		return "default 100 (10-100 recommended)"
	}
	return "default 10000"
}

// Run loads configuration, wires up the processor factory and starts the TUI.
func Run() error {
	cfg, err := config.LoadConfig("")
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	factory := cli.NewCryptoProcessorFactory()
	factory.SetConfig(cfg)

	p := tea.NewProgram(newModel(factory), tea.WithAltScreen())
	_, err = p.Run()
	return err
}
