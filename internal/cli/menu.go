package cli

// Menu implements MenuInterface for handling the main application flow
type Menu struct {
	display DisplayHandler
	input   UserInputHandler
	factory ProcessorFactory
}

// NewMenu creates a new menu instance
func NewMenu(display DisplayHandler, input UserInputHandler, factory ProcessorFactory) *Menu {
	return &Menu{
		display: display,
		input:   input,
		factory: factory,
	}
}

// Run executes the main menu loop
func (m *Menu) Run() error {
	m.display.ShowWelcome()

	for {
		m.display.ShowMenu()

		choice, err := m.input.GetChoice()
		if err != nil {
			m.display.ShowError(err)
			continue
		}

		if choice == 5 {
			m.display.ShowGoodbye()
			return nil
		}

		if err := m.processChoice(choice); err != nil {
			m.display.ShowError(err)
		}
	}
}

// processChoice handles the user's menu choice
func (m *Menu) processChoice(choice int) error {
	processor, err := m.factory.CreateProcessor(choice)
	if err != nil {
		return err
	}

	// Show prompt for user input
	m.display.ShowMessage("")

	// Get text input from user
	text, err := m.input.GetText()
	if err != nil {
		return err
	}

	// Show the message being processed
	m.display.ShowProcessingMessage(text)

	result, steps, err := processor.Process(text)
	if err != nil {
		return err
	}

	m.display.ShowResult(result, steps)
	return nil
}
