package cli

import "github.com/abdorrahmani/cryptolens/internal/crypto"

// ProcessorFactory defines the contract for creating crypto processors.
type ProcessorFactory interface {
	CreateProcessor(choice int) (crypto.Processor, error)
	CreateAttackProcessor(choice int) (crypto.Processor, error)
}
