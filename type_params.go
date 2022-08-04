package argonize

// ----------------------------------------------------------------------------
//  Type: Params
// ----------------------------------------------------------------------------

// Params holds the parameters for the Argon2id algorithm.
type Params struct {
	// Iterations is the number of iterations or passes over the memory.
	// Defaults to 1 which is the sensible number from the Argon2's draft RFC
	// recommends[2].
	Iterations uint32
	// KeyLength is the length of the key used in Argon2.
	// Defaults to 32.
	KeyLength uint32
	// MemoryCost is the amount of memory used by the algorithm in KiB.
	// Defaults to 64 * 1024 KiB = 64 MiB. Which is the sensible number from
	// the Argon2's draft RFC recommends[2].
	MemoryCost uint32
	// SaltLength is the length of the salt used in Argon2.
	// Defaults to 16.
	SaltLength uint32
	// Parallelism is the number of threads or lanes used by the algorithm.
	// Defaults to 2.
	Parallelism uint8
}

const (
	// IterationsDefault is the default number of ArgonIterations.
	IterationsDefault = uint32(1)
	// KeyLengthDefault is the default length of ArgonKeyLength.
	KeyLengthDefault = uint32(32)
	// MemoryCostDefault is the default amount of ArgonMemoryCost.
	MemoryCostDefault = uint32(64 * 1024)
	// ParallelismDefault is the default number of ArgonParallelism.
	ParallelismDefault = uint8(2)
	// SaltLengthDefault is the default length of ArgonSaltLength.
	SaltLengthDefault = uint32(16)
)

// ----------------------------------------------------------------------------
//  Constructor
// ----------------------------------------------------------------------------

// NewParams returns a new Params object with default values.
func NewParams() *Params {
	p := new(Params)

	p.SetDefault()

	return p
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// SetDefault sets the fields to default values.
func (p *Params) SetDefault() {
	p.Iterations = IterationsDefault
	p.KeyLength = KeyLengthDefault
	p.MemoryCost = MemoryCostDefault
	p.SaltLength = SaltLengthDefault
	p.Parallelism = ParallelismDefault
}
