package matrix

// Executor defines the interface for a tool runner that executes a chosen technique and retrieves results
type Executor interface {
	Execute(decision Decision) (string, error)
}

