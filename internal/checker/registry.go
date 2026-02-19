package checker

import (
	"fmt"
	"sync"
)

// Registry holds all registered security checkers.
// It is safe for concurrent reads after initial registration.
type Registry struct {
	mu       sync.RWMutex
	checkers map[string]Checker
	order    []string
}

// NewRegistry creates an empty checker registry.
func NewRegistry() *Registry {
	return &Registry{
		checkers: make(map[string]Checker),
	}
}

// Register adds a checker to the registry.
// Returns an error if the checker's name is empty or already registered.
func (r *Registry) Register(c Checker) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := c.Name()
	if name == "" {
		return fmt.Errorf("checker name must not be empty")
	}
	if _, exists := r.checkers[name]; exists {
		return fmt.Errorf("checker %q already registered", name)
	}

	r.checkers[name] = c
	r.order = append(r.order, name)
	return nil
}

// MustRegister adds a checker to the registry, panicking on error.
// Use this in init() functions where registration failure is a programming error.
func (r *Registry) MustRegister(c Checker) {
	if err := r.Register(c); err != nil {
		panic(fmt.Sprintf("kubevigil: %v", err))
	}
}

// Get retrieves a checker by name.
// Returns the checker and true if found, nil and false otherwise.
func (r *Registry) Get(name string) (Checker, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.checkers[name]
	return c, ok
}

// All returns all registered checkers in registration order.
func (r *Registry) All() []Checker {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Checker, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.checkers[name])
	}
	return result
}

// Names returns the names of all registered checkers in registration order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]string, len(r.order))
	copy(result, r.order)
	return result
}

// Len returns the number of registered checkers.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.checkers)
}

// defaultRegistry is the global checker registry used by package-level functions.
var defaultRegistry = NewRegistry()

// DefaultRegistry returns the global default registry.
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Register adds a checker to the default registry.
func Register(c Checker) error {
	return defaultRegistry.Register(c)
}

// MustRegister adds a checker to the default registry, panicking on error.
func MustRegister(c Checker) {
	defaultRegistry.MustRegister(c)
}

// Get retrieves a checker by name from the default registry.
func Get(name string) (Checker, bool) {
	return defaultRegistry.Get(name)
}

// All returns all registered checkers from the default registry.
func All() []Checker {
	return defaultRegistry.All()
}
