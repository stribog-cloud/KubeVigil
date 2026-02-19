package checker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// stubChecker is a minimal Checker implementation for testing the registry.
type stubChecker struct {
	name string
}

func (s *stubChecker) Name() string        { return s.name }
func (s *stubChecker) Description() string { return "stub: " + s.name }
func (s *stubChecker) Categories() []Category {
	return []Category{CategoryWorkload}
}
func (s *stubChecker) SupportedModes() []ScanMode {
	return []ScanMode{ScanModeLive, ScanModeManifest}
}
func (s *stubChecker) RequiredResources() []schema.GroupVersionResource {
	return nil
}
func (s *stubChecker) Run(_ context.Context, _ *ResourceCache) ([]Finding, error) {
	return nil, nil
}

func newStub(name string) *stubChecker {
	return &stubChecker{name: name}
}

func TestRegistry_Register(t *testing.T) {
	tests := []struct {
		name      string
		checkers  []string
		wantErr   string
		setupFunc func(r *Registry)
	}{
		{
			name:     "single checker registers successfully",
			checkers: []string{"privileged"},
		},
		{
			name:     "multiple checkers register successfully",
			checkers: []string{"privileged", "host-pid", "host-ipc"},
		},
		{
			name:    "duplicate name returns error",
			wantErr: `checker "privileged" already registered`,
			setupFunc: func(r *Registry) {
				err := r.Register(newStub("privileged"))
				require.NoError(t, err)
			},
			checkers: []string{"privileged"},
		},
		{
			name:     "empty name returns error",
			wantErr:  "checker name must not be empty",
			checkers: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			if tt.setupFunc != nil {
				tt.setupFunc(r)
			}

			var lastErr error
			for _, name := range tt.checkers {
				if err := r.Register(newStub(name)); err != nil {
					lastErr = err
				}
			}

			if tt.wantErr != "" {
				require.Error(t, lastErr)
				assert.Contains(t, lastErr.Error(), tt.wantErr)
			} else {
				assert.NoError(t, lastErr)
			}
		})
	}
}

func TestRegistry_MustRegister(t *testing.T) {
	t.Run("panics on duplicate", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(newStub("privileged"))
		assert.Panics(t, func() {
			r.MustRegister(newStub("privileged"))
		})
	})

	t.Run("panics on empty name", func(t *testing.T) {
		r := NewRegistry()
		assert.Panics(t, func() {
			r.MustRegister(newStub(""))
		})
	})

	t.Run("succeeds on valid checker", func(t *testing.T) {
		r := NewRegistry()
		assert.NotPanics(t, func() {
			r.MustRegister(newStub("host-pid"))
		})
		assert.Equal(t, 1, r.Len())
	})
}

func TestRegistry_Get(t *testing.T) {
	t.Run("found returns checker and true", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(newStub("privileged"))

		c, ok := r.Get("privileged")
		assert.True(t, ok)
		require.NotNil(t, c)
		assert.Equal(t, "privileged", c.Name())
	})

	t.Run("not found returns nil and false", func(t *testing.T) {
		r := NewRegistry()

		c, ok := r.Get("nonexistent")
		assert.False(t, ok)
		assert.Nil(t, c)
	})
}

func TestRegistry_All(t *testing.T) {
	t.Run("empty registry returns empty slice", func(t *testing.T) {
		r := NewRegistry()
		all := r.All()
		assert.Empty(t, all)
	})

	t.Run("preserves registration order", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(newStub("charlie"))
		r.MustRegister(newStub("alpha"))
		r.MustRegister(newStub("bravo"))

		all := r.All()
		require.Len(t, all, 3)
		assert.Equal(t, "charlie", all[0].Name())
		assert.Equal(t, "alpha", all[1].Name())
		assert.Equal(t, "bravo", all[2].Name())
	})
}

func TestRegistry_Names(t *testing.T) {
	t.Run("empty registry returns empty slice", func(t *testing.T) {
		r := NewRegistry()
		assert.Empty(t, r.Names())
	})

	t.Run("returns names in registration order", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(newStub("charlie"))
		r.MustRegister(newStub("alpha"))
		r.MustRegister(newStub("bravo"))

		names := r.Names()
		assert.Equal(t, []string{"charlie", "alpha", "bravo"}, names)
	})
}

func TestRegistry_Len(t *testing.T) {
	t.Run("zero for empty registry", func(t *testing.T) {
		r := NewRegistry()
		assert.Equal(t, 0, r.Len())
	})

	t.Run("correct count after registrations", func(t *testing.T) {
		r := NewRegistry()
		r.MustRegister(newStub("a"))
		r.MustRegister(newStub("b"))
		r.MustRegister(newStub("c"))
		assert.Equal(t, 3, r.Len())
	})
}
