package secrets

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "empty string",
			input:   "",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "single character",
			input:   "aaaa",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "two characters equal",
			input:   "abab",
			wantMin: 0.99,
			wantMax: 1.01,
		},
		{
			name:    "low entropy config value",
			input:   "localhost",
			wantMin: 2.0,
			wantMax: 3.5,
		},
		{
			name:    "high entropy secret-like string",
			input:   "aB3$kL9mNp2QrS5tUv8WxYz1",
			wantMin: 4.0,
			wantMax: 5.0,
		},
		{
			name:    "hex string high entropy",
			input:   "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
			wantMin: 3.5,
			wantMax: 4.5,
		},
		{
			name:    "base64-like high entropy",
			input:   "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleQ==",
			wantMin: 3.5,
			wantMax: 5.0,
		},
		{
			name:    "simple word",
			input:   "true",
			wantMin: 1.5,
			wantMax: 2.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.input)
			if tt.wantMin == 0 && tt.wantMax == 0 {
				assert.Equal(t, 0.0, got)
				return
			}
			assert.GreaterOrEqual(t, got, tt.wantMin, "entropy too low for %q", tt.input)
			assert.LessOrEqual(t, got, tt.wantMax, "entropy too high for %q", tt.input)
		})
	}
}

func TestShannonEntropyMaximum(t *testing.T) {
	// Maximum entropy for base-256 is log2(256) = 8 bits/char.
	// For printable ASCII (~95 chars), max is ~6.57 bits/char.
	allPrintable := ""
	for c := byte(32); c < 127; c++ {
		allPrintable += string(c)
	}
	entropy := ShannonEntropy(allPrintable)
	maxPossible := math.Log2(float64(95))
	assert.InDelta(t, maxPossible, entropy, 0.01)
}
