package crd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseCertDurationHours tests the parseCertDurationHours helper function
// covering branches: valid hours format, invalid format, edge values.
func TestParseCertDurationHours(t *testing.T) {
	testCases := []struct {
		name string
		s    string
		want float64
	}{
		{
			name: "90 days in hours",
			s:    "2160h",
			want: 2160,
		},
		{
			name: "1 year in hours",
			s:    "8760h",
			want: 8760,
		},
		{
			name: "2 years in hours",
			s:    "17520h",
			want: 17520,
		},
		{
			name: "fractional hours",
			s:    "1.5h",
			want: 1.5,
		},
		{
			name: "zero hours",
			s:    "0h",
			want: 0,
		},
		{
			name: "invalid format without h suffix returns 0",
			s:    "90d",
			want: 0,
		},
		{
			name: "empty string returns 0",
			s:    "",
			want: 0,
		},
		{
			name: "just text returns 0",
			s:    "invalid",
			want: 0,
		},
		{
			name: "minutes format returns 0 (not supported)",
			s:    "30m",
			want: 0,
		},
		{
			name: "negative hours",
			s:    "-100h",
			want: -100,
		},
		{
			name: "very large duration",
			s:    "87600h",
			want: 87600,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCertDurationHours(tc.s)
			assert.InDelta(t, tc.want, got, 0.001)
		})
	}
}
