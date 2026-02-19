package report

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestAllReportersContract(t *testing.T) {
	names := Names()
	require.Contains(t, names, "text")
	require.Contains(t, names, "json")

	for _, name := range names {
		r, err := Get(name)
		require.NoError(t, err)

		t.Run(name+"/name_is_non_empty", func(t *testing.T) {
			assert.NotEmpty(t, r.Name())
		})

		t.Run(name+"/empty_result", func(t *testing.T) {
			var buf bytes.Buffer
			result := &checker.ScanResult{}
			err := r.Generate(context.Background(), result, &buf)
			require.NoError(t, err)
			assert.NotEmpty(t, buf.String())
		})

		t.Run(name+"/populated_result", func(t *testing.T) {
			var buf bytes.Buffer
			result := populatedResult()
			err := r.Generate(context.Background(), result, &buf)
			require.NoError(t, err)
			assert.NotEmpty(t, buf.String())
		})
	}
}

func TestGet_UnknownReporter(t *testing.T) {
	_, err := Get("unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown reporter")
}

func populatedResult() *checker.ScanResult {
	return &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				Container:   "nginx",
				Message:     "Container runs in privileged mode",
				Remediation: "Set securityContext.privileged to false",
				FieldPath:   ".spec.containers[0].securityContext.privileged",
			},
			{
				Checker:     "run-as-root",
				Severity:    checker.SeverityHigh,
				Resource:    "api-server",
				Namespace:   "backend",
				Kind:        "Deployment",
				Container:   "api",
				Message:     "Container runs as root",
				Remediation: "Set runAsNonRoot: true",
			},
		},
		ClusterInfo: checker.ClusterInfo{
			ServerVersion: "v1.28.0",
			NodeCount:     3,
			ContextName:   "my-cluster",
		},
		ScanMeta: checker.ScanMeta{
			StartTime:     time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			Duration:      42 * time.Millisecond,
			ChecksRun:     25,
			ChecksSkipped: 0,
			ChecksErrored: 0,
			ScanMode:      checker.ScanModeManifest,
		},
	}
}
