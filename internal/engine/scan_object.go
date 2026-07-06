package engine

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/frameworks"
)

// ScanObject scans a single in-memory Kubernetes object and returns its
// findings. It runs the manifest-mode checkers (plus any custom policies in the
// registry) through the identical post-processing pipeline as ScanManifest —
// severity overrides, exemptions, and framework attachment — so a single-object
// scan is indistinguishable from a manifest scan of that one object.
//
// This is the entry point used by the admission webhook (v1.2.0): each
// AdmissionReview request carries exactly one object to validate.
func (s *Scanner) ScanObject(ctx context.Context, obj unstructured.Unstructured) (*checker.ScanResult, error) {
	start := time.Now()

	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	if apiVersion == "" || kind == "" {
		return nil, fmt.Errorf("object missing apiVersion or kind")
	}
	gvr, err := checker.GVRForKind(apiVersion, kind)
	if err != nil {
		return nil, fmt.Errorf("resolving GVR for %s/%s: %w", apiVersion, kind, err)
	}

	enabled := s.enabledChecks(checker.ScanModeManifest)

	cache := checker.NewResourceCache()
	cache.Add(gvr, obj)
	cache.SetPolicies(&s.config.Policies)
	cache.Freeze()

	annotations := collectAnnotations(cache)
	findings, errCount := s.runChecks(ctx, enabled, cache)
	findings = s.applySeverityOverrides(findings)
	findings = config.FilterFindings(findings, s.config.Exemptions, annotations)
	frameworks.AttachFrameworks(findings)

	return &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			StartTime:         start,
			Duration:          time.Since(start),
			ChecksRun:         len(enabled),
			ChecksSkipped:     s.registry.Len() - len(enabled),
			ChecksErrored:     errCount,
			CheckNames:        checkNames(enabled),
			CheckDescriptions: checkDescriptions(enabled),
			CheckCategories:   checkCategories(enabled),
			ScanMode:          checker.ScanModeManifest,
		},
	}, nil
}
