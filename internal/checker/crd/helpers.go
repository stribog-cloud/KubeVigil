// Package crd implements CRD and custom resource security checkers.
// These checkers detect missing CRD validation schemas, insecure conversion
// webhooks, and cert-manager certificate issues.
package crd

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVR constants for CRD-related resource types.
var (
	// CustomResourceDefinitionGVR is the GroupVersionResource for apiextensions.k8s.io/v1 CRD objects.
	CustomResourceDefinitionGVR = schema.GroupVersionResource{
		Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions",
	}
	// CertificateGVR is the GroupVersionResource for cert-manager.io/v1 Certificate objects.
	CertificateGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificates",
	}
)
