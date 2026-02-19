// Package checker defines the core checker interface, types, and registry
// for KubeVigil security checks.
package checker

import "fmt"

// Category classifies security checks into functional groups.
type Category int

const (
	// CategoryWorkload covers pod and container security checks.
	CategoryWorkload Category = iota
	// CategoryLifecycle covers init, sidecar, and ephemeral container checks.
	CategoryLifecycle
	// CategoryImage covers image security checks.
	CategoryImage
	// CategoryRBAC covers identity and access control checks.
	CategoryRBAC
	// CategorySecrets covers secrets management checks.
	CategorySecrets
	// CategoryNetwork covers network security checks.
	CategoryNetwork
	// CategoryPSS covers Pod Security Standards checks.
	CategoryPSS
	// CategoryStorage covers storage and volume checks.
	CategoryStorage
	// CategoryScheduling covers scheduling and placement checks.
	CategoryScheduling
	// CategoryClusterConfig covers cluster-level configuration checks.
	CategoryClusterConfig
	// CategorySupplyChain covers supply chain security checks.
	CategorySupplyChain
	// CategoryCRD covers custom resource security checks.
	CategoryCRD
	// CategoryCloudProvider covers cloud provider integration checks.
	CategoryCloudProvider
)

var categoryNames = map[Category]string{
	CategoryWorkload:      "Workload",
	CategoryLifecycle:     "Lifecycle",
	CategoryImage:         "Image",
	CategoryRBAC:          "RBAC",
	CategorySecrets:       "Secrets",
	CategoryNetwork:       "Network",
	CategoryPSS:           "PodSecurityStandards",
	CategoryStorage:       "Storage",
	CategoryScheduling:    "Scheduling",
	CategoryClusterConfig: "ClusterConfig",
	CategorySupplyChain:   "SupplyChain",
	CategoryCRD:           "CRD",
	CategoryCloudProvider: "CloudProvider",
}

// String returns the short identifier of the category (e.g., "ClusterConfig").
func (c Category) String() string {
	if name, ok := categoryNames[c]; ok {
		return name
	}
	return fmt.Sprintf("Category(%d)", int(c))
}

var categoryDisplayNames = map[string]string{
	"Workload":             "Workload",
	"Lifecycle":            "Lifecycle",
	"Image":                "Image",
	"RBAC":                 "RBAC",
	"Secrets":              "Secrets",
	"Network":              "Network",
	"PodSecurityStandards": "Pod Security Standards",
	"Storage":              "Storage",
	"Scheduling":           "Scheduling",
	"ClusterConfig":        "Cluster Configuration",
	"SupplyChain":          "Supply Chain",
	"CRD":                  "CRD",
	"CloudProvider":        "Cloud Provider",
}

// CategoryDisplayName returns the human-readable display name for a category
// string. Unknown categories are returned unchanged.
func CategoryDisplayName(cat string) string {
	if dn, ok := categoryDisplayNames[cat]; ok {
		return dn
	}
	return cat
}
