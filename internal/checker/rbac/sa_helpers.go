package rbac

import "k8s.io/apimachinery/pkg/runtime/schema"

// serviceAccountGVR is the GroupVersionResource for ServiceAccount.
var serviceAccountGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}
