package policy

import (
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// categoryByName maps a lower-cased category string to a built-in checker
// category, so a policy can opt into an existing group (e.g. "network") and
// have its findings aggregate alongside built-in checks of that category.
var categoryByName = func() map[string]checker.Category {
	m := make(map[string]checker.Category)
	for cat := checker.CategoryWorkload; cat <= checker.CategoryCustom; cat++ {
		m[strings.ToLower(cat.String())] = cat
	}
	return m
}()

// resolveCategory maps a policy's category string to a checker.Category.
// An empty or unrecognized value falls back to CategoryCustom.
func resolveCategory(name string) checker.Category {
	if name == "" {
		return checker.CategoryCustom
	}
	if cat, ok := categoryByName[strings.ToLower(name)]; ok {
		return cat
	}
	return checker.CategoryCustom
}
