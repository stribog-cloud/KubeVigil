package vuln

import "testing"

func TestParseSBOM_SPDX(t *testing.T) {
	doc := `{
	  "spdxVersion": "SPDX-2.3",
	  "packages": [
	    {"name": "django", "versionInfo": "3.2.0", "externalRefs": [
	      {"referenceType": "purl", "referenceLocator": "pkg:pypi/django@3.2.0"}
	    ]},
	    {"name": "openssl", "versionInfo": "1.1.1k-r0", "externalRefs": [
	      {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:openssl"},
	      {"referenceType": "purl", "referenceLocator": "pkg:apk/alpine/openssl@1.1.1k-r0"}
	    ]},
	    {"name": "no-purl-pkg", "versionInfo": "1.0", "externalRefs": []}
	  ]
	}`
	pkgs, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (purl-less package must be skipped)", len(pkgs))
	}
	// Sorted by purl: apk/... before pypi/...
	if pkgs[0].Purl != "pkg:apk/alpine/openssl@1.1.1k-r0" || pkgs[0].Name != "openssl" {
		t.Errorf("pkgs[0]=%+v", pkgs[0])
	}
	if pkgs[1].Purl != "pkg:pypi/django@3.2.0" || pkgs[1].Version != "3.2.0" {
		t.Errorf("pkgs[1]=%+v", pkgs[1])
	}
}

func TestParseSBOM_CycloneDX(t *testing.T) {
	doc := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "components": [
	    {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
	    {"name": "no-purl", "version": "1.0"},
	    {"name": "lodash-dup", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}
	  ]
	}`
	pkgs, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1 (dedup by purl, skip purl-less)", len(pkgs))
	}
	if pkgs[0].Purl != "pkg:npm/lodash@4.17.15" {
		t.Errorf("pkg=%+v", pkgs[0])
	}
}

func TestParseSBOM_Errors(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty", ""},
		{"whitespace only", "   \n  "},
		{"not json", "this is not json"},
		{"unrecognized format", `{"foo": "bar"}`},
		{"cyclonedx bad components", `{"bomFormat":"CycloneDX","components":"not-an-array"}`},
		{"spdx bad packages", `{"spdxVersion":"SPDX-2.3","packages":42}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSBOM([]byte(tc.doc)); err == nil {
				t.Errorf("ParseSBOM(%q) expected error, got nil", tc.doc)
			}
		})
	}
}

func TestParseSBOM_EmptyInventory(t *testing.T) {
	// A well-formed SPDX doc with no purl-bearing packages yields zero packages
	// and no error — an image with an empty/unmatched inventory is valid.
	pkgs, err := ParseSBOM([]byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`))
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("got %d packages, want 0", len(pkgs))
	}
}
