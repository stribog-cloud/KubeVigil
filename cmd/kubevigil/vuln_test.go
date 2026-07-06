package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const spdxFixture = `{"spdxVersion":"SPDX-2.3","packages":[
  {"name":"django","versionInfo":"3.2.0","externalRefs":[
    {"referenceType":"purl","referenceLocator":"pkg:pypi/django@3.2.0"}]}]}`

func TestLoadSBOMPackages_File(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "app.spdx.json", spdxFixture)
	pkgs, err := loadSBOMPackages(p)
	if err != nil {
		t.Fatalf("loadSBOMPackages: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Purl != "pkg:pypi/django@3.2.0" {
		t.Fatalf("pkgs=%+v", pkgs)
	}
}

func TestLoadSBOMPackages_Directory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.spdx.json", spdxFixture)
	writeFile(t, dir, "b.cdx.json", `{"bomFormat":"CycloneDX","components":[{"name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`)
	writeFile(t, dir, "notes.txt", "ignored")           // non-json skipped
	writeFile(t, dir, "broken.json", "{not valid json") // unparseable json skipped with warning
	pkgs, err := loadSBOMPackages(dir)
	if err != nil {
		t.Fatalf("loadSBOMPackages: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (merged from two SBOMs)", len(pkgs))
	}
}

func TestLoadSBOMPackages_Errors(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		if _, err := loadSBOMPackages(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Error("expected error for missing path")
		}
	})
	t.Run("single file bad SBOM is hard error", func(t *testing.T) {
		dir := t.TempDir()
		p := writeFile(t, dir, "bad.json", `{"foo":"bar"}`)
		if _, err := loadSBOMPackages(p); err == nil {
			t.Error("expected parse error for unrecognized single-file SBOM")
		}
	})
	t.Run("directory with no parseable SBOMs", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "x.json", `{"foo":"bar"}`)
		if _, err := loadSBOMPackages(dir); err == nil {
			t.Error("expected error when no SBOM parses in directory")
		}
	})
}

func TestMaxVulnScanTime(t *testing.T) {
	// Small SBOM: budget scales with package count (1 batch + 5 fetches).
	if got := maxVulnScanTime(time.Second, 5); got != 6*time.Second {
		t.Errorf("small budget=%v, want 6s", got)
	}
	// Huge SBOM: capped at 15 minutes.
	if got := maxVulnScanTime(time.Minute, 100000); got != 15*time.Minute {
		t.Errorf("huge budget=%v, want 15m cap", got)
	}
	// Zero packages still gets one batch's worth.
	if got := maxVulnScanTime(2*time.Second, 0); got != 2*time.Second {
		t.Errorf("zero-pkg budget=%v, want 2s", got)
	}
}
