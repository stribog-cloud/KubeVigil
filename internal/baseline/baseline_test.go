package baseline

import (
	"path/filepath"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func f(chk, kind, ns, res, container string) checker.Finding {
	return checker.Finding{Checker: chk, Kind: kind, Namespace: ns, Resource: res, Container: container}
}

func TestFingerprint_StableAndIdentitySensitive(t *testing.T) {
	a := f("privileged", "Pod", "default", "web", "app")
	// Same identity, different message/severity → same fingerprint.
	b := a
	b.Message = "totally different message"
	b.Severity = checker.SeverityCritical
	if Fingerprint(&a) != Fingerprint(&b) {
		t.Error("fingerprint should ignore message/severity")
	}
	// Different resource → different fingerprint.
	c := f("privileged", "Pod", "default", "api", "app")
	if Fingerprint(&a) == Fingerprint(&c) {
		t.Error("fingerprint should distinguish resources")
	}
	// Different container → different fingerprint.
	d := f("privileged", "Pod", "default", "web", "sidecar")
	if Fingerprint(&a) == Fingerprint(&d) {
		t.Error("fingerprint should distinguish containers")
	}
}

func TestFingerprint_NoDelimiterCollision(t *testing.T) {
	// Regression (red-team): a naive "\x00"-joined identity collides when a
	// field contains an embedded NUL. These two findings have the SAME
	// separator-joined bytes but are DIFFERENT resources — they must not share
	// a fingerprint, or a crafted resource could masquerade as an existing
	// baselined finding and slip past --fail-on-new.
	a := f("chk", "Pod", "a", "\x00c", "") // namespace="a", resource="\x00c"
	b := f("chk", "Pod", "a\x00", "c", "") // namespace="a\x00", resource="c"
	if Fingerprint(&a) == Fingerprint(&b) {
		t.Fatal("fingerprint collision: embedded-NUL fields must not shift the boundary")
	}
	c := f("chk", "Pod", "a", "\x00c", "")
	if Fingerprint(&a) != Fingerprint(&c) {
		t.Error("identical findings must share a fingerprint")
	}
}

func TestAnnotate_ClassifiesNewExistingResolved(t *testing.T) {
	base := FromFindings([]checker.Finding{
		f("privileged", "Pod", "default", "web", "app"),  // stays
		f("run-as-root", "Pod", "default", "web", "app"), // resolved
	})

	current := []checker.Finding{
		f("privileged", "Pod", "default", "web", "app"), // existing
		f("host-network", "Pod", "default", "web", ""),  // new
	}
	res := Annotate(base, current)

	if res.New != 1 || res.Existing != 1 || res.Resolved != 1 {
		t.Fatalf("diff = %+v, want New=1 Existing=1 Resolved=1", res)
	}
	if current[0].Status != StatusExisting {
		t.Errorf("findings[0].Status = %q, want existing", current[0].Status)
	}
	if current[1].Status != StatusNew {
		t.Errorf("findings[1].Status = %q, want new", current[1].Status)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	orig := FromFindings([]checker.Finding{
		f("privileged", "Pod", "default", "web", "app"),
		f("run-as-root", "Deployment", "prod", "api", "server"),
	})
	orig.ToolVersion = "v1.1.0"
	if err := orig.Save(path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Fingerprints) != 2 {
		t.Fatalf("loaded %d fingerprints, want 2", len(loaded.Fingerprints))
	}
	// A scan producing the same findings should classify both as existing.
	current := []checker.Finding{
		f("privileged", "Pod", "default", "web", "app"),
		f("run-as-root", "Deployment", "prod", "api", "server"),
	}
	res := Annotate(loaded, current)
	if res.New != 0 || res.Existing != 2 || res.Resolved != 0 {
		t.Errorf("round-trip diff = %+v, want all existing", res)
	}
}

func TestLoad_RejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	if err := (&Baseline{Version: "v99", Fingerprints: []string{}}).Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error loading unsupported version")
	}
}

func TestFromFindings_Deduplicates(t *testing.T) {
	dup := f("privileged", "Pod", "default", "web", "app")
	b := FromFindings([]checker.Finding{dup, dup, dup})
	if len(b.Fingerprints) != 1 {
		t.Errorf("got %d fingerprints, want 1 (deduped)", len(b.Fingerprints))
	}
}
